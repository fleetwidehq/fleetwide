package assets

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
)

func tgz(t *testing.T, files map[string]string, top string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, c := range files {
		name := n
		if top != "" {
			name = top + "/" + n
		}
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sum(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func TestObjectSyncSwapAndPrune(t *testing.T) {
	dir := t.TempDir()
	cache, _ := layercache.Open(filepath.Join(dir, "cache"))
	v1b := tgz(t, map[string]string{"prompt.txt": "hello v1", "sub/x.json": "{}"}, "")
	v2b := []byte("GGUF-binary-v2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1.tgz":
			w.Write(v1b)
		case "/model.gguf":
			w.Write(v2b)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	unpack := filepath.Join(dir, "assets")
	a := v1.Asset{Name: "bundle", Source: "object", Ref: srv.URL + "/v1.tgz", Digest: sum(v1b), Insecure: true, UnpackTo: unpack, Auth: &v1.RegistryAuth{Username: "token", Secret: "tok"}}
	res, err := Sync(context.Background(), []v1.Asset{a}, Options{Cache: cache, Log: t.Logf})
	if err != nil || !res[0].Changed {
		t.Fatalf("sync: %v %+v", err, res)
	}
	if b, _ := os.ReadFile(filepath.Join(unpack, "bundle", "current", "prompt.txt")); string(b) != "hello v1" {
		t.Fatalf("content: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(unpack, "bundle", "current", "sub", "x.json")); string(b) != "{}" {
		t.Fatal("nested file")
	}
	// second run: nothing to do, no network (server would 401 without auth anyway)
	a.Auth = nil
	res, err = Sync(context.Background(), []v1.Asset{a}, Options{Cache: cache})
	if err != nil || res[0].Changed {
		t.Fatalf("idempotent: %v %+v", err, res)
	}
	// wrong digest is refused and nothing changes
	bad := a
	bad.Ref, bad.Digest, bad.Auth = srv.URL+"/model.gguf", sum([]byte("other")), &v1.RegistryAuth{Secret: "tok"}
	if _, err := Sync(context.Background(), []v1.Asset{bad}, Options{Cache: cache}); err == nil {
		t.Fatal("digest mismatch must fail")
	}
	if Current(a) != Key(a) {
		t.Fatal("failed sync must leave current untouched")
	}
	// new version: single file, swapped atomically, old version kept
	a2 := a
	a2.Ref, a2.Digest, a2.Auth = srv.URL+"/model.gguf", sum(v2b), &v1.RegistryAuth{Secret: "tok"}
	res, err = Sync(context.Background(), []v1.Asset{a2}, Options{Cache: cache})
	if err != nil || !res[0].Changed {
		t.Fatalf("v2: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(unpack, "bundle", "current", "model.gguf")); string(b) != "GGUF-binary-v2" {
		t.Fatalf("v2 content: %q", b)
	}
	ents, _ := os.ReadDir(filepath.Join(unpack, "bundle", ".versions"))
	if len(ents) != 2 {
		t.Fatalf("previous version must be kept: %d", len(ents))
	}
	// rollback = pin the old digest again: instant, no download
	res, err = Sync(context.Background(), []v1.Asset{a}, Options{Cache: cache})
	if err != nil || !res[0].Changed || Current(a) != Key(a) {
		t.Fatalf("rollback: %v %+v", err, res)
	}
}

func TestGitArchiveStripsTopDir(t *testing.T) {
	dir := t.TempDir()
	body := tgz(t, map[string]string{"README.md": "# rules", "rules/a.yaml": "a: 1"}, "repo-abc123")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	err := fetchGit(context.Background(), v1.Asset{Name: "rules", Source: "git", Ref: srv.URL + "/acme/rules", Digest: "0123456789abcdef0123456789abcdef01234567"}, dir, Options{HTTP: srv.Client(), Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "rules", "a.yaml")); string(b) != "a: 1" {
		t.Fatalf("stripped layout wrong: %q", b)
	}
}

func TestTarEscapeIsContained(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "../../escape.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	if err := extractTar(&buf, dir, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "escape.txt")); err == nil {
		t.Fatal("path escaped the asset directory")
	}
	if _, err := os.Lstat(filepath.Join(dir, "link")); err == nil {
		t.Fatal("absolute symlink must be skipped")
	}
}
