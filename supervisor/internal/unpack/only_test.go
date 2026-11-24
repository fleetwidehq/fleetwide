package unpack

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type tent struct {
	name, body, link string
	typ              byte
	mode             int64
}

func layer(t *testing.T, ents ...tent) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typ, Linkname: e.link}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return &buf
}

// Only keeps a layer's entries under the sync paths — whiteouts included —
// and drops the rest, so applying the layers that touch /app into a staging
// root gives exactly the image's /app and nothing else.
func TestOnlyFiltersToTheSyncPaths(t *testing.T) {
	root := t.TempDir()
	a, err := New(root, Options{Only: []string{"/app", "/etc/nginx/conf.d"}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.Apply(layer(t,
		tent{name: "usr/lib/libssl.so", body: "base"},
		tent{name: "app/", typ: tar.TypeDir, mode: 0o755},
		tent{name: "app/main.js", body: "v1"},
		tent{name: "app/old.js", body: "old"},
		tent{name: "etc/nginx/conf.d/default.conf", body: "conf"},
		tent{name: "etc/nginx/nginx.conf", body: "outside"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.Skipped != 2 {
		t.Fatalf("files=%d skipped=%d", st.Files, st.Skipped)
	}
	for _, p := range []string{"usr/lib/libssl.so", "etc/nginx/nginx.conf"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			t.Fatalf("%s is outside the sync paths and must not be written", p)
		}
	}
	// a later layer removes a file under a sync path and adds one outside
	st, err = a.Apply(layer(t, tent{name: "app/.wh.old.js"}, tent{name: "usr/lib/libnew.so", body: "n"}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Whiteouts != 1 || st.Removed != 1 || st.Skipped != 1 {
		t.Fatalf("second layer: %+v", st)
	}
	if _, err := os.Lstat(filepath.Join(root, "app/old.js")); err == nil {
		t.Fatal("whiteout under a sync path must apply")
	}
}

// Preflight says no before anything is written when a destination's
// directory is not ours to write, and yes when the layer set itself creates
// the directory first.
func TestPreflightChecksWritability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere; run unprivileged")
	}
	root := t.TempDir()
	// Build the tree writable, then lock the base parts down the way a
	// root-owned image directory is for the app's user.
	os.MkdirAll(filepath.Join(root, "app"), 0o755)
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	if err := os.WriteFile(filepath.Join(root, "usr/lib/libssl.so"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(root, "opt/vendor/data"), 0o755)
	for _, p := range []string{"usr/lib", "opt/vendor/data", "opt/vendor"} {
		os.Chmod(filepath.Join(root, p), 0o555)
	}
	t.Cleanup(func() {
		for _, p := range []string{"usr/lib", "opt/vendor", "opt/vendor/data"} {
			os.Chmod(filepath.Join(root, p), 0o755)
		}
	})
	a, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// writable sync dir: fine; a new subdir created by the same layer: fine
	if err := a.Preflight(layer(t, tent{name: "app/main.js", body: "v"}, tent{name: "app/lib/", typ: tar.TypeDir, mode: 0o755}, tent{name: "app/lib/x.js", body: "y"}), map[string]bool{}); err != nil {
		t.Fatalf("writable destinations refused: %v", err)
	}
	// replacing a file in a read-only directory
	var pe *PreflightError
	err = a.Preflight(layer(t, tent{name: "usr/lib/libssl.so", body: "new"}), map[string]bool{})
	if !errors.As(err, &pe) || pe.Path != filepath.Join(root, "usr/lib/libssl.so") {
		t.Fatalf("read-only parent must be refused with the path: %v", err)
	}
	// a new file whose nearest existing ancestor is read-only
	if err := a.Preflight(layer(t, tent{name: "usr/lib/new/thing", body: "n"}), map[string]bool{}); !errors.As(err, &pe) {
		t.Fatalf("read-only ancestor must be refused: %v", err)
	}
	// whiting out a directory whose subtree is not writable
	if err := a.Preflight(layer(t, tent{name: "opt/.wh.vendor"}), map[string]bool{}); !errors.As(err, &pe) {
		t.Fatalf("unwritable subtree must be refused: %v", err)
	}
	// nothing was written by any of it
	if _, err := os.Lstat(filepath.Join(root, "app/main.js")); err == nil {
		t.Fatal("preflight must not write")
	}
}
