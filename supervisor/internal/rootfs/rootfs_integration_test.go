package rootfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

// Run with: FLEETWIDE_INTEGRATION=1 go test ./internal/rootfs -run Integration -v
// Pulls public images; works on macOS (non-root: devices/ownership skipped).
func TestIntegrationMaterialize(t *testing.T) {
	if os.Getenv("FLEETWIDE_INTEGRATION") == "" {
		t.Skip("set FLEETWIDE_INTEGRATION=1 to pull public images")
	}
	cases := []struct {
		ref       string
		wantFile  string // must exist after unpack
		minFiles  int
		wantArgv0 string // resolved entrypoint/cmd[0]
	}{
		{ref: "docker.io/library/alpine:3.20", wantFile: "etc/alpine-release", minFiles: 50, wantArgv0: "/bin/sh"},
		{ref: "docker.io/library/busybox:1.36", wantFile: "bin/busybox", minFiles: 1, wantArgv0: "sh"},
		{ref: "docker.io/library/debian:bookworm-slim", wantFile: "etc/debian_version", minFiles: 1000, wantArgv0: "bash"},
		{ref: "docker.io/library/nginx:1.27", wantFile: "usr/sbin/nginx", minFiles: 1000, wantArgv0: "/docker-entrypoint.sh"},
		{ref: "docker.io/library/python:3.12-slim", wantFile: "usr/local/bin/python3", minFiles: 1000, wantArgv0: "python3"},
		{ref: "gcr.io/distroless/static-debian12:latest", wantFile: "etc/passwd", minFiles: 5, wantArgv0: ""},
		{ref: "docker.io/library/hello-world:latest", wantFile: "hello", minFiles: 1, wantArgv0: "/hello"},
	}
	cache, err := layercache.Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			dest := t.TempDir()
			res, err := Materialize(ctx, tc.ref, Options{Cache: cache, Platform: registry.HostPlatform(), Root: dest, Chown: true, Log: t.Logf})
			if err != nil {
				t.Fatalf("materialize: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dest, tc.wantFile)); err != nil {
				t.Errorf("expected %s in tree: %v", tc.wantFile, err)
			}
			if res.Stats.Files < tc.minFiles {
				t.Errorf("only %d files unpacked, want >= %d", res.Stats.Files, tc.minFiles)
			}
			argv := res.Runtime.Argv(nil)
			if tc.wantArgv0 != "" && (len(argv) == 0 || argv[0] != tc.wantArgv0) {
				t.Errorf("argv[0] = %v, want %s", argv, tc.wantArgv0)
			}
			// Every layer must have been verified (cache only stores verified blobs).
			for _, l := range res.Image.Layers {
				if !cache.Has(l.Digest) {
					t.Errorf("layer %s not in cache after pull", l.Digest)
				}
				if !strings.HasPrefix(l.Digest, "sha256:") {
					t.Errorf("unexpected digest %s", l.Digest)
				}
			}
			t.Logf("%s: %d layers %v, %d files, %d dirs, %d symlinks, %d hardlinks, %d whiteouts, pull %dms unpack %dms, %d warnings",
				tc.ref, len(res.Image.Layers), res.Compression, res.Stats.Files, res.Stats.Dirs, res.Stats.Symlinks, res.Stats.Hardlinks,
				res.Stats.Whiteouts+res.Stats.Opaques, res.PullMS, res.UnpackMS, len(res.Warnings))
		})
	}
}

func TestIntegrationDigestMismatchIsRejected(t *testing.T) {
	if os.Getenv("FLEETWIDE_INTEGRATION") == "" {
		t.Skip("set FLEETWIDE_INTEGRATION=1")
	}
	cache, _ := layercache.Open(t.TempDir())
	// Feed the cache content that does not match the claimed digest.
	_, err := cache.Put("sha256:0000000000000000000000000000000000000000000000000000000000000000", strings.NewReader("not the blob"))
	if err == nil {
		t.Fatal("expected digest mismatch error")
	}
	if cache.Has("sha256:0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatal("mismatched blob must not be committed")
	}
}
