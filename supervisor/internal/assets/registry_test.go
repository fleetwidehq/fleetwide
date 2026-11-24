package assets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
)

// TestOCIFromLocalRegistry runs against a plain-HTTP registry holding the
// e2e's test/prompts:1 image (FW_TEST_REGISTRY=localhost:5001), e.g. after
// scripts/e2e-fleet.sh left fw-registry up.
func TestOCIFromLocalRegistry(t *testing.T) {
	reg := os.Getenv("FW_TEST_REGISTRY")
	if reg == "" {
		t.Skip("FW_TEST_REGISTRY not set")
	}
	dir := t.TempDir()
	cache, _ := layercache.Open(filepath.Join(dir, "cache"))
	a := v1.Asset{Name: "prompts", Source: "oci", Ref: reg + "/test/prompts:1", Insecure: true, UnpackTo: filepath.Join(dir, "assets")}
	// resolve the digest: any manifest, index allowed
	dg, _, err := resolveForTest(reg + "/test/prompts:1")
	if err != nil {
		t.Fatal(err)
	}
	a.Digest = dg
	res, err := Sync(context.Background(), []v1.Asset{a}, Options{Cache: cache, Log: t.Logf})
	if err != nil || !res[0].Changed {
		t.Fatalf("sync: %v %+v", err, res)
	}
	b, err := os.ReadFile(filepath.Join(a.UnpackTo, "prompts", "current", "hello.txt"))
	if err != nil || len(b) == 0 {
		t.Fatalf("hello.txt: %v %q", err, b)
	}
	t.Logf("hello.txt = %q", b)
}

// resolveForTest resolves a reference to its digest (index allowed).
func resolveForTest(ref string) (string, int64, error) {
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		return "", 0, err
	}
	desc, err := remote.Get(r, remote.WithContext(context.Background()))
	if err != nil {
		return "", 0, err
	}
	return desc.Digest.String(), desc.Size, nil
}
