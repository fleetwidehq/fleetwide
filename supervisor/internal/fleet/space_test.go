package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

func blob(t *testing.T, c *layercache.Cache, body string, old bool) string {
	t.Helper()
	h := sha256.Sum256([]byte(body))
	d := "sha256:" + hex.EncodeToString(h[:])
	if _, err := c.Put(d, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if old {
		p := filepath.Join(c.Dir(), "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
		then := time.Now().Add(-2 * time.Hour)
		os.Chtimes(p, then, then)
	}
	return d
}

// A cache too full for the incoming layers is trimmed before the pull is
// refused — keeping the running release's blobs and the incoming image's
// own shared layers, dropping the rest — and refused only when trimming was
// not enough.
func TestSpaceCheckTrimsBeforeRefusing(t *testing.T) {
	cache, err := layercache.Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cur := blob(t, cache, "current layer", true)
	shared := blob(t, cache, "shared base layer", true)
	stale := blob(t, cache, "stale release layer", true)
	c := &Controller{cfg: Config{Cache: cache}, log: t.Logf}
	c.current = &release{ReleaseID: "rel_cur", Image: "x", Layers: []string{cur}}

	img := &registry.Image{Digest: "sha256:new", Layers: []registry.LayerInfo{
		{Digest: shared, Size: int64(len("shared base layer"))},
		{Digest: "sha256:" + strings.Repeat("a", 64), Size: 100},
	}}
	// 120 bytes free: the 100-byte pull fits only once the stale blob is gone.
	freeSpace = func(path string) (uint64, uint64, bool) {
		if path == "/" {
			return 1 << 40, 1 << 40, true
		}
		if cache.Has(stale) {
			return 50, 1000, true
		}
		return 120, 1000, true
	}
	defer func() { freeSpace = nil; freeSpace = freeSpaceDefault }()
	if err := c.spaceCheck(img); err != nil {
		t.Fatalf("trimming should have made room: %v", err)
	}
	if cache.Has(stale) {
		t.Fatal("the stale release's blob should have been trimmed")
	}
	if !cache.Has(cur) || !cache.Has(shared) {
		t.Fatal("the running release's layer and the incoming image's shared layer must survive trimming")
	}
	// nothing left to trim and still short: refused, with the figures
	freeSpace = func(path string) (uint64, uint64, bool) {
		if path == "/" {
			return 1 << 40, 1 << 40, true
		}
		return 10, 1000, true
	}
	err = c.spaceCheck(img)
	if err == nil || !strings.Contains(err.Error(), "layer cache") || !strings.Contains(err.Error(), "100 B needed") {
		t.Fatalf("want a refusal naming the shortfall, got %v", err)
	}
}

// "/" decides staging: too small for an extracted copy means extract in
// the gap; too small for even the compressed image means refuse.
func TestSpaceCheckDecidesStaging(t *testing.T) {
	cache, err := layercache.Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{cfg: Config{Cache: cache}, log: t.Logf}
	img := &registry.Image{Digest: "sha256:new", Layers: []registry.LayerInfo{{Digest: "sha256:" + strings.Repeat("b", 64), Size: 1000}}}
	rootFree := uint64(0)
	freeSpace = func(path string) (uint64, uint64, bool) {
		if path == "/" {
			return rootFree, 1 << 20, true
		}
		return 1 << 30, 1 << 30, true // the cache dir on a big volume
	}
	defer func() { freeSpace = freeSpaceDefault }()

	rootFree = 10000
	if err := c.spaceCheck(img); err != nil || c.noStage != "" {
		t.Fatalf("plenty of room: err=%v noStage=%q", err, c.noStage)
	}
	rootFree = 2000 // ≥ compressed, < ×3
	if err := c.spaceCheck(img); err != nil || c.noStage != img.Digest {
		t.Fatalf("short for a stage should fall back, not fail: err=%v noStage=%q", err, c.noStage)
	}
	rootFree = 500
	if err := c.spaceCheck(img); err == nil || !strings.Contains(err.Error(), "root filesystem") {
		t.Fatalf("less than the compressed image must be refused, got %v", err)
	}
}
