package layercache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func put(t *testing.T, c *Cache, body string) string {
	t.Helper()
	d := digestOf([]byte(body))
	if _, err := c.Put(d, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	return d
}

func age(t *testing.T, c *Cache, digest string, by time.Duration) {
	t.Helper()
	p, _ := c.blobPath(digest)
	old := time.Now().Add(-by)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

// Five blobs, keep two: the other three go and the bytes are reported. A
// digest in the keep set that was never cached is not an error.
func TestRetainRemovesWhatIsNotKept(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var ds []string
	for _, b := range []string{"one", "two", "three", "four", "five"} {
		d := put(t, c, b)
		age(t, c, d, 2*time.Hour)
		ds = append(ds, d)
	}
	keep := map[string]bool{ds[0]: true, ds[1]: true, "sha256:" + strings.Repeat("0", 64): true}
	r, err := c.Retain(keep, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r.Blobs != 3 || r.Bytes != int64(len("three")+len("four")+len("five")) {
		t.Fatalf("retained: %+v", r)
	}
	for i, d := range ds {
		if c.Has(d) != (i < 2) {
			t.Fatalf("blob %d present=%v", i, c.Has(d))
		}
	}
}

// A blob written moments ago belongs to a pull in flight, named in the keep
// set or not; a tmp file younger than an hour is a pull mid-stream.
func TestRetainLeavesYoungBlobsAlone(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	young := put(t, c, "young")
	old := put(t, c, "old")
	age(t, c, old, 2*time.Hour)
	fresh := filepath.Join(c.Dir(), "tmp", "blob-fresh")
	stale := filepath.Join(c.Dir(), "tmp", "blob-stale")
	os.WriteFile(fresh, []byte("x"), 0o600)
	os.WriteFile(stale, []byte("x"), 0o600)
	then := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, then, then)
	r, err := c.Retain(map[string]bool{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Has(young) || c.Has(old) {
		t.Fatalf("young kept=%v old kept=%v", c.Has(young), c.Has(old))
	}
	if r.Temps != 1 {
		t.Fatalf("temps removed: %d", r.Temps)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("a fresh tmp file is a pull mid-stream and must stay")
	}
}

func TestSize(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put(t, c, "abc")
	put(t, c, "defgh")
	if b, n := c.Size(); b != 8 || n != 2 {
		t.Fatalf("size %d blobs %d", b, n)
	}
}
