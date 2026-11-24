// Package layercache is a content-addressed store for compressed OCI layer
// blobs. Blobs are written to a temp file, hashed while streaming, verified
// against the expected digest and atomically renamed into place.
package layercache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cache stores blobs under <dir>/blobs/sha256/<hex>.
type Cache struct {
	dir string
}

// Open creates the cache directory structure if needed.
func Open(dir string) (*Cache, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		return nil, err
	}
	return &Cache{dir: dir}, nil
}

// Dir returns the cache root.
func (c *Cache) Dir() string { return c.dir }

func (c *Cache) blobPath(digest string) (string, error) {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" || len(hex) != 64 {
		return "", fmt.Errorf("unsupported digest %q", digest)
	}
	return filepath.Join(c.dir, "blobs", "sha256", hex), nil
}

// Has reports whether the blob is present.
func (c *Cache) Has(digest string) bool {
	p, err := c.blobPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Open returns a reader for a cached blob.
func (c *Cache) Open(digest string) (*os.File, error) {
	p, err := c.blobPath(digest)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Retained is what Retain removed.
type Retained struct {
	Blobs int
	Bytes int64
	Temps int // abandoned tmp/blob-* files
}

// Retain deletes every blob whose digest is not in keep and that is older
// than minAge, plus tmp files older than an hour. The age floor keeps a pull
// in flight safe: a blob written moments ago belongs to someone. A digest in
// keep that is not in the cache is not an error.
func (c *Cache) Retain(keep map[string]bool, minAge time.Duration) (Retained, error) {
	var out Retained
	dir := filepath.Join(c.dir, "blobs", "sha256")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	cutoff := time.Now().Add(-minAge)
	for _, e := range entries {
		if e.IsDir() || keep["sha256:"+e.Name()] {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			out.Blobs++
			out.Bytes += fi.Size()
		}
	}
	if temps, err := os.ReadDir(filepath.Join(c.dir, "tmp")); err == nil {
		old := time.Now().Add(-time.Hour)
		for _, e := range temps {
			if fi, err := e.Info(); err == nil && !fi.IsDir() && fi.ModTime().Before(old) {
				if os.Remove(filepath.Join(c.dir, "tmp", e.Name())) == nil {
					out.Temps++
				}
			}
		}
	}
	return out, nil
}

// Size is the bytes held by the cache's blobs, and how many there are.
func (c *Cache) Size() (bytes int64, blobs int) {
	entries, err := os.ReadDir(filepath.Join(c.dir, "blobs", "sha256"))
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && !fi.IsDir() {
			bytes += fi.Size()
			blobs++
		}
	}
	return bytes, blobs
}

// ErrDigestMismatch is returned when streamed content does not hash to the
// expected digest. Nothing is committed to the cache in that case.
var ErrDigestMismatch = errors.New("digest mismatch")

// Put streams r into the cache, verifying it hashes to digest. Returns the
// number of bytes written. If the blob already exists it drains nothing and
// returns (0, nil).
func (c *Cache) Put(digest string, r io.Reader) (int64, error) {
	final, err := c.blobPath(digest)
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(final); err == nil {
		return 0, nil
	}
	tmp, err := os.CreateTemp(filepath.Join(c.dir, "tmp"), "blob-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		cleanup()
		return n, err
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != digest {
		cleanup()
		return n, fmt.Errorf("%w: want %s got %s", ErrDigestMismatch, digest, got)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return n, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return n, err
	}
	if err := os.Chmod(tmpName, 0o444); err != nil {
		os.Remove(tmpName)
		return n, err
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		// Lost a race with a concurrent Put of the same blob: fine.
		if _, statErr := os.Stat(final); statErr == nil {
			return n, nil
		}
		return n, err
	}
	return n, nil
}
