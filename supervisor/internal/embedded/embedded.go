// Package embedded describes an image produced by `fleetwide embed`: the
// customer's image with the supervisor as its start command, running as the
// image's USER. The supervisor keeps the app's declared sync paths in step with
// the release the console assigns and leaves everything else alone; the
// index of everything else is what tells a base change from an app change.
package embedded

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
)

// Files and labels written into the image by the CLI.
const (
	Dir            = "/fleetwide"
	File           = Dir + "/embedded.json"
	IndexFile      = Dir + "/embedded.index.gz"
	StagingDir     = Dir + "/staging"
	SupervisorPath = "/fleetwide-supervisor"

	LabelRuntime   = "io.fleetwide.runtime"
	LabelMetaLayer = "io.fleetwide.meta.layer"   // digest of the layer holding embedded.json + the index
	LabelIndexSHA  = "io.fleetwide.index.sha256" // sha256 of embedded.index.gz
	LabelAppDigest = "io.fleetwide.app.digest"   // the customer image this was built from

	RuntimeEmbedded = "embedded"
)

// Start modes (Info.Start).
const (
	StartEmbedded = "embedded" // run the embedded app now, sync when the console says
	StartLatest   = "latest"   // enroll, sync the assigned release, then start
)

// Info is the content of embedded.json.
type Info struct {
	Runtime  string `json:"runtime"` // "embedded"
	App      string `json:"app,omitempty"`
	Console  string `json:"console,omitempty"`
	CASHA256 string `json:"ca_sha256,omitempty"`

	// The customer image this was built from: reference pinned by digest,
	// its digest, and its layers (DiffIDs) so an identical release is
	// recognised without reading anything.
	Image  string `json:"image"`
	Digest string `json:"digest"`
	// IndexDigest is the multi-platform index Digest came out of, if any: a
	// release may pin either.
	IndexDigest string   `json:"index_digest,omitempty"`
	DiffIDs     []string `json:"diff_ids"`
	// SyncLayers are the customer image's layers (compressed digests) that
	// touch a sync or asset path: the only layers the supervisor has to pull
	// from this image to bring another container's sync paths to this state.
	SyncLayers []string `json:"sync_layers"`
	SyncPaths  []string `json:"sync_paths"`
	AssetPaths []string `json:"asset_paths,omitempty"`

	User          string           `json:"user"` // "uid:gid" the supervisor and app run as ("" = root)
	Start         string           `json:"start"`
	StartFallback string           `json:"start_fallback,omitempty"` // fallback | strict, for start=latest
	StartTimeoutS int              `json:"start_timeout_s,omitempty"`
	Process       imagecfg.Runtime `json:"process"` // the image's original entrypoint/cmd/env/user/workdir

	SupervisorVersion string    `json:"supervisor_version"`
	Profile           string    `json:"profile,omitempty"`
	IndexSHA256       string    `json:"index_sha256"`
	EmbeddedAt        time.Time `json:"embedded_at"`
}

// Load reads embedded.json under root. Returns (nil, nil) when the image is
// not an embedded image.
func Load(root string) (*Info, error) {
	b, err := os.ReadFile(filepath.Join(root, File))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("embedded.json: %w", err)
	}
	if in.Runtime != RuntimeEmbedded || in.Digest == "" {
		return nil, errors.New("embedded.json: not an embedded image")
	}
	return &in, nil
}

// Excluded are paths that differ between builds by construction and are
// left out of every index: the supervisor, its metadata and its state.
var Excluded = []string{Dir, SupervisorPath, "/var/lib/fleetwide"}

// Entry is one filesystem entry in an index.
type Entry struct {
	Path string `json:"p"`
	Type string `json:"t"`           // f file, d dir, l symlink, c char, b block, p fifo
	Mode uint32 `json:"m"`           // permission bits incl. setuid/setgid/sticky
	UID  int    `json:"u"`           //
	GID  int    `json:"g"`           //
	Size int64  `json:"s,omitempty"` // regular files
	Hash string `json:"h,omitempty"` // sha256 hex of a regular file's content
	Link string `json:"l,omitempty"` // symlink target
}

// Index is the merged view of an image's filesystem outside the excluded
// paths: one entry per path, sorted.
type Index struct {
	Entries []Entry
}

// Build indexes a flattened image tar (whiteouts already applied — what
// mutate.Extract produces). Regular files are hashed as they stream past.
func Build(r io.Reader) (*Index, error) {
	tr := tar.NewReader(r)
	byPath := map[string]Entry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		p := clean(h.Name)
		if p == "/" || under(p, Excluded) {
			if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
				io.Copy(io.Discard, tr)
			}
			continue
		}
		e := Entry{Path: p, Mode: uint32(h.Mode) & 0o7777, UID: h.Uid, GID: h.Gid}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			e.Type = "f"
			sum := sha256.New()
			n, err := io.Copy(sum, tr)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			e.Size, e.Hash = n, hex.EncodeToString(sum.Sum(nil))
		case tar.TypeDir:
			e.Type = "d"
		case tar.TypeSymlink:
			e.Type, e.Link = "l", h.Linkname
		case tar.TypeLink:
			// a hard link is the same content as its target; record it as a
			// file with the target's hash, filled in below
			e.Type, e.Link = "f", clean(h.Linkname)
		case tar.TypeChar:
			e.Type = "c"
		case tar.TypeBlock:
			e.Type = "b"
		case tar.TypeFifo:
			e.Type = "p"
		default:
			continue
		}
		byPath[p] = e
	}
	out := &Index{}
	for _, e := range byPath {
		if e.Type == "f" && e.Hash == "" && e.Link != "" {
			if t, ok := byPath[e.Link]; ok {
				e.Size, e.Hash = t.Size, t.Hash
			}
			e.Link = ""
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	return out, nil
}

// Write encodes the index as gzipped JSON lines and returns the sha256 of
// what was written.
func (x *Index) Write(w io.Writer) (string, error) {
	sum := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(w, sum))
	enc := json.NewEncoder(gz)
	for _, e := range x.Entries {
		if err := enc.Encode(e); err != nil {
			return "", err
		}
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil)), nil
}

// Read decodes an index written by Write and returns it with the sha256 of
// the bytes read, for checking against the label.
func Read(r io.Reader) (*Index, string, error) {
	sum := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(r, sum))
	if err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(gz)
	out := &Index{}
	for {
		var e Entry
		if err := dec.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return nil, "", err
		}
		out.Entries = append(out.Entries, e)
	}
	return out, "sha256:" + hex.EncodeToString(sum.Sum(nil)), nil
}

// Change is one difference between two indexes.
type Change struct {
	Path string
	Kind string // added | removed | changed
	What string // the field that differs, for changed
}

// Diff compares two indexes outside the given paths (the sync and asset
// paths, which are meant to differ): what b has that a does not, what a has
// that b lost, and what both have with different type, size, content, mode,
// owner or link target. mtime is not part of an index at all.
func Diff(a, b *Index, inside []string) []Change {
	am := map[string]Entry{}
	for _, e := range a.Entries {
		if !under(e.Path, inside) {
			am[e.Path] = e
		}
	}
	var out []Change
	for _, e := range b.Entries {
		if under(e.Path, inside) {
			continue
		}
		o, ok := am[e.Path]
		if !ok {
			out = append(out, Change{Path: e.Path, Kind: "added"})
			continue
		}
		delete(am, e.Path)
		switch {
		case o.Type != e.Type:
			out = append(out, Change{e.Path, "changed", "type"})
		case o.Hash != e.Hash || o.Size != e.Size:
			out = append(out, Change{e.Path, "changed", "content"})
		case o.Link != e.Link:
			out = append(out, Change{e.Path, "changed", "link"})
		case o.Mode != e.Mode:
			out = append(out, Change{e.Path, "changed", "mode"})
		case o.UID != e.UID || o.GID != e.GID:
			out = append(out, Change{e.Path, "changed", "owner"})
		}
	}
	for p := range am {
		out = append(out, Change{Path: p, Kind: "removed"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Summary is a one-line account of changes for an event: the count and the
// first few paths.
func Summary(ch []Change, max int) string {
	if len(ch) == 0 {
		return "no changes"
	}
	var names []string
	for i, c := range ch {
		if i == max {
			break
		}
		names = append(names, c.Path+" ("+c.Kind+")")
	}
	more := ""
	if len(ch) > max {
		more = fmt.Sprintf(", … %d more", len(ch)-max)
	}
	return fmt.Sprintf("%d path(s): %s%s", len(ch), strings.Join(names, ", "), more)
}

// ReadMeta finds embedded.json and the index in a metadata layer's tar
// stream (uncompressed).
func ReadMeta(r io.Reader) (*Info, *Index, string, error) {
	tr := tar.NewReader(r)
	var info *Info
	var idx *Index
	var sha string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, "", err
		}
		switch clean(h.Name) {
		case File:
			var in Info
			if err := json.NewDecoder(tr).Decode(&in); err != nil {
				return nil, nil, "", fmt.Errorf("embedded.json: %w", err)
			}
			info = &in
		case IndexFile:
			if idx, sha, err = Read(tr); err != nil {
				return nil, nil, "", fmt.Errorf("index: %w", err)
			}
		}
	}
	if info == nil || idx == nil {
		return nil, nil, "", errors.New("metadata layer has no embedded.json or index")
	}
	return info, idx, sha, nil
}

// Under reports whether p is one of the roots or lies beneath one.
func Under(p string, roots []string) bool { return under(p, roots) }

func under(p string, roots []string) bool {
	for _, r := range roots {
		r = clean(r)
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func clean(name string) string {
	return "/" + strings.TrimPrefix(path.Clean("/"+name), "/")
}
