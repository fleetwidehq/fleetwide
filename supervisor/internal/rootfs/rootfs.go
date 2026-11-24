// Package rootfs pulls an image and materialises it into a directory: the
// pull → verify → decompress → apply pipeline shared by `unpack` and `run`.
package rootfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/mounts"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/progress"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/unpack"
)

// Result summarises a materialised image.
type Result struct {
	Image       *registry.Image  `json:"image"`
	Runtime     imagecfg.Runtime `json:"runtime"`
	Root        string           `json:"root"`
	Compression []string         `json:"compression"` // per layer
	Stats       unpack.Stats     `json:"stats"`
	Protected   []string         `json:"protected,omitempty"`
	PullMS      int64            `json:"pull_ms"`
	UnpackMS    int64            `json:"unpack_ms"`
	Warnings    []string         `json:"warnings,omitempty"`
	// Paths is every absolute path written (files, dirs, links), for residue
	// cleanup on update. Not serialised: tens of thousands of entries.
	Paths []string `json:"-"`
}

// Options for Fetch, Apply and Materialize.
type Options struct {
	Cache    *layercache.Cache
	Platform registry.Platform
	// Root is the destination. When Root is "/" the process's mount points
	// and its own executable are protected automatically.
	Root string
	// Extra protected paths.
	Protected  []string
	Chown      bool
	Insecure   bool // plain-HTTP registry
	SkipVerify bool // accept any TLS certificate from the registry
	// Auth is the Console-supplied registry credential for this release (may be nil).
	Auth *registry.Auth
	// ExpectDigest, when set, must equal the resolved platform manifest
	// digest or nothing is pulled: the vendor-declared digest is the
	// contract for private and isolated registries.
	ExpectDigest string
	Log          func(format string, args ...any)
	Progress     progress.Reporter // optional: reports bytes while layers download
	// Preflight, when set, runs after the image is resolved and its digest
	// checked, before a byte is pulled: the resolved manifest says how big
	// every layer is, so this is where a caller refuses what cannot fit.
	Preflight func(img *registry.Image) error
	// PullOnly, when set, pulls only these layer digests (the embedded
	// runtime's sync-path layers and metadata layer); nil pulls every layer.
	PullOnly []string
}

// Fetched is an image whose layers are all in the cache: everything needed
// to write it into a root, with nothing written yet. The runtime config comes
// from the image config, so the caller knows what it will run before it stops
// what is running now.
type Fetched struct {
	Image   *registry.Image
	Runtime imagecfg.Runtime
	PullMS  int64

	opts Options
}

// Fetch resolves ref, verifies the pinned digest and pulls every layer into
// the cache. It writes nothing into opts.Root: a bad digest, an unreachable
// registry, a rejected credential or a full cache all fail here. Call Apply
// to write the image.
func Fetch(ctx context.Context, ref string, opts Options) (*Fetched, error) {
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	img, err := registry.Resolve(ctx, ref, opts.Platform, registry.Options{Insecure: opts.Insecure, SkipVerify: opts.SkipVerify, Auth: opts.Auth})
	if err != nil {
		return nil, err
	}
	opts.Log("resolved %s -> %s (%d layers, %s)", ref, img.Digest, len(img.Layers), img.Platform)
	if !img.Matches(opts.ExpectDigest) {
		served := img.Digest
		if img.IndexDigest != "" {
			served = fmt.Sprintf("%s (%s of index %s)", img.Digest, img.Platform, img.IndexDigest)
		}
		return nil, fmt.Errorf("digest mismatch before pull: release pins %s, registry serves %s", opts.ExpectDigest, served)
	}

	if opts.Preflight != nil {
		if err := opts.Preflight(img); err != nil {
			return nil, err
		}
	}

	t0 := time.Now()
	var want map[string]bool
	if opts.PullOnly != nil {
		want = map[string]bool{}
		for _, d := range opts.PullOnly {
			want[d] = true
		}
	}
	if err := img.PullSubset(ctx, opts.Cache, want, opts.Progress); err != nil {
		return nil, err
	}
	f := &Fetched{Image: img, Runtime: imagecfg.FromConfigFile(img.Config), PullMS: time.Since(t0).Milliseconds(), opts: opts}
	for _, l := range img.Layers {
		src := "pulled"
		if l.FromCache {
			src = "cache"
		}
		opts.Log("layer %s %d bytes (%s)", l.Digest[:19], l.Size, src)
	}
	return f, nil
}

// Layers is the image's layer digests in order, for the caller to remember
// which cache blobs this image needs.
func (f *Fetched) Layers() []string {
	out := make([]string, len(f.Image.Layers))
	for i, l := range f.Image.Layers {
		out[i] = l.Digest
	}
	return out
}

// Apply writes the fetched image into the root Fetch was given, recording
// every path it creates. Mount points are read here rather than at fetch
// time: a mount can appear while the layers download, and the list has to
// describe the filesystem as it is when the writing happens. Apply may be
// called more than once; each call re-reads the cached layers.
func (f *Fetched) Apply() (*Result, error) {
	opts := f.opts
	res := &Result{Image: f.Image, Runtime: f.Runtime, Root: opts.Root, PullMS: f.PullMS}

	protected, err := ProtectedPaths(opts.Root, append([]string{opts.Cache.Dir()}, opts.Protected...)...)
	if err != nil {
		return nil, err
	}
	res.Protected = protected

	seen := map[string]struct{}{}
	applier, err := unpack.New(opts.Root, unpack.Options{
		Protected: protected,
		Chown:     opts.Chown,
		Record: func(abs string) {
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				res.Paths = append(res.Paths, abs)
			}
		},
		Warn: func(fm string, a ...any) {
			msg := fmt.Sprintf(fm, a...)
			res.Warnings = append(res.Warnings, msg)
			opts.Log("warn: %s", msg)
		},
	})
	if err != nil {
		return nil, err
	}

	t1 := time.Now()
	for i, l := range f.Image.Layers {
		blob, err := opts.Cache.Open(l.Digest)
		if err != nil {
			return nil, err
		}
		tr, kind, err := unpack.Decompress(blob)
		if err != nil {
			blob.Close()
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		st, err := applier.Apply(tr)
		tr.Close()
		blob.Close()
		if err != nil {
			return nil, fmt.Errorf("apply layer %d (%s): %w", i, l.Digest, err)
		}
		res.Compression = append(res.Compression, kind)
		res.Stats.Add(st)
		opts.Log("applied layer %d: %s files=%d dirs=%d links=%d/%d wh=%d opq=%d removed=%d skipped=%d",
			i, kind, st.Files, st.Dirs, st.Symlinks, st.Hardlinks, st.Whiteouts, st.Opaques, st.Removed, st.Skipped)
	}
	res.UnpackMS = time.Since(t1).Milliseconds()
	return res, nil
}

// ApplyTo writes the image into root instead of the root Fetch was given,
// for staging. Options.Protected describes the root Fetch was given and is
// enforced when the staged tree is committed; only protected paths that lie
// under root are kept here.
func (f *Fetched) ApplyTo(root string) (*Result, error) {
	g := *f
	g.opts.Root = root
	g.opts.Protected = nil
	for _, p := range f.opts.Protected {
		if strings.HasPrefix(p, root+"/") {
			g.opts.Protected = append(g.opts.Protected, p)
		}
	}
	res, err := g.Apply()
	if err != nil {
		return nil, err
	}
	if res.Stats.Files+res.Stats.Dirs+res.Stats.Symlinks+res.Stats.Hardlinks == 0 && len(f.Image.Layers) > 0 {
		// An image with layers always has entries; a tree with none means
		// everything was skipped, and committing it would remove the
		// running release's files without putting anything in their place.
		return nil, fmt.Errorf("staging %s: nothing was written (%d entries skipped)", root, res.Stats.Skipped)
	}
	return res, nil
}

// SyncView writes the merged view of the sync paths into root: the layers
// named in digests (a subset of the image's, in image order) are applied
// with everything outside only skipped, whiteouts included, so the result
// under each sync path is exactly what the image has there. Nothing else in
// root is touched.
func (f *Fetched) SyncView(digests []string, only []string, root string) (*Result, error) {
	want := map[string]bool{}
	for _, d := range digests {
		want[d] = true
	}
	res := &Result{Image: f.Image, Runtime: f.Runtime, Root: root, PullMS: f.PullMS}
	seen := map[string]struct{}{}
	applier, err := unpack.New(root, unpack.Options{
		Only:  only,
		Chown: f.opts.Chown,
		Record: func(abs string) {
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				res.Paths = append(res.Paths, abs)
			}
		},
		Warn: func(fm string, a ...any) {
			msg := fmt.Sprintf(fm, a...)
			res.Warnings = append(res.Warnings, msg)
			f.opts.Log("warn: %s", msg)
		},
	})
	if err != nil {
		return nil, err
	}
	t1 := time.Now()
	for i, l := range f.Image.Layers {
		if !want[l.Digest] {
			continue
		}
		blob, err := f.opts.Cache.Open(l.Digest)
		if err != nil {
			return nil, err
		}
		tr, kind, err := unpack.Decompress(blob)
		if err != nil {
			blob.Close()
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		st, err := applier.Apply(tr)
		tr.Close()
		blob.Close()
		if err != nil {
			return nil, fmt.Errorf("apply layer %d (%s): %w", i, l.Digest, err)
		}
		res.Compression = append(res.Compression, kind)
		res.Stats.Add(st)
	}
	res.UnpackMS = time.Since(t1).Milliseconds()
	return res, nil
}

// SyncPreflight checks, as this process, that the sync-path entries of the
// named layers could be written into root — the same walk SyncView would
// make, with nothing written. The first impossible destination is returned
// as an *unpack.PreflightError.
func (f *Fetched) SyncPreflight(digests []string, only []string, root string, protected []string) error {
	want := map[string]bool{}
	for _, d := range digests {
		want[d] = true
	}
	applier, err := unpack.New(root, unpack.Options{Only: only, Protected: protected})
	if err != nil {
		return err
	}
	created := map[string]bool{}
	for i, l := range f.Image.Layers {
		if !want[l.Digest] {
			continue
		}
		blob, err := f.opts.Cache.Open(l.Digest)
		if err != nil {
			return err
		}
		tr, _, err := unpack.Decompress(blob)
		if err != nil {
			blob.Close()
			return fmt.Errorf("layer %d: %w", i, err)
		}
		err = applier.Preflight(tr, created)
		tr.Close()
		blob.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// StagedPaths lists where every entry of a staged tree will land under dst,
// before it is committed: the record a crash mid-commit leaves behind, so the
// next start knows what to clean up. Destinations are the plain join — the
// commit resolves them properly and rewrites the record afterwards.
func StagedPaths(staged, dst string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(staged, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == staged {
			return nil
		}
		rel, err := filepath.Rel(staged, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.Join(dst, rel))
		return nil
	})
	return out, err
}

// Materialize is Fetch followed immediately by Apply: resolve, pull and
// unpack ref into opts.Root in one go. The one-shot commands use it; the
// managed supervisor fetches first and applies later, with the application stopped.
func Materialize(ctx context.Context, ref string, opts Options) (*Result, error) {
	f, err := Fetch(ctx, ref, opts)
	if err != nil {
		return nil, err
	}
	return f.Apply()
}

// ProtectedPaths returns the paths that must never be written or removed
// when materialising into root: when root is "/", every mount point and the
// supervisor's own executable, plus extra.
func ProtectedPaths(root string, extra ...string) ([]string, error) {
	protected := append([]string{}, extra...)
	if filepath.Clean(root) == "/" {
		mps, err := mounts.Points()
		if err != nil {
			return nil, fmt.Errorf("mountinfo: %w", err)
		}
		protected = append(protected, mps...)
		if exe, err := os.Executable(); err == nil {
			protected = append(protected, exe)
		}
	}
	return protected, nil
}
