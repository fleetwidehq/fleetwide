package rootfs

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	ggcr "github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

// A tiny image in an in-process registry: the whole pull → verify → apply
// pipeline with no network and no root. The platform is the host's so
// registry.Resolve picks it without a manifest list.
func testImage(t *testing.T) (ref string, digest string) {
	t.Helper()
	srv := httptest.NewServer(ggcr.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	// crane.Image writes every entry with mode 0, which only root can read
	// back; these tests run unprivileged.
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, f := range []struct {
			name, body string
			mode       int64
		}{
			{"etc/app.conf", "listen 8080\n", 0o644},
			{"fleetwide/fleetwide.yaml", "version: \"1\"\n", 0o644},
			{"usr/bin/app", "#!/bin/sh\necho hi\n", 0o755},
		} {
			if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body))}); err != nil {
				return nil, err
			}
			if _, err := tw.Write([]byte(f.body)); err != nil {
				return nil, err
			}
		}
		if err := tw.Close(); err != nil {
			return nil, err
		}
		return io.NopCloser(&buf), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	// Edit the config AppendLayers built rather than replacing it: a fresh
	// ConfigFile has no RootFS.DiffIDs and the resolver rightly refuses an
	// image whose layer count and diff-id count disagree.
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	p := registry.HostPlatform()
	cf.OS, cf.Architecture = p.OS, p.Arch
	cf.Config.Entrypoint = []string{"/usr/bin/app"}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := name.ParseReference(host+"/acme/app:1", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	return host + "/acme/app:1", d.String()
}

func listing(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != root {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func testOpts(t *testing.T, root string) Options {
	t.Helper()
	cache, err := layercache.Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Cache: cache, Platform: registry.HostPlatform(), Root: root, Insecure: true, Log: t.Logf}
}

// The point of fetching first: a fetch that quietly touched the root would put
// files under a live process again. After Fetch the root is empty and the
// runtime is already known, so the caller can stop the old app knowing what
// it will start.
func TestFetchWritesNothing(t *testing.T) {
	ref, _ := testImage(t)
	root := t.TempDir()
	f, err := Fetch(context.Background(), ref, testOpts(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if got := listing(t, root); len(got) != 0 {
		t.Fatalf("Fetch wrote into the root: %v", got)
	}
	if argv := f.Runtime.Argv(nil); len(argv) == 0 || argv[0] != "/usr/bin/app" {
		t.Fatalf("the runtime should be known before anything is written: %v", argv)
	}
	if len(f.Layers()) != 1 || !strings.HasPrefix(f.Layers()[0], "sha256:") {
		t.Fatalf("layers: %v", f.Layers())
	}
	if !f.opts.Cache.Has(f.Layers()[0]) {
		t.Fatal("the layer should be in the cache after Fetch")
	}
}

// Fetch then Apply must produce exactly what Materialize does.
func TestApplyAfterFetchIsTheSameTree(t *testing.T) {
	ref, _ := testImage(t)
	a, b := t.TempDir(), t.TempDir()
	if _, err := Materialize(context.Background(), ref, testOpts(t, a)); err != nil {
		t.Fatal(err)
	}
	f, err := Fetch(context.Background(), ref, testOpts(t, b))
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if la, lb := listing(t, a), listing(t, b); strings.Join(la, "\n") != strings.Join(lb, "\n") {
		t.Fatalf("trees differ:\n%v\n%v", la, lb)
	}
	if res.PullMS != f.PullMS || res.Root != b || res.Stats.Files != 3 {
		t.Fatalf("result: pull=%d root=%s files=%d", res.PullMS, res.Root, res.Stats.Files)
	}
	if len(res.Paths) == 0 || res.Paths[0][0] != '/' {
		t.Fatalf("recorded paths should be absolute: %v", res.Paths[:1])
	}
}

// The vendor's digest is the contract: a registry serving something else is
// refused before a byte is pulled, and the root is untouched.
func TestFetchRejectsWrongDigestWithoutWriting(t *testing.T) {
	ref, _ := testImage(t)
	root := t.TempDir()
	o := testOpts(t, root)
	o.ExpectDigest = "sha256:" + strings.Repeat("0", 64)
	_, err := Fetch(context.Background(), ref, o)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("want a digest mismatch, got %v", err)
	}
	if got := listing(t, root); len(got) != 0 {
		t.Fatalf("nothing may be written on a refused fetch: %v", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(o.Cache.Dir(), "blobs", "sha256")); len(entries) != 0 {
		t.Fatalf("nothing may be pulled on a refused fetch: %d blobs", len(entries))
	}
}

// Apply is allowed to run twice from the same fetch: rollback in the gap
// re-applies a release whose layers are already cached.
func TestApplyTwice(t *testing.T) {
	ref, _ := testImage(t)
	root := t.TempDir()
	f, err := Fetch(context.Background(), ref, testOpts(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "etc", "app.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Apply(); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "app.conf")); string(b) != "listen 8080\n" {
		t.Fatalf("second apply must recreate the file: %q", b)
	}
}

// The managed supervisor's Options.Protected describes "/": mount points, the
// state dir and the staging root itself. Applied inside the staging root
// those prefixes match everything, and the first staged release committed a
// tree of nothing. Protection belongs to the commit; the stage must write.
func TestApplyToIgnoresProtectedPathsOutsideTheStagingRoot(t *testing.T) {
	ref, _ := testImage(t)
	o := testOpts(t, "/")
	o.Protected = []string{"/.fleetwide-staging", "/var/lib/fleetwide", "/data"}
	f, err := Fetch(context.Background(), ref, o)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), ".fleetwide-staging", "rel_1")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	// Make the extras look like the real ones: the staging root is an
	// ancestor of the tree being written.
	o.Protected = []string{filepath.Dir(staging), "/var/lib/fleetwide", "/data", filepath.Join(staging, "etc", "hosts")}
	f.opts = o
	res, err := f.ApplyTo(staging)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Files != 3 || res.Stats.Skipped != 0 {
		t.Fatalf("stage wrote files=%d skipped=%d; want 3 and 0", res.Stats.Files, res.Stats.Skipped)
	}
	if got := listing(t, staging); len(got) == 0 {
		t.Fatal("staging root is empty")
	}
}

// A stage that writes nothing is refused rather than committed: the commit
// of an empty tree would take the running release's files away and put
// nothing back.
func TestApplyToRefusesAnEmptyStage(t *testing.T) {
	ref, _ := testImage(t)
	f, err := Fetch(context.Background(), ref, testOpts(t, "/"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "rel_1")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	f.opts.Protected = []string{filepath.Join(staging, "etc"), filepath.Join(staging, "fleetwide"), filepath.Join(staging, "usr")}
	if _, err := f.ApplyTo(staging); err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// The embedded runtime pulls only the layers it needs and applies only the
// sync paths out of them: the staging root ends up with the image's /etc
// and /fleetwide and nothing from /usr.
func TestSyncViewAppliesOnlyTheSyncPathsOfTheNamedLayers(t *testing.T) {
	ref, _ := testImage(t)
	o := testOpts(t, "/")
	// Resolve first to learn the digests, then fetch just those.
	img, err := registry.Resolve(context.Background(), ref, o.Platform, registry.Options{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	o.PullOnly = []string{img.Layers[0].Digest}
	f, err := Fetch(context.Background(), ref, o)
	if err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	res, err := f.SyncView([]string{img.Layers[0].Digest}, []string{"/etc", "/fleetwide"}, staging)
	if err != nil {
		t.Fatal(err)
	}
	got := listing(t, staging)
	want := []string{"etc", "etc/app.conf", "fleetwide", "fleetwide/fleetwide.yaml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sync view: %v", got)
	}
	if res.Stats.Files != 2 || res.Stats.Skipped != 1 {
		t.Fatalf("stats: files=%d skipped=%d", res.Stats.Files, res.Stats.Skipped)
	}
	if err := f.SyncPreflight([]string{img.Layers[0].Digest}, []string{"/etc"}, t.TempDir(), nil); err != nil {
		t.Fatalf("preflight into a fresh writable root: %v", err)
	}
}

// A subset pull leaves the other layers out of the cache.
func TestPullOnlyLeavesOtherLayersUncached(t *testing.T) {
	ref, _ := testImage(t)
	o := testOpts(t, "/")
	o.PullOnly = []string{"sha256:" + strings.Repeat("f", 64)} // nothing matches
	f, err := Fetch(context.Background(), ref, o)
	if err != nil {
		t.Fatal(err)
	}
	if o.Cache.Has(f.Layers()[0]) {
		t.Fatal("a layer outside PullOnly must not be pulled")
	}
}

// A multi-platform index: the release pins the index, every architecture
// takes it, and each supervisor resolves and verifies its own image.
func testIndex(t *testing.T) (ref, indexDigest, hostDigest string) {
	t.Helper()
	srv := httptest.NewServer(ggcr.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	p := registry.HostPlatform()
	other := "amd64"
	if p.Arch == "amd64" {
		other = "arm64"
	}
	idx := ggcrv1.ImageIndex(empty.Index)
	idx = mutate.IndexMediaType(idx, types.OCIImageIndex)
	for _, arch := range []string{p.Arch, other} {
		img, err := crane.Image(map[string][]byte{"etc/" + arch: []byte(arch)})
		if err != nil {
			t.Fatal(err)
		}
		cf, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture = "linux", arch
		cf.Config.Entrypoint = []string{"/bin/" + arch}
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatal(err)
		}
		if arch == p.Arch {
			d, _ := img.Digest()
			hostDigest = d.String()
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: ggcrv1.Descriptor{Platform: &ggcrv1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	r, err := name.ParseReference(host+"/acme/multi:1", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
	d, _ := idx.Digest()
	return host + "/acme/multi:1", d.String(), hostDigest
}

func TestFetchAcceptsAnIndexDigest(t *testing.T) {
	ref, indexDigest, hostDigest := testIndex(t)
	if indexDigest == hostDigest {
		t.Fatal("the index and its child must differ, or this proves nothing")
	}
	// pinned by the index: resolves to this architecture and verifies
	o := testOpts(t, t.TempDir())
	o.ExpectDigest = indexDigest
	f, err := Fetch(context.Background(), ref, o)
	if err != nil {
		t.Fatalf("an index-pinned release must resolve here: %v", err)
	}
	if f.Image.IndexDigest != indexDigest || f.Image.Digest != hostDigest {
		t.Fatalf("index=%s digest=%s want %s / %s", f.Image.IndexDigest, f.Image.Digest, indexDigest, hostDigest)
	}
	if argv := f.Runtime.Argv(nil); argv[0] != "/bin/"+registry.HostPlatform().Arch {
		t.Fatalf("resolved the wrong architecture: %v", argv)
	}
	// pinned by this platform's manifest: also accepted
	o = testOpts(t, t.TempDir())
	o.ExpectDigest = hostDigest
	if _, err := Fetch(context.Background(), ref, o); err != nil {
		t.Fatalf("a platform-pinned release must resolve too: %v", err)
	}
	// anything else is still refused
	o = testOpts(t, t.TempDir())
	o.ExpectDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := Fetch(context.Background(), ref, o); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("want a digest mismatch, got %v", err)
	}
}
