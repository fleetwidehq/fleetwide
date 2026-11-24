package main

import (
	"archive/tar"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	gv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/baked"
	fwregistry "github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

func TestParsePlatforms(t *testing.T) {
	got, err := parsePlatforms("linux/arm64, linux/amd64 ,linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if joinPlatforms(got) != "linux/arm64,linux/amd64" {
		t.Fatalf("a repeated platform must be listed once, in order: %s", joinPlatforms(got))
	}
	if _, err := parsePlatforms("  "); err == nil {
		t.Fatal("an empty platform list must be refused")
	}
	if _, err := parsePlatforms("nonsense"); err == nil {
		t.Fatal("a malformed platform must be refused")
	}
}

// A mixed fleet should be one tag and one command: baking two platforms pushes
// an index with an entry per platform, each carrying the supervisor for it.
func TestBakeMultiPlatformPushesAnIndex(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	host := strings.TrimPrefix(reg.URL, "http://")

	// a two-platform source image
	idx := gv1.ImageIndex(empty.Index)
	idx = mutate.IndexMediaType(idx, types.OCIImageIndex)
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{
			OS: "linux", Architecture: arch,
			Config: gv1.Config{Entrypoint: []string{"/app"}, Env: []string{"PATH=/bin"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: gv1.Descriptor{Platform: &gv1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	srcRef, _ := name.ParseReference(host+"/acme/app:1", name.Insecure)
	if err := remote.WriteIndex(srcRef, idx); err != nil {
		t.Fatal(err)
	}

	// One binary is built for one architecture: a multi-platform bake needs
	// one per platform, and says so rather than baking the wrong one.
	dir := t.TempDir()
	bins := map[string]string{}
	for _, arch := range []string{"amd64", "arm64"} {
		path := filepath.Join(dir, "fleetwide-supervisor."+arch)
		if err := os.WriteFile(path, []byte("ELF-supervisor-"+arch), 0o755); err != nil {
			t.Fatal(err)
		}
		bins[arch] = path
	}
	dst := host + "/acme/app-fleetwide:1"
	if err := cmdBake([]string{
		"--image", host + "/acme/app:1", "--tag", dst, "--push", "--plain-http",
		"--platform", "linux/amd64,linux/arm64", "--supervisor-binary", bins["arm64"],
		"--app", "acme", "--version", "1",
	}); err == nil || !strings.Contains(err.Error(), "one per platform") {
		t.Fatalf("one binary for two platforms must be refused, got %v", err)
	}
	err := cmdBake([]string{
		"--image", host + "/acme/app:1", "--tag", dst, "--push", "--plain-http",
		"--platform", "linux/amd64,linux/arm64",
		"--supervisor-binary", "linux/amd64=" + bins["amd64"], "--supervisor-binary", "linux/arm64=" + bins["arm64"],
		"--app", "acme", "--version", "1",
	})
	if err != nil {
		t.Fatalf("bake: %v", err)
	}

	dstRef, _ := name.ParseReference(dst, name.Insecure)
	got, err := remote.Index(dstRef)
	if err != nil {
		t.Fatalf("the result must be an index: %v", err)
	}
	im, err := got.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 2 {
		t.Fatalf("want one manifest per platform, got %d", len(im.Manifests))
	}
	seen := map[string]bool{}
	for _, m := range im.Manifests {
		if m.Platform == nil {
			t.Fatalf("every entry needs its platform: %+v", m)
		}
		seen[m.Platform.OS+"/"+m.Platform.Architecture] = true
		img, err := got.Image(m.Digest)
		if err != nil {
			t.Fatal(err)
		}
		cf, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if cf.Architecture != m.Platform.Architecture {
			t.Fatalf("entry says %s but the image is %s", m.Platform.Architecture, cf.Architecture)
		}
		if strings.Join(cf.Config.Entrypoint, " ") != baked.SupervisorPath+" supervise" {
			t.Fatalf("each platform must be baked: %v", cf.Config.Entrypoint)
		}
		if cf.Config.Labels["io.fleetwide.app"] != "acme" {
			t.Fatalf("provenance labels missing on %s: %v", m.Platform.Architecture, cf.Config.Labels)
		}
		// the supervisor inside must be the one built for this architecture
		if want, got := "ELF-supervisor-"+m.Platform.Architecture, supervisorBytesIn(t, img); got != want {
			t.Fatalf("%s image carries %q, want %q", m.Platform.Architecture, got, want)
		}
	}
	if !seen["linux/amd64"] || !seen["linux/arm64"] {
		t.Fatalf("platforms: %v", seen)
	}
}

// --all-platforms bakes what the source actually has, and says so plainly when
// the source is a single image.
func TestAllPlatformsReadsTheSource(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	host := strings.TrimPrefix(reg.URL, "http://")
	img, _ := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "linux", Architecture: "arm64"})
	ref, _ := name.ParseReference(host+"/acme/single:1", name.Insecure)
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	if _, err := platformsOf(t.Context(), host+"/acme/single:1", true); err == nil || !strings.Contains(err.Error(), "single image") {
		t.Fatalf("a single image should say so: %v", err)
	}
	idx := mutate.IndexMediaType(gv1.ImageIndex(empty.Index), types.OCIImageIndex)
	for _, arch := range []string{"amd64", "arm64"} {
		i, _ := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "linux", Architecture: arch})
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: i, Descriptor: gv1.Descriptor{Platform: &gv1.Platform{OS: "linux", Architecture: arch}}})
	}
	// an attestation manifest, which is not a platform anyone can run
	att, _ := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "unknown", Architecture: "unknown"})
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: att, Descriptor: gv1.Descriptor{Platform: &gv1.Platform{OS: "unknown", Architecture: "unknown"}}})
	multiRef, _ := name.ParseReference(host+"/acme/multi:1", name.Insecure)
	if err := remote.WriteIndex(multiRef, idx); err != nil {
		t.Fatal(err)
	}
	got, err := platformsOf(t.Context(), host+"/acme/multi:1", true)
	if err != nil {
		t.Fatal(err)
	}
	if s := joinPlatforms(got); s != "linux/amd64,linux/arm64" {
		t.Fatalf("platforms = %s (attestations must be skipped)", s)
	}
}

// supervisorBytesIn reads /fleetwide-supervisor out of a baked image.
func supervisorBytesIn(t *testing.T, img gv1.Image) string {
	t.Helper()
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		if "/"+strings.TrimPrefix(h.Name, "/") == baked.SupervisorPath {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
}

// A single-platform image is served whatever platform is asked for, so the
// CLI checks what actually came back instead of trusting the request.
func TestBakeRefusesAnImageOfAnotherArchitecture(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	host := strings.TrimPrefix(reg.URL, "http://")
	img, err := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "linux", Architecture: "amd64", Config: gv1.Config{Entrypoint: []string{"/app"}}})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(host+"/acme/amd64only:1", name.Insecure)
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "fleetwide-supervisor")
	os.WriteFile(bin, []byte("ELF"), 0o755)
	err = cmdBake([]string{
		"--image", host + "/acme/amd64only:1", "--tag", host + "/acme/out:1", "--push", "--plain-http",
		"--platform", "linux/arm64", "--supervisor-binary", bin, "--app", "acme",
	})
	if err == nil || !strings.Contains(err.Error(), "no linux/arm64 variant") {
		t.Fatalf("want a refusal naming the platform, got %v", err)
	}
}

// parseSupervisorBinaries: bare path for one platform, qualified for several.
func TestParseSupervisorBinaries(t *testing.T) {
	one := []fwregistry.Platform{{OS: "linux", Arch: "arm64"}}
	two := append(one, fwregistry.Platform{OS: "linux", Arch: "amd64"})
	if m, err := parseSupervisorBinaries(multiFlag{"/tmp/a"}, one); err != nil || m["linux/arm64"] != "/tmp/a" {
		t.Fatalf("bare path, one platform: %v %v", m, err)
	}
	if _, err := parseSupervisorBinaries(multiFlag{"/tmp/a"}, two); err == nil {
		t.Fatal("bare path, two platforms must be refused")
	}
	m, err := parseSupervisorBinaries(multiFlag{"linux/arm64=/tmp/a", "linux/amd64=/tmp/b"}, two)
	if err != nil || m["linux/arm64"] != "/tmp/a" || m["linux/amd64"] != "/tmp/b" {
		t.Fatalf("qualified: %v %v", m, err)
	}
	if _, err := parseSupervisorBinaries(multiFlag{"linux/arm64=/tmp/a"}, two); err == nil {
		t.Fatal("a missing platform must be named")
	}
	if m, err := parseSupervisorBinaries(nil, two); err != nil || m != nil {
		t.Fatalf("no flag means the supervisor image: %v %v", m, err)
	}
}

// A multi-platform source is covered whole without being asked: the result
// is an index of the same platforms, each with its own supervisor.
func TestBakeCoversAMultiPlatformSourceByDefault(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	host := strings.TrimPrefix(reg.URL, "http://")
	idx := gv1.ImageIndex(empty.Index)
	idx = mutate.IndexMediaType(idx, types.OCIImageIndex)
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "linux", Architecture: arch, Config: gv1.Config{Entrypoint: []string{"/app"}}})
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: gv1.Descriptor{Platform: &gv1.Platform{OS: "linux", Architecture: arch}}})
	}
	// buildkit's attestation manifests must not be baked
	att, err := mutate.ConfigFile(empty.Image, &gv1.ConfigFile{OS: "unknown", Architecture: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: att, Descriptor: gv1.Descriptor{Platform: &gv1.Platform{OS: "unknown", Architecture: "unknown"}}})
	srcRef, _ := name.ParseReference(host+"/acme/multi:1", name.Insecure)
	if err := remote.WriteIndex(srcRef, idx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var bins []string
	for _, arch := range []string{"amd64", "arm64"} {
		p := filepath.Join(dir, arch)
		if err := os.WriteFile(p, []byte("ELF-"+arch), 0o755); err != nil {
			t.Fatal(err)
		}
		bins = append(bins, "--supervisor-binary", "linux/"+arch+"="+p)
	}
	dst := host + "/acme/multi-fleetwide:1"
	args := append([]string{"--image", host + "/acme/multi:1", "--tag", dst, "--push", "--plain-http", "--app", "acme"}, bins...)
	if err := cmdBake(args); err != nil {
		t.Fatalf("bake without --platform must cover the whole index: %v", err)
	}
	dstRef, _ := name.ParseReference(dst, name.Insecure)
	got, err := remote.Index(dstRef)
	if err != nil {
		t.Fatalf("the result must be an index: %v", err)
	}
	im, err := got.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 2 {
		t.Fatalf("want the two real platforms, not the attestation: %d", len(im.Manifests))
	}
	for _, m := range im.Manifests {
		img, err := got.Image(m.Digest)
		if err != nil {
			t.Fatal(err)
		}
		if want, got := "ELF-"+m.Platform.Architecture, supervisorBytesIn(t, img); got != want {
			t.Fatalf("%s carries %q, want %q", m.Platform.Architecture, got, want)
		}
	}
	// naming one narrows it back to a single image
	if err := cmdBake(append([]string{"--image", host + "/acme/multi:1", "--tag", host + "/acme/one:1", "--push", "--plain-http", "--platform", "linux/arm64", "--app", "acme", "--supervisor-binary", filepath.Join(dir, "arm64")}, nil...)); err != nil {
		t.Fatalf("--platform must narrow: %v", err)
	}
	oneRef, _ := name.ParseReference(host+"/acme/one:1", name.Insecure)
	if _, err := remote.Image(oneRef); err != nil {
		t.Fatalf("a narrowed bake is one image: %v", err)
	}
}
