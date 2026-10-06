// Package registry resolves image references and streams layers into the
// layer cache with digest verification.
package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/progress"
)

// Platform selects the image variant from a multi-arch index.
type Platform struct {
	OS      string
	Arch    string
	Variant string
}

// HostPlatform returns linux/<GOARCH>: images are always Linux images,
// whatever the host OS.
func HostPlatform() Platform {
	p := Platform{OS: "linux", Arch: runtime.GOARCH}
	if p.Arch == "arm" {
		p.Variant = "v7"
	}
	return p
}

// ParsePlatform parses "os/arch[/variant]".
func ParsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 2:
		return Platform{OS: parts[0], Arch: parts[1]}, nil
	case 3:
		return Platform{OS: parts[0], Arch: parts[1], Variant: parts[2]}, nil
	}
	return Platform{}, fmt.Errorf("bad platform %q, want os/arch[/variant]", s)
}

func (p Platform) String() string {
	if p.Variant != "" {
		return p.OS + "/" + p.Arch + "/" + p.Variant
	}
	return p.OS + "/" + p.Arch
}

// LayerInfo describes one layer of a resolved image.
type LayerInfo struct {
	Digest    string `json:"digest"`     // compressed blob digest (what the registry serves)
	DiffID    string `json:"diff_id"`    // uncompressed tar digest
	MediaType string `json:"media_type"` // e.g. application/vnd.oci.image.layer.v1.tar+gzip
	Size      int64  `json:"size"`
	FromCache bool   `json:"from_cache"`
	PullMS    int64  `json:"pull_ms"`
}

// Image is a resolved image ready to be unpacked.
type Image struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"` // manifest digest of the platform image
	// IndexDigest is the digest of the multi-platform index the reference
	// resolved through, empty when it named a single image. A release may be
	// pinned to either the index or one platform's manifest.
	IndexDigest string         `json:"index_digest,omitempty"`
	Platform    Platform       `json:"platform"`
	Config      *v1.ConfigFile `json:"-"`
	Layers      []LayerInfo    `json:"layers"`

	img v1.Image
}

// Options for Resolve.
type Options struct {
	// Insecure allows plain-HTTP registries (local test registries).
	Insecure bool
	// SkipVerify accepts any TLS certificate (self-signed test registries).
	SkipVerify bool
	// Auth is an explicit credential (from the Console) tried before the
	// Docker config and cloud IAM keychains; nil = those only.
	Auth *Auth
}

// Resolve fetches the manifest and config for ref on the given platform. It
// does not download layers.
func Resolve(ctx context.Context, ref string, p Platform, o Options) (*Image, error) {
	var nameOpts []name.Option
	if o.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	r, err := name.ParseReference(ref, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse reference: %w", err)
	}
	ropts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(Keychain(o.Auth)),
		remote.WithPlatform(v1.Platform{OS: p.OS, Architecture: p.Arch, Variant: p.Variant}),
	}
	if o.SkipVerify {
		ropts = append(ropts, remote.WithTransport(SkipVerifyTransport()))
	}
	desc, err := remote.Get(r, ropts...)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}
	// An index is descended by platform; its digest is what a multi-platform
	// release pins, since the child manifest digest differs per architecture.
	indexDigest := ""
	if desc.MediaType.IsIndex() {
		indexDigest = desc.Digest.String()
	}
	img, err := desc.Image()
	if err != nil {
		if indexDigest != "" {
			// The index covers other architectures; say which.
			return nil, fmt.Errorf("%s has no %s image; it has %s", ref, p, strings.Join(indexPlatforms(desc), ", "))
		}
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}
	if m, err := img.Manifest(); err == nil {
		switch ct := string(m.Config.MediaType); ct {
		case "application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json", "":
		default:
			return nil, fmt.Errorf("%s is not a container image (config media type %s): nothing to run", ref, ct)
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layers: %w", err)
	}
	if len(cfg.RootFS.DiffIDs) != len(layers) {
		return nil, fmt.Errorf("%s is not a runnable container image: %d layers but %d filesystem diff ids", ref, len(layers), len(cfg.RootFS.DiffIDs))
	}
	out := &Image{Reference: ref, Digest: digest.String(), IndexDigest: indexDigest, Platform: p, Config: cfg, img: img}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		diff, err := l.DiffID()
		if err != nil {
			return nil, err
		}
		mt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		size, err := l.Size()
		if err != nil {
			return nil, err
		}
		out.Layers = append(out.Layers, LayerInfo{Digest: d.String(), DiffID: diff.String(), MediaType: string(mt), Size: size})
	}
	return out, nil
}

// Pull downloads every layer not already in the cache. Digests are verified
// while streaming (the remote layer reader verifies on EOF and the cache
// hashes independently); a mismatch commits nothing.
func (im *Image) Pull(ctx context.Context, cache *layercache.Cache, rep progress.Reporter) error {
	return im.PullSubset(ctx, cache, nil, rep)
}

// PullSubset is Pull for the layers whose digests are in want; nil means
// every layer.
func (im *Image) PullSubset(ctx context.Context, cache *layercache.Cache, want map[string]bool, rep progress.Reporter) error {
	layers, err := im.img.Layers()
	if err != nil {
		return err
	}
	wanted := func(d string) bool { return want == nil || want[d] }
	// Only the layers that are actually fetched count towards the total, so
	// the percentage means "of what is left to download".
	var total int64
	for i := range im.Layers {
		if wanted(im.Layers[i].Digest) && !cache.Has(im.Layers[i].Digest) {
			total += im.Layers[i].Size
		}
	}
	if total > 0 && rep != nil {
		rep.Begin("image", im.Reference, total)
		defer rep.End()
	}
	for i, l := range layers {
		info := &im.Layers[i]
		if !wanted(info.Digest) {
			continue
		}
		if cache.Has(info.Digest) {
			info.FromCache = true
			continue
		}
		start := time.Now()
		rc, err := l.Compressed()
		if err != nil {
			return fmt.Errorf("layer %d %s: open: %w", i, info.Digest, err)
		}
		_, err = cache.Put(info.Digest, progress.Wrap(rc, rep))
		rc.Close()
		if err != nil {
			return fmt.Errorf("layer %d %s: %w", i, info.Digest, err)
		}
		info.PullMS = time.Since(start).Milliseconds()
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// indexPlatforms lists the platforms an index offers, for the message when
// none of them is ours.
func indexPlatforms(desc *remote.Descriptor) []string {
	idx, err := desc.ImageIndex()
	if err != nil {
		return []string{"none this supervisor could read"}
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return []string{"none this supervisor could read"}
	}
	var out []string
	for _, m := range im.Manifests {
		if m.Platform == nil || m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown" {
			continue // buildkit attestation manifests are not images
		}
		out = append(out, m.Platform.String())
	}
	if len(out) == 0 {
		return []string{"no platform images at all"}
	}
	return out
}

// Matches reports whether a pinned digest names this image: the platform
// manifest it resolved to, or the multi-platform index it came out of. An
// empty digest pins nothing and matches.
func (im *Image) Matches(digest string) bool {
	return digest == "" || digest == im.Digest || (im.IndexDigest != "" && digest == im.IndexDigest)
}

// Label returns a config label, or "".
func (im *Image) Label(key string) string {
	if im.Config == nil || im.Config.Config.Labels == nil {
		return ""
	}
	return im.Config.Config.Labels[key]
}

// DiffIDs are the image's layer diff ids in order.
func (im *Image) DiffIDs() []string {
	out := make([]string, len(im.Layers))
	for i, l := range im.Layers {
		out[i] = l.DiffID
	}
	return out
}

// MetaLayer is the layer a config label names by digest: how an embedded
// image points at the one layer holding its metadata. ok is false when the
// label is absent or names no layer of this image.
func (im *Image) MetaLayer(label string) (LayerInfo, bool) {
	d := im.Label(label)
	if d == "" {
		return LayerInfo{}, false
	}
	for _, l := range im.Layers {
		if l.Digest == d {
			return l, true
		}
	}
	return LayerInfo{}, false
}

// PinByDigest rewrites an image reference to repo@digest so the Supervisor never
// resolves a tag itself.
func PinByDigest(image, digest string, insecure bool) (string, error) {
	var nameOpts []name.Option
	if insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	r, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", err
	}
	return r.Context().Name() + "@" + digest, nil
}

// SkipVerifyTransport is the default transport without certificate checks,
// for registries that serve a self-signed certificate.
func SkipVerifyTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see above
	return t
}
