// Package bake builds a "baked" image: the customer's image plus the Supervisor
// binary and a baked.json describing the original runtime. The result runs
// the customer's application through the Supervisor from the first start.
package bake

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/baked"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
)

// Options for Build.
type Options struct {
	// ImageRef is how the customer image was referenced (recorded, pinned by digest).
	ImageRef string
	// IndexDigest is the multi-platform index ImageRef resolved through, if any.
	IndexDigest string
	Platform    string
	Version     string
	AppKey      string
	ReleaseID   string
	// Console and CAPin are the public half of a deployment key: where this
	// image belongs and which console CA to trust. The secret is never baked.
	Console           string
	CAPin             string
	Variant           string // supervisor image the layers came from
	SupervisorVersion string
	// Supervisor is the Supervisor binary content (from --supervisor-binary) — or nil when SupervisorLayers is given.
	Supervisor []byte
	// SupervisorLayers are the layers of the published supervisor image (from --supervisor-image).
	SupervisorLayers []v1.Layer
	Now              time.Time
}

// Build layers the Supervisor onto base and rewrites the config so the Supervisor is
// PID 1. It returns the new image and the baked.json it embedded.
func Build(base v1.Image, o Options) (v1.Image, *baked.Info, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	digest, err := base.Digest()
	if err != nil {
		return nil, nil, err
	}
	cf, err := base.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	paths, err := imagePaths(base)
	if err != nil {
		return nil, nil, fmt.Errorf("list image paths: %w", err)
	}
	plat := o.Platform
	if plat == "" {
		plat = cf.OS + "/" + cf.Architecture
		if cf.Variant != "" {
			plat += "/" + cf.Variant
		}
	}
	info := &baked.Info{
		Image: o.ImageRef, Digest: digest.String(), IndexDigest: o.IndexDigest, Platform: plat, Version: o.Version,
		AppKey: o.AppKey, ReleaseID: o.ReleaseID, Console: o.Console, CASHA256: o.CAPin,
		Runtime: imagecfg.FromConfigFile(cf), SupervisorVersion: o.SupervisorVersion, SupervisorVariant: o.Variant, BakedAt: o.Now,
	}
	infoJSON, _ := json.MarshalIndent(info, "", "  ")

	layers := append([]v1.Layer{}, o.SupervisorLayers...)
	if len(layers) == 0 {
		if len(o.Supervisor) == 0 {
			return nil, nil, fmt.Errorf("need the supervisor binary or the supervisor image layers")
		}
		l, err := tarLayer(o.Now, []tarEntry{{Name: baked.SupervisorPath, Mode: 0o755, Body: o.Supervisor}})
		if err != nil {
			return nil, nil, err
		}
		layers = append(layers, l)
	}
	bakedLayer, err := tarLayer(o.Now, []tarEntry{
		{Name: baked.Dir, Mode: 0o755, Dir: true},
		{Name: baked.File, Mode: 0o644, Body: infoJSON},
		{Name: baked.PathsFile, Mode: 0o644, Body: []byte(strings.Join(paths, "\n") + "\n")},
	})
	if err != nil {
		return nil, nil, err
	}
	layers = append(layers, bakedLayer)

	img, err := mutate.AppendLayers(base, layers...)
	if err != nil {
		return nil, nil, fmt.Errorf("append layers: %w", err)
	}
	// Take the config from the appended image (its rootfs diff IDs and
	// history now include the new layers) and rewrite only the runtime part.
	acf, err := img.ConfigFile()
	if err != nil {
		return nil, nil, err
	}
	ncf := acf.DeepCopy()
	ncf.Config.Entrypoint = []string{baked.SupervisorPath, "supervise"}
	ncf.Config.Cmd = nil
	ncf.Config.User = "" // the Supervisor must be root to extract updates over /; it drops to the original USER for the app
	ncf.Config.Healthcheck = nil
	ncf.Config.StopSignal = "" // the Supervisor forwards its own stop signal per the manifest
	env := []string{}
	for _, kv := range ncf.Config.Env {
		if !strings.HasPrefix(kv, "FLEETWIDE_") {
			env = append(env, kv)
		}
	}
	env = append(env, "FLEETWIDE_BAKED=1")
	ncf.Config.Env = env
	if ncf.Config.Labels == nil {
		ncf.Config.Labels = map[string]string{}
	}
	// Provenance labels.
	for k, v := range map[string]string{
		"io.fleetwide.baked":                     "true",
		"io.fleetwide.baked.digest":              digest.String(),
		"io.fleetwide.baked.index":               o.IndexDigest,
		"io.fleetwide.supervisor.version":        o.SupervisorVersion,
		"io.fleetwide.supervisor.variant":        o.Variant,
		"io.fleetwide.app":                       o.AppKey,
		"io.fleetwide.release":                   o.ReleaseID,
		"io.fleetwide.version":                   o.Version,
		"io.fleetwide.console":                   o.Console,
		"io.fleetwide.platform":                  plat,
		"org.opencontainers.image.base.name":     o.ImageRef,
		"org.opencontainers.image.base.digest":   digest.String(),
		"org.opencontainers.image.created":       o.Now.UTC().Format(time.RFC3339),
		"org.opencontainers.image.revision":      o.Version,
		"org.opencontainers.image.documentation": "https://fleetwide.io/docs",
	} {
		if v != "" {
			ncf.Config.Labels[k] = v
		}
	}
	ncf.Created = v1.Time{Time: o.Now}
	for i := len(ncf.History) - len(layers); i >= 0 && i < len(ncf.History); i++ {
		ncf.History[i].Created = v1.Time{Time: o.Now}
		ncf.History[i].CreatedBy = "fleetwide bake"
		ncf.History[i].Comment = "Fleetwide supervisor"
	}
	img, err = mutate.ConfigFile(img, ncf)
	if err != nil {
		return nil, nil, err
	}
	return img, info, nil
}

type tarEntry struct {
	Name string
	Mode int64
	Body []byte
	Dir  bool
}

func tarLayer(now time.Time, entries []tarEntry) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: strings.TrimPrefix(e.Name, "/"), Mode: e.Mode, ModTime: now, Uid: 0, Gid: 0}
		if e.Dir {
			h.Typeflag = tar.TypeDir
			h.Name += "/"
		} else {
			h.Typeflag = tar.TypeReg
			h.Size = int64(len(e.Body))
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if !e.Dir {
			if _, err := tw.Write(e.Body); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return tarLayerFromBytes(buf.Bytes())
}

func tarLayerFromBytes(b []byte) (v1.Layer, error) {
	return tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
}

func runtimeOf(cf *v1.ConfigFile) imagecfg.Runtime { return imagecfg.FromConfigFile(cf) }

func marshalIndent(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// imagePaths flattens the image and lists every absolute path it contains
// (whiteouts applied), sorted, for residue cleanup on the first update.
func imagePaths(img v1.Image) ([]string, error) {
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	seen := map[string]struct{}{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := "/" + strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if name == "/" {
			continue
		}
		seen[name] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
