package bake

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/embedded"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/passwd"
)

// EmbedOptions is what `fleetwide embed` knows about an app.
type EmbedOptions struct {
	Options
	SyncPaths  []string // the app's declared sync paths, from the console
	AssetPaths []string // App.Assets[].unpack_to
	Start      string   // embedded | latest
	Fallback   string   // fallback | strict (start=latest)
	TimeoutS   int
}

// EmbedResult describes what was built.
type EmbedResult struct {
	Info       *embedded.Info
	MetaLayer  string   // digest of the metadata layer
	IndexBytes int      // size of the index
	Surface    []string // directories made writable
	Warnings   []string
}

// systemDirs are places a sync path may legitimately be under but that are
// worth a warning when made writable for the app's user.
var systemDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/tmp", "/opt"}

// scan is one pass over the flattened image: directory modes, the symlink
// map, and the passwd/group files the USER resolves against.
type scan struct {
	dirs     map[string]*tar.Header // path → header (mode, uid, gid)
	symlinks map[string]string      // path → target
	passwd   []byte
	group    []byte
	index    *embedded.Index
}

func scanImage(img v1.Image) (*scan, error) {
	rc := mutate.Extract(img)
	defer rc.Close()
	// Two readers over one stream is not possible; tee into the indexer.
	pr, pw := io.Pipe()
	type idxRes struct {
		x   *embedded.Index
		err error
	}
	done := make(chan idxRes, 1)
	go func() {
		x, err := embedded.Build(pr)
		io.Copy(io.Discard, pr)
		done <- idxRes{x, err}
	}()
	sc := &scan{dirs: map[string]*tar.Header{}, symlinks: map[string]string{}}
	tr := tar.NewReader(io.TeeReader(rc, pw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			pw.CloseWithError(err)
			return nil, err
		}
		p := cleanAbs(h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			hc := *h
			sc.dirs[p] = &hc
		case tar.TypeSymlink:
			sc.symlinks[p] = h.Linkname
		case tar.TypeReg, tar.TypeRegA:
			if p == "/etc/passwd" || p == "/etc/group" {
				b, err := io.ReadAll(tr)
				if err != nil {
					pw.CloseWithError(err)
					return nil, err
				}
				if p == "/etc/passwd" {
					sc.passwd = b
				} else {
					sc.group = b
				}
			}
		}
	}
	// drain the tee so the indexer sees EOF
	io.Copy(io.Discard, rc)
	pw.Close()
	r := <-done
	if r.err != nil {
		return nil, fmt.Errorf("index: %w", r.err)
	}
	sc.index = r.x
	return sc, nil
}

// resolveDir follows symlinks in the image's own map so a sync path that is
// a symlink (usr-merge style) becomes the real directory: a literal
// directory entry over a symlink would turn it into a directory.
func (sc *scan) resolveDir(p string) string {
	for i := 0; i < 16; i++ {
		t, ok := sc.symlinks[p]
		if !ok {
			return p
		}
		if !strings.HasPrefix(t, "/") {
			t = path.Join(path.Dir(p), t)
		}
		p = cleanAbs(t)
	}
	return p
}

// surface lists the directories to make writable: each sync and asset path
// and every directory of the image beneath it, resolved through symlinks.
func (sc *scan) surface(roots []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, r := range roots {
		r = sc.resolveDir(cleanAbs(r))
		if r == "/" {
			return nil, fmt.Errorf("sync path resolves to /: the whole image cannot be a sync path")
		}
		add(r)
		for d := range sc.dirs {
			if strings.HasPrefix(d, r+"/") {
				add(sc.resolveDir(d))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// permissionLayer re-owns the surface directories for the app's user:
// original mode with group rwx added, uid = the user, gid = 0. Only directory
// entries: the files inside stay root-owned and are replaced by unlink +
// create.
func permissionLayer(now time.Time, sc *scan, dirs []string, uid, gid int) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, d := range dirs {
		mode := int64(0o755)
		if h, ok := sc.dirs[d]; ok {
			mode = h.Mode & 0o7777
		}
		h := &tar.Header{Name: strings.TrimPrefix(d, "/") + "/", Typeflag: tar.TypeDir, Mode: mode | 0o070, ModTime: now, Uid: uid, Gid: gid}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytesLayer(buf.Bytes())
}

// Embed builds an embedded-runtime image: the customer image plus the supervisor,
// a permission layer for the sync paths, and a metadata layer holding
// embedded.json and the index of everything outside the sync paths. The
// image keeps its USER; the supervisor runs as that user and starts the original
// process. The metadata layer's digest goes into a config label.
func Embed(base v1.Image, o EmbedOptions) (v1.Image, *EmbedResult, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if len(o.SyncPaths) == 0 {
		return nil, nil, fmt.Errorf("embedded runtime needs at least one sync path; declare them on the app")
	}
	switch o.Start {
	case embedded.StartEmbedded, embedded.StartLatest:
	default:
		return nil, nil, fmt.Errorf("--start must be embedded or latest")
	}
	digest, err := base.Digest()
	if err != nil {
		return nil, nil, err
	}
	cf, err := base.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	sc, err := scanImage(base)
	if err != nil {
		return nil, nil, err
	}
	res := &EmbedResult{}

	// Who the supervisor and the app run as.
	uid, gid := 0, 0
	user := strings.TrimSpace(cf.Config.User)
	if user != "" && user != "root" && user != "0" {
		u, g, err := passwd.Lookup(bytes.NewReader(sc.passwd), bytes.NewReader(sc.group), user)
		if err != nil {
			return nil, nil, fmt.Errorf("USER %q: %w", user, err)
		}
		uid, gid = int(u), int(g)
	} else {
		res.Warnings = append(res.Warnings, "the image has no USER (or USER root): the supervisor and the app run as root; updates work the same way, with nothing to keep them apart")
	}

	// The surface: sync + asset paths and their directories, plus the
	// supervisor's own.
	roots := append(append([]string{}, o.SyncPaths...), o.AssetPaths...)
	surface, err := sc.surface(roots)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range surface {
		for _, sysd := range systemDirs {
			if d == sysd {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s itself becomes writable for the app's user; consider a narrower sync path", d))
			}
		}
	}
	res.Surface = surface
	own := append(append([]string{}, surface...), embedded.Dir, embedded.StagingDir, "/var/lib/fleetwide", "/var/lib")
	sort.Strings(own)
	// Directories: owned by the user, group 0, group-writable, so an
	// arbitrary uid with gid 0 can write too.
	permLayer, err := permissionLayer(o.Now, sc, own, uid, 0)
	if err != nil {
		return nil, nil, err
	}

	// Which layers of the customer image touch the sync paths.
	syncLayers, err := layersTouching(base, roots)
	if err != nil {
		return nil, nil, err
	}

	// The index: the customer image outside the excluded paths, as bytes.
	var idx bytes.Buffer
	indexSHA, err := sc.index.Write(&idx)
	if err != nil {
		return nil, nil, err
	}
	res.IndexBytes = idx.Len()

	plat := o.Platform
	if plat == "" {
		plat = cf.OS + "/" + cf.Architecture
		if cf.Variant != "" {
			plat += "/" + cf.Variant
		}
	}
	info := &embedded.Info{
		Runtime: embedded.RuntimeEmbedded, App: o.AppKey, Console: o.Console, CASHA256: o.CAPin,
		Image: o.ImageRef, Digest: digest.String(), IndexDigest: o.IndexDigest, DiffIDs: diffIDs(cf), SyncLayers: syncLayers,
		SyncPaths: cleanAll(o.SyncPaths), AssetPaths: cleanAll(o.AssetPaths),
		User: fmt.Sprintf("%d:%d", uid, gid), Start: o.Start, StartFallback: o.Fallback, StartTimeoutS: o.TimeoutS,
		Process: runtimeOf(cf), SupervisorVersion: o.SupervisorVersion, Profile: o.Variant, IndexSHA256: indexSHA, EmbeddedAt: o.Now,
	}
	if uid == 0 {
		info.User = ""
	}
	infoJSON := marshalIndent(info)
	metaLayer, err := tarLayer(o.Now, []tarEntry{
		{Name: embedded.Dir, Mode: 0o775, Dir: true},
		{Name: embedded.File, Mode: 0o644, Body: infoJSON},
		{Name: embedded.IndexFile, Mode: 0o644, Body: idx.Bytes()},
	})
	if err != nil {
		return nil, nil, err
	}
	metaDigest, err := metaLayer.Digest()
	if err != nil {
		return nil, nil, err
	}
	res.MetaLayer = metaDigest.String()

	layers := append([]v1.Layer{}, o.SupervisorLayers...)
	if len(layers) == 0 {
		if len(o.Supervisor) == 0 {
			return nil, nil, fmt.Errorf("need the supervisor binary or the supervisor image layers")
		}
		l, err := tarLayer(o.Now, []tarEntry{{Name: embedded.SupervisorPath, Mode: 0o755, Body: o.Supervisor}})
		if err != nil {
			return nil, nil, err
		}
		layers = append(layers, l)
	}
	layers = append(layers, permLayer, metaLayer)
	img, err := mutate.AppendLayers(base, layers...)
	if err != nil {
		return nil, nil, fmt.Errorf("append layers: %w", err)
	}
	acf, err := img.ConfigFile()
	if err != nil {
		return nil, nil, err
	}
	ncf := acf.DeepCopy()
	ncf.Config.Entrypoint = []string{embedded.SupervisorPath, "supervise"}
	ncf.Config.Cmd = nil
	// USER stays: the supervisor runs as the app's user. Healthcheck and stop
	// signal are the supervisor's business now.
	ncf.Config.Healthcheck = nil
	ncf.Config.StopSignal = ""
	env := []string{}
	for _, kv := range ncf.Config.Env {
		if !strings.HasPrefix(kv, "FLEETWIDE_") {
			env = append(env, kv)
		}
	}
	ncf.Config.Env = env
	if ncf.Config.Labels == nil {
		ncf.Config.Labels = map[string]string{}
	}
	for k, v := range map[string]string{
		embedded.LabelRuntime:                    embedded.RuntimeEmbedded,
		embedded.LabelMetaLayer:                  metaDigest.String(),
		embedded.LabelIndexSHA:                   indexSHA,
		embedded.LabelAppDigest:                  digest.String(),
		"io.fleetwide.supervisor.version":        o.SupervisorVersion,
		"io.fleetwide.supervisor.variant":        o.Variant,
		"io.fleetwide.app":                       o.AppKey,
		"io.fleetwide.console":                   o.Console,
		"io.fleetwide.platform":                  plat,
		"org.opencontainers.image.base.name":     o.ImageRef,
		"org.opencontainers.image.base.digest":   digest.String(),
		"org.opencontainers.image.created":       o.Now.UTC().Format(time.RFC3339),
		"org.opencontainers.image.documentation": "https://fleetwide.io/docs",
	} {
		if v != "" {
			ncf.Config.Labels[k] = v
		}
	}
	ncf.Created = v1.Time{Time: o.Now}
	for i := len(ncf.History) - len(layers); i >= 0 && i < len(ncf.History); i++ {
		ncf.History[i].Created = v1.Time{Time: o.Now}
		ncf.History[i].CreatedBy = "fleetwide embed"
		ncf.History[i].Comment = "Fleetwide supervisor"
	}
	img, err = mutate.ConfigFile(img, ncf)
	if err != nil {
		return nil, nil, err
	}
	res.Info = info
	return img, res, nil
}

// layersTouching returns the compressed digests of the layers with an entry
// at or under one of the roots (whiteouts included), in image order.
func layersTouching(img v1.Image, roots []string) ([]string, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	clean := cleanAll(roots)
	var out []string
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, err
		}
		touches := false
		tr := tar.NewReader(rc)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return nil, err
			}
			name := cleanAbs(h.Name)
			base := path.Base(name)
			if strings.HasPrefix(base, ".wh.") {
				name = path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))
			}
			if embedded.Under(name, clean) {
				touches = true
				break
			}
		}
		rc.Close()
		if touches {
			d, err := l.Digest()
			if err != nil {
				return nil, err
			}
			out = append(out, d.String())
		}
	}
	return out, nil
}

func diffIDs(cf *v1.ConfigFile) []string {
	out := make([]string, len(cf.RootFS.DiffIDs))
	for i, d := range cf.RootFS.DiffIDs {
		out[i] = d.String()
	}
	return out
}

func cleanAll(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, cleanAbs(p))
	}
	sort.Strings(out)
	return out
}

func cleanAbs(name string) string {
	return "/" + strings.TrimPrefix(path.Clean("/"+name), "/")
}

func bytesLayer(b []byte) (v1.Layer, error) {
	return tarLayerFromBytes(b)
}
