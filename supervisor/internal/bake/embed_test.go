package bake

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/embedded"
)

type fe struct {
	name, body, link string
	typ              byte
	mode             int64
}

func layerOf(t *testing.T, ents ...fe) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typ, Linkname: e.link}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	l, err := tarLayerFromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A two-layer customer image: a base with passwd, /usr and a usr-merge style
// /bin symlink, and an app layer under /app and /etc/nginx/conf.d.
func customerImage(t *testing.T, user string) v1.Image {
	t.Helper()
	base := layerOf(t,
		fe{name: "etc/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "etc/passwd", body: "root:x:0:0::/root:/bin/sh\nnginx:x:101:101::/nonexistent:/bin/false\n"},
		fe{name: "etc/group", body: "root:x:0:\nnginx:x:101:\n"},
		fe{name: "usr/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "usr/lib/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "usr/lib/libssl.so", body: "ssl"},
		fe{name: "usr/share/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "usr/share/www/", typ: tar.TypeDir, mode: 0o1777},
		fe{name: "www", typ: tar.TypeSymlink, link: "usr/share/www"},
		fe{name: "etc/nginx/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "etc/nginx/conf.d/", typ: tar.TypeDir, mode: 0o755},
	)
	app := layerOf(t,
		fe{name: "app/", typ: tar.TypeDir, mode: 0o750},
		fe{name: "app/lib/", typ: tar.TypeDir, mode: 0o755},
		fe{name: "app/main.js", body: "v1"},
		fe{name: "etc/nginx/conf.d/default.conf", body: "conf"},
		fe{name: "usr/share/www/index.html", body: "hi"},
	)
	img, err := mutate.AppendLayers(empty.Image, base, app)
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := img.ConfigFile()
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "arm64"
	cf.Config.User = user
	cf.Config.Entrypoint = []string{"/docker-entrypoint.sh"}
	cf.Config.Cmd = []string{"nginx", "-g", "daemon off;"}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func entriesOf(t *testing.T, l v1.Layer) map[string]*tar.Header {
	t.Helper()
	rc, err := l.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		hc := *h
		out["/"+strings.TrimSuffix(h.Name, "/")] = &hc
	}
}

func TestEmbedBuildsTheEmbeddedImage(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	img, res, err := Embed(customerImage(t, "nginx"), EmbedOptions{
		Options:    Options{ImageRef: "ghcr.io/acme/web@sha256:x", AppKey: "web", Console: "https://c", Supervisor: []byte("SUPERVISOR"), SupervisorVersion: "t", Variant: "slim", Now: now},
		SyncPaths:  []string{"/app", "/www", "/etc/nginx/conf.d"},
		AssetPaths: []string{"/opt/models"},
		Start:      embedded.StartLatest, Fallback: "strict", TimeoutS: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := img.ConfigFile()
	// the supervisor is the entrypoint, USER stays, the metadata layer is labelled
	if strings.Join(cf.Config.Entrypoint, " ") != "/fleetwide-supervisor supervise" || cf.Config.Cmd != nil || cf.Config.User != "nginx" {
		t.Fatalf("config: %v %v %q", cf.Config.Entrypoint, cf.Config.Cmd, cf.Config.User)
	}
	if cf.Config.Labels[embedded.LabelRuntime] != "embedded" || cf.Config.Labels[embedded.LabelMetaLayer] != res.MetaLayer || cf.Config.Labels[embedded.LabelIndexSHA] != res.Info.IndexSHA256 {
		t.Fatalf("labels: %v", cf.Config.Labels)
	}
	layers, _ := img.Layers()
	if len(layers) != 5 { // base, app, supervisor, permissions, metadata
		t.Fatalf("layers: %d", len(layers))
	}
	d, _ := layers[4].Digest()
	if d.String() != res.MetaLayer {
		t.Fatal("the metadata layer must be last and be the one the label names")
	}
	// the permission layer: sync/asset dirs and the supervisor's own, uid 101 gid 0, g+rwx, sticky kept, symlink resolved
	perm := entriesOf(t, layers[3])
	for _, want := range []string{"/app", "/app/lib", "/etc/nginx/conf.d", "/usr/share/www", "/opt/models", "/fleetwide", "/fleetwide/staging", "/var/lib/fleetwide"} {
		h, ok := perm[want]
		if !ok || h.Typeflag != tar.TypeDir {
			t.Fatalf("permission layer lacks dir %s: %v", want, dirKeys(perm))
		}
		if h.Uid != 101 || h.Gid != 0 || h.Mode&0o070 != 0o070 {
			t.Fatalf("%s: uid=%d gid=%d mode=%o", want, h.Uid, h.Gid, h.Mode)
		}
	}
	if _, literal := perm["/www"]; literal {
		t.Fatal("a symlinked sync path must be resolved, never emitted as a directory")
	}
	if perm["/usr/share/www"].Mode&0o1000 == 0 || perm["/app"].Mode&0o7777 != 0o770 {
		t.Fatalf("modes: www=%o app=%o", perm["/usr/share/www"].Mode, perm["/app"].Mode)
	}
	if _, has := perm["/usr/lib"]; has {
		t.Fatal("directories outside the surface must not be touched")
	}
	// embedded.json
	info := res.Info
	if info.User != "101:101" || info.Start != "latest" || info.StartFallback != "strict" || info.StartTimeoutS != 30 || len(info.DiffIDs) != 2 {
		t.Fatalf("info: %+v", info)
	}
	if strings.Join(info.SyncPaths, ",") != "/app,/etc/nginx/conf.d,/www" || strings.Join(info.AssetPaths, ",") != "/opt/models" {
		t.Fatalf("paths: %v %v", info.SyncPaths, info.AssetPaths)
	}
	if info.Process.Argv(nil)[0] != "/docker-entrypoint.sh" {
		t.Fatalf("original process lost: %v", info.Process)
	}
	// both customer layers touch the sync paths here: the base creates the
	// directories, the app fills them.
	bd, _ := layers[0].Digest()
	ad, _ := layers[1].Digest()
	if strings.Join(info.SyncLayers, ",") != bd.String()+","+ad.String() {
		t.Fatalf("sync layers: %v", info.SyncLayers)
	}
	// the metadata layer carries embedded.json and an index whose sha matches
	rc, _ := layers[4].Uncompressed()
	mi, idx, sha, err := embedded.ReadMeta(rc)
	rc.Close()
	if err != nil || mi.Digest != info.Digest || sha != info.IndexSHA256 {
		t.Fatalf("meta: %v %+v %s", err, mi, sha)
	}
	// the index is the whole customer image outside the excluded paths (Diff
	// ignores the sync paths); it must not contain the supervisor's paths.
	for _, e := range idx.Entries {
		if strings.HasPrefix(e.Path, "/fleetwide") {
			t.Fatalf("index must not contain the supervisor's paths: %s", e.Path)
		}
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("no warnings expected: %v", res.Warnings)
	}
}

// The same customer image embedded twice, with different supervisors, indexes
// identically — otherwise every release would look like a base change.
func TestEmbedIndexIsIndependentOfTheSupervisor(t *testing.T) {
	o := EmbedOptions{Options: Options{Supervisor: []byte("SUPERVISOR one"), SupervisorVersion: "1", Now: time.Unix(1, 0)}, SyncPaths: []string{"/app"}, Start: embedded.StartEmbedded}
	_, a, err := Embed(customerImage(t, "nginx"), o)
	if err != nil {
		t.Fatal(err)
	}
	o.Supervisor, o.SupervisorVersion, o.Now = []byte("SUPERVISOR two, longer"), "2", time.Unix(2, 0)
	_, b, err := Embed(customerImage(t, "nginx"), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Info.IndexSHA256 != b.Info.IndexSHA256 {
		t.Fatal("index must depend on the customer image only")
	}
}

func TestEmbedRefusals(t *testing.T) {
	if _, _, err := Embed(customerImage(t, "nginx"), EmbedOptions{Options: Options{Supervisor: []byte("a")}, Start: "embedded"}); err == nil || !strings.Contains(err.Error(), "sync path") {
		t.Fatalf("no sync paths: %v", err)
	}
	if _, _, err := Embed(customerImage(t, "nginx"), EmbedOptions{Options: Options{Supervisor: []byte("a")}, SyncPaths: []string{"/"}, Start: "embedded"}); err == nil || !strings.Contains(err.Error(), "/") {
		t.Fatalf("root sync path: %v", err)
	}
	if _, _, err := Embed(customerImage(t, "nobody"), EmbedOptions{Options: Options{Supervisor: []byte("a")}, SyncPaths: []string{"/app"}, Start: "embedded"}); err == nil || !strings.Contains(err.Error(), "USER") {
		t.Fatalf("unknown user: %v", err)
	}
	_, res, err := Embed(customerImage(t, ""), EmbedOptions{Options: Options{Supervisor: []byte("a")}, SyncPaths: []string{"/app", "/etc"}, Start: "embedded"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Info.User != "" || len(res.Warnings) < 2 {
		t.Fatalf("root image: user=%q warnings=%v", res.Info.User, res.Warnings)
	}
}

func dirKeys(m map[string]*tar.Header) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
