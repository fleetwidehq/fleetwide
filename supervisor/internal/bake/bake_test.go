package bake

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/baked"
)

func TestBuild(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	appLayer, err := tarLayer(now, []tarEntry{{Name: "/app", Mode: 0o755, Dir: true}, {Name: "/app/server", Mode: 0o755, Body: []byte("#!/bin/sh\necho hi\n")}, {Name: "/etc/motd", Mode: 0o644, Body: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := mutate.AppendLayers(empty.Image, appLayer)
	base, _ = mutate.ConfigFile(base, &v1.ConfigFile{OS: "linux", Architecture: "arm64", Config: v1.Config{
		Entrypoint: []string{"/app/server"}, Cmd: []string{"--port", "8080"}, User: "1000:1000", WorkingDir: "/app",
		Env: []string{"PATH=/usr/bin", "FLEETWIDE_KEY=stale"}, StopSignal: "SIGQUIT"}})
	baseDigest, _ := base.Digest()

	img, info, err := Build(base, Options{ImageRef: "acme/app:1.2", Version: "1.2", AppKey: "app", ReleaseID: "rel_1",
		Console: "https://console.acme.test", CAPin: "abcd", Variant: "developer",
		Supervisor: []byte("ELF-supervisor"), SupervisorVersion: "t", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest != baseDigest.String() || info.Runtime.User != "1000:1000" || info.Runtime.Entrypoint[0] != "/app/server" || info.Runtime.Cmd[1] != "8080" {
		t.Fatalf("baked info wrong: %+v", info)
	}
	cf, _ := img.ConfigFile()
	if strings.Join(cf.Config.Entrypoint, " ") != baked.SupervisorPath+" supervise" || cf.Config.Cmd != nil || cf.Config.User != "" || cf.Config.StopSignal != "" {
		t.Fatalf("config must make the supervisor PID 1 as root: %+v", cf.Config)
	}
	// The deployment key is never baked: holding the image must not be the
	// same as being able to enroll. Any FLEETWIDE_* the base image carried
	// goes too.
	env := strings.Join(cf.Config.Env, ",")
	if !strings.Contains(env, "FLEETWIDE_BAKED=1") || strings.Contains(env, "FLEETWIDE_KEY") || strings.Contains(env, "stale") || !strings.Contains(env, "PATH=/usr/bin") {
		t.Fatalf("env: %v", cf.Config.Env)
	}
	// The public half is recorded, so the image can say where it belongs and
	// refuse a key for another app.
	if info.Console != "https://console.acme.test" || info.CASHA256 != "abcd" || info.ReleaseID != "rel_1" || info.SupervisorVariant != "developer" {
		t.Fatalf("baked info should carry the public half: %+v", info)
	}
	// Provenance, answerable with docker inspect.
	for k, want := range map[string]string{
		"io.fleetwide.baked.digest":            baseDigest.String(),
		"io.fleetwide.app":                     "app",
		"io.fleetwide.release":                 "rel_1",
		"io.fleetwide.version":                 "1.2",
		"io.fleetwide.console":                 "https://console.acme.test",
		"io.fleetwide.supervisor.variant":      "developer",
		"io.fleetwide.supervisor.version":      "t",
		"org.opencontainers.image.base.name":   "acme/app:1.2",
		"org.opencontainers.image.base.digest": baseDigest.String(),
	} {
		if cf.Config.Labels[k] != want {
			t.Fatalf("label %s = %q, want %q (all: %v)", k, cf.Config.Labels[k], want, cf.Config.Labels)
		}
	}
	if cf.Config.Labels["org.opencontainers.image.created"] == "" {
		t.Fatalf("created label missing: %v", cf.Config.Labels)
	}
	layers, _ := img.Layers()
	if len(layers) != 3 {
		t.Fatalf("expected app + supervisor + baked layers, got %d", len(layers))
	}
	// flattened filesystem has the app, the supervisor and the baked files
	files := map[string]string{}
	tr := tar.NewReader(mutate.Extract(img))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if h.Typeflag == tar.TypeReg {
			var b bytes.Buffer
			io.Copy(&b, tr)
			files["/"+strings.TrimPrefix(h.Name, "/")] = b.String()
		}
	}
	if files[baked.SupervisorPath] != "ELF-supervisor" || files["/app/server"] == "" {
		t.Fatalf("missing supervisor or app: %v", keys(files))
	}
	var back baked.Info
	if err := json.Unmarshal([]byte(files[baked.File]), &back); err != nil || back.Digest != baseDigest.String() {
		t.Fatalf("baked.json: %v %+v", err, back)
	}
	paths := strings.Split(strings.TrimSpace(files[baked.PathsFile]), "\n")
	if strings.Join(paths, " ") != "/app /app/server /etc/motd" {
		t.Fatalf("paths must list the customer image only: %v", paths)
	}
	// the supervisor image path variant
	img2, _, err := Build(base, Options{ImageRef: "acme/app:1.2", SupervisorLayers: []v1.Layer{appLayer}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := img2.Layers(); len(l) != 3 {
		t.Fatalf("supervisor-image variant layers: %d", len(l))
	}
}

func keys(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
