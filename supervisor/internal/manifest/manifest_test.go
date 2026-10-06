package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsWhenMissing(t *testing.T) {
	m, err := Load(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Source != "defaults" || m.Health.Kind() != "process" || m.Update.Strategy != "restart" {
		t.Fatalf("unexpected defaults: %+v", m)
	}
	if m.Health.Interval != 10*time.Second || m.Rollback.OnUnhealthyFor != 60*time.Second {
		t.Fatalf("default durations wrong: %+v", m.Health)
	}
}

func TestParseFullExample(t *testing.T) {
	// The documented example must parse.
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "examples", "fleetwide.yaml"))
	if err != nil {
		t.Skip("docs example not found:", err)
	}
	m, err := Parse(b, "example")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "fluent-bit-supervisor" || m.Health.Kind() != "http" || m.Update.Strategy != "reload" || m.Update.ReloadSignal != "SIGHUP" {
		t.Fatalf("example parsed wrong: %+v", m)
	}
	if m.Health.Grace != 15*time.Second || m.Rollback.OnUnhealthyFor != 60*time.Second {
		t.Fatalf("durations: %+v %+v", m.Health, m.Rollback)
	}
}

func TestLoadFromImageRoot(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "fleetwide"), 0o755)
	os.WriteFile(filepath.Join(root, Path), []byte("name: x\nhealth:\n  tcp: 127.0.0.1:6379\n  interval: 2s\n  timeout: 1s\n"), 0o644)
	m, err := Load(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Source != "image:"+Path || m.Health.Kind() != "tcp" || m.Health.Interval != 2*time.Second {
		t.Fatalf("%+v", m)
	}
	// override file wins
	ov := filepath.Join(t.TempDir(), "o.yaml")
	os.WriteFile(ov, []byte("name: y\nhealth:\n  exec: [\"true\"]\n"), 0o644)
	m, err = Load(root, ov)
	if err != nil || m.Name != "y" || m.Health.Kind() != "exec" {
		t.Fatalf("override: %v %+v", err, m)
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]string{
		"two checks":        "health:\n  http: http://x/\n  tcp: x:1\n",
		"bad url":           "health:\n  http: x/healthz\n",
		"bad on_unhealthy":  "health:\n  on_unhealthy: explode\n",
		"bad strategy":      "update:\n  strategy: yolo\n",
		"reload no signal":  "update:\n  strategy: reload\n",
		"timeout>=interval": "health:\n  interval: 2s\n  timeout: 2s\n",
		"bad class":         "release_class: scary\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y), name); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Parse([]byte(""), "empty"); err != nil {
		t.Errorf("empty manifest must be valid: %v", err)
	}
	if _, err := Parse([]byte("future_field: 1\nname: ok\n"), "fwd"); err != nil {
		t.Errorf("unknown fields must be ignored: %v", err)
	}
	if _, err := Parse([]byte("health: [1,2]\n"), "type"); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Errorf("type error should be reported")
	}
}
