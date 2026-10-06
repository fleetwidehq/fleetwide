// Package manifest reads fleetwide.yaml: the vendor-declared metadata an OCI
// image config cannot express (requirements, health, update strategy,
// readiness endpoint, telemetry schema). Every field is optional; an image
// without a manifest gets Defaults(), which is "process alive is health,
// restart is the strategy".
package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Path is where the Supervisor looks inside the unpacked image.
const Path = "/fleetwide/fleetwide.yaml"

// Manifest is the parsed fleetwide.yaml.
type Manifest struct {
	Name       string   `yaml:"name" json:"name"`
	Version    string   `yaml:"version" json:"version"`
	Supervisor string   `yaml:"supervisor" json:"supervisor,omitempty"` // min supervisor version constraint, e.g. ">=1.2" (recorded, not enforced)
	Platforms  []string `yaml:"platforms" json:"platforms,omitempty"`

	Requires Requires `yaml:"requires" json:"requires"`

	Entrypoint []string `yaml:"entrypoint" json:"entrypoint,omitempty"`
	Cmd        []string `yaml:"cmd" json:"cmd,omitempty"`
	WorkDir    string   `yaml:"workdir" json:"workdir,omitempty"`
	User       string   `yaml:"user" json:"user,omitempty"`

	Health   Health   `yaml:"health" json:"health"`
	Update   Update   `yaml:"update" json:"update"`
	Rollback Rollback `yaml:"rollback" json:"rollback"`
	Ready    Ready    `yaml:"ready" json:"ready"`

	// Parsed and reported, not acted on.
	Telemetry    map[string]any `yaml:"telemetry" json:"telemetry,omitempty"`
	ReleaseClass string         `yaml:"release_class" json:"release_class,omitempty"`

	// Source records where the manifest came from: "image", "file:<path>" or "defaults".
	Source string `yaml:"-" json:"source"`
}

// Requires gates a release before anything is downloaded.
type Requires struct {
	Kernel       string   `yaml:"kernel" json:"kernel,omitempty"` // ">=5.10"
	Capabilities []string `yaml:"capabilities" json:"capabilities,omitempty"`
}

// Health defines the Supervisor-side health check (the vendor's view, feeding
// rollback and rollout decisions; the customer's orchestrator probes are
// separate and untouched).
type Health struct {
	HTTP string   `yaml:"http" json:"http,omitempty"` // GET, 2xx/3xx healthy
	TCP  string   `yaml:"tcp" json:"tcp,omitempty"`   // host:port connect
	Exec []string `yaml:"exec" json:"exec,omitempty"` // exit 0 healthy

	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	Grace            time.Duration `yaml:"grace" json:"grace"`                         // failures ignored after (re)start
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"` // consecutive failures → unhealthy

	OnUnhealthy    string        `yaml:"on_unhealthy" json:"on_unhealthy"`       // restart | report (ignore: older name); anything but restart means report
	MaxRestarts    int           `yaml:"max_restarts" json:"max_restarts"`       // health-triggered restarts before giving up (exit 1)
	RestartBackoff time.Duration `yaml:"restart_backoff" json:"restart_backoff"` // wait before restarting
	StopTimeout    time.Duration `yaml:"stop_timeout" json:"stop_timeout"`       // SIGTERM → SIGKILL
}

// Kind returns the check type in use.
func (h Health) Kind() string {
	switch {
	case h.HTTP != "":
		return "http"
	case h.TCP != "":
		return "tcp"
	case len(h.Exec) > 0:
		return "exec"
	}
	return "process"
}

// Update is the declared update strategy; parsed and validated.
type Update struct {
	Strategy     string   `yaml:"strategy" json:"strategy"` // restart | reload | bluegreen
	ReloadSignal string   `yaml:"reload_signal" json:"reload_signal,omitempty"`
	ConfigPaths  []string `yaml:"config_paths" json:"config_paths,omitempty"`
}

// Rollback controls what happens when a release stays unhealthy.
type Rollback struct {
	OnUnhealthyFor time.Duration `yaml:"on_unhealthy_for" json:"on_unhealthy_for"` // continuous unhealthy → act
	KeepVersions   int           `yaml:"keep_versions" json:"keep_versions"`
}

// Ready configures the optional Supervisor HTTP endpoint that mirrors the app's
// health check so customers may point orchestrator probes at it and the
// Supervisor can flip it to unready while draining.
type Ready struct {
	Listen string `yaml:"listen" json:"listen,omitempty"` // e.g. ":9100"; empty = disabled unless --ready-listen
}

// Defaults is the manifest used when the image has none.
func Defaults() *Manifest {
	m := &Manifest{Source: "defaults"}
	m.fill()
	return m
}

// fill applies defaults to zero fields.
func (m *Manifest) fill() {
	h := &m.Health
	if h.Interval == 0 {
		h.Interval = 10 * time.Second
	}
	if h.Timeout == 0 {
		h.Timeout = 3 * time.Second
	}
	if h.Grace == 0 {
		h.Grace = 15 * time.Second
	}
	if h.FailureThreshold == 0 {
		h.FailureThreshold = 3
	}
	if h.OnUnhealthy == "" {
		h.OnUnhealthy = "restart"
	}
	if h.MaxRestarts == 0 {
		h.MaxRestarts = 5
	}
	if h.RestartBackoff == 0 {
		h.RestartBackoff = 5 * time.Second
	}
	if h.StopTimeout == 0 {
		h.StopTimeout = 30 * time.Second
	}
	if m.Update.Strategy == "" {
		m.Update.Strategy = "restart"
	}
	if m.Rollback.OnUnhealthyFor == 0 {
		m.Rollback.OnUnhealthyFor = 60 * time.Second
	}
	if m.Rollback.KeepVersions == 0 {
		m.Rollback.KeepVersions = 2
	}
}

// Parse decodes YAML, applies defaults and validates.
func Parse(data []byte, source string) (*Manifest, error) {
	m := &Manifest{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(false) // forward compatibility: newer fields are ignored, not fatal
	if err := dec.Decode(m); err != nil && !errors.Is(err, os.ErrNotExist) {
		if err.Error() != "EOF" { // empty file = all defaults
			return nil, fmt.Errorf("manifest %s: %w", source, err)
		}
	}
	m.Source = source
	m.fill()
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", source, err)
	}
	return m, nil
}

// Validate rejects contradictory or unknown values.
func (m *Manifest) Validate() error {
	n := 0
	if m.Health.HTTP != "" {
		n++
		if !strings.HasPrefix(m.Health.HTTP, "http://") && !strings.HasPrefix(m.Health.HTTP, "https://") {
			return fmt.Errorf("health.http must be a URL, got %q", m.Health.HTTP)
		}
	}
	if m.Health.TCP != "" {
		n++
	}
	if len(m.Health.Exec) > 0 {
		n++
	}
	if n > 1 {
		return errors.New("health: only one of http, tcp, exec may be set")
	}
	switch m.Health.OnUnhealthy {
	case "restart", "ignore":
	default:
		return fmt.Errorf("health.on_unhealthy must be restart or ignore, got %q", m.Health.OnUnhealthy)
	}
	switch m.Update.Strategy {
	case "restart", "reload", "bluegreen":
	default:
		return fmt.Errorf("update.strategy must be restart, reload or bluegreen, got %q", m.Update.Strategy)
	}
	if m.Update.Strategy == "reload" && m.Update.ReloadSignal == "" {
		return errors.New("update.strategy reload needs update.reload_signal")
	}
	if m.Health.Interval < time.Second {
		return errors.New("health.interval must be >= 1s")
	}
	if m.Health.Timeout >= m.Health.Interval {
		return errors.New("health.timeout must be shorter than health.interval")
	}
	if m.ReleaseClass != "" && m.ReleaseClass != "behavior" && m.ReleaseClass != "permission-widening" {
		return fmt.Errorf("release_class must be behavior or permission-widening, got %q", m.ReleaseClass)
	}
	return nil
}

// Load resolves the manifest for an unpacked image root: an explicit override
// file wins, then Path inside the root, then Defaults().
func Load(root, override string) (*Manifest, error) {
	if override != "" {
		b, err := os.ReadFile(override)
		if err != nil {
			return nil, err
		}
		return Parse(b, "file:"+override)
	}
	p := filepath.Join(root, Path)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b, "image:"+Path)
}
