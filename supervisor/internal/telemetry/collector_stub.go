//go:build !telemetry

package telemetry

import v1 "github.com/fleetwidehq/fleetwide/api/v1"

// New returns the no-op: this image was built without the telemetry feature,
// so there is no scraper to run. The console is told through the absent
// capability and sends no directive; one that arrives anyway is ignored.
func New(cfg Config) Collector { return noop{log: cfg.Log, said: new(bool)} }

type noop struct {
	log  func(string, ...any)
	said *bool
}

func (n noop) Apply(t *v1.Telemetry) {
	if t != nil && !*n.said && n.log != nil {
		*n.said = true
		n.log("the console asked for telemetry, but this supervisor image does not carry the telemetry feature; run the fleetwide-supervisor/telemetry or /developer image")
	}
}

func (noop) Close() {}

func (noop) Missing() []string { return nil }
