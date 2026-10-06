//go:build !access

package tunnel

import v1 "github.com/fleetwidehq/fleetwide/api/v1"

// New returns the no-op: this image was built without the access feature, so
// there is no tunnel code to run. The console is told through the absent
// capability, and any directive that arrives anyway is ignored.
func New(cfg Config) Manager { return noop{log: cfg.Log} }

type noop struct {
	log  func(string, ...any)
	said bool
}

func (n noop) Apply(w *v1.TunnelWanted) {
	if w != nil && !n.said && n.log != nil {
		n.log("the console asked for an Access tunnel, but this supervisor image does not carry the access feature; run the fleetwide-supervisor/developer image")
	}
}
func (noop) Status() *v1.TunnelState { return nil }
func (noop) Close()                  {}
