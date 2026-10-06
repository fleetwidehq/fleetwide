// Package tunnel keeps an outbound connection from an access-capable supervisor to
// the Fleetwide proxy so a deployment's container ports can be reached at
// https://<subdomain>.<access domain>. An image built without the access
// feature compiles only the stub in this package: no tunnel code, no
// multiplexer, nothing to reach.
package tunnel

import (
	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/consoleclient"
)

// Config for a Manager. Identity is the supervisor's enrollment (client cert,
// key, console CA); the proxy serves a certificate from the same CA.
type Config struct {
	Identity          func() *consoleclient.Identity // current enrollment (changes after a re-enroll)
	InsecureTLS       bool
	SupervisorVersion string
	Log               func(string, ...any)
}

// Manager reacts to the console's TunnelWanted (nil = close) and reports state.
type Manager interface {
	Apply(w *v1.TunnelWanted)
	Status() *v1.TunnelState
	Close()
}
