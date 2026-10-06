// Package health runs the supervisor-side health check for the application:
// HTTP, TCP, exec, or "process alive". It tracks consecutive failures, a
// grace period after (re)start, and how long the app has been continuously
// unhealthy, and notifies a listener on transitions.
package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// Checker performs one probe.
type Checker interface {
	Check(ctx context.Context) error
	String() string
}

// HTTPCheck is healthy on any 2xx/3xx response.
type HTTPCheck struct{ URL string }

func (c HTTPCheck) String() string { return "http " + c.URL }
func (c HTTPCheck) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "fleetwide-supervisor/health")
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("status %d", resp.StatusCode)
}

// TCPCheck is healthy when a connection can be established.
type TCPCheck struct{ Addr string }

func (c TCPCheck) String() string { return "tcp " + c.Addr }
func (c TCPCheck) Check(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ExecCheck is healthy when the command exits 0. It runs in the supervisor's own
// filesystem, which after extract-over-root is the application image.
type ExecCheck struct{ Argv []string }

func (c ExecCheck) String() string { return fmt.Sprintf("exec %v", c.Argv) }
func (c ExecCheck) Check(ctx context.Context) error {
	if len(c.Argv) == 0 {
		return errors.New("empty exec check")
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 200 {
			out = out[:200]
		}
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// ProcessCheck is healthy while the supplied function reports the process alive.
type ProcessCheck struct{ Alive func() bool }

func (c ProcessCheck) String() string { return "process alive" }
func (c ProcessCheck) Check(context.Context) error {
	if c.Alive() {
		return nil
	}
	return errors.New("process not running")
}

// Config controls the loop.
type Config struct {
	Interval         time.Duration
	Timeout          time.Duration
	Grace            time.Duration // after Start/Reset, failures are recorded but do not count
	FailureThreshold int           // consecutive counted failures → Unhealthy
}

// State is a snapshot.
type State struct {
	Check               string        `json:"check"`
	Healthy             bool          `json:"healthy"`
	InGrace             bool          `json:"in_grace"`
	Checks              int           `json:"checks"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	LastOK              time.Time     `json:"last_ok,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	LastCheck           time.Time     `json:"last_check,omitempty"`
	Since               time.Time     `json:"since"`         // when Healthy last changed
	UnhealthyFor        time.Duration `json:"unhealthy_for"` // 0 when healthy
}

// Monitor runs the check loop.
type Monitor struct {
	cfg     Config
	checker Checker

	mu       sync.Mutex
	st       State
	started  time.Time
	onChange func(State)
	wake     chan struct{}
}

// New creates a monitor. onChange is called (outside the lock) whenever
// Healthy flips.
func New(cfg Config, c Checker, onChange func(State)) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout <= 0 || cfg.Timeout >= cfg.Interval {
		cfg.Timeout = cfg.Interval / 2
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if onChange == nil {
		onChange = func(State) {}
	}
	m := &Monitor{cfg: cfg, checker: c, onChange: onChange, wake: make(chan struct{}, 1)}
	m.Reset()
	return m
}

// Reset restarts the grace period (call after the app (re)starts). The app is
// considered healthy-pending until the first counted failure sequence.
func (m *Monitor) Reset() {
	m.mu.Lock()
	m.started = time.Now()
	m.st = State{Check: m.checker.String(), Healthy: true, InGrace: m.cfg.Grace > 0, Since: m.started}
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// State returns a snapshot with UnhealthyFor computed.
func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.st
	if !s.Healthy {
		s.UnhealthyFor = time.Since(s.Since)
	}
	return s
}

// CheckNow performs one probe immediately and records it.
func (m *Monitor) CheckNow(ctx context.Context) State {
	cctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	err := m.checker.Check(cctx)
	cancel()
	return m.record(err)
}

func (m *Monitor) record(err error) State {
	m.mu.Lock()
	now := time.Now()
	m.st.Checks++
	m.st.LastCheck = now
	m.st.InGrace = now.Sub(m.started) < m.cfg.Grace
	prev := m.st.Healthy
	if err == nil {
		m.st.ConsecutiveFailures = 0
		m.st.LastOK = now
		m.st.LastError = ""
		if !m.st.Healthy {
			m.st.Healthy = true
			m.st.Since = now
		}
	} else {
		m.st.LastError = err.Error()
		if !m.st.InGrace {
			m.st.ConsecutiveFailures++
			if m.st.Healthy && m.st.ConsecutiveFailures >= m.cfg.FailureThreshold {
				m.st.Healthy = false
				m.st.Since = now
			}
		}
	}
	s := m.st
	if !s.Healthy {
		s.UnhealthyFor = now.Sub(s.Since)
	}
	changed := prev != s.Healthy
	m.mu.Unlock()
	if changed {
		m.onChange(s)
	}
	return s
}

// Run loops until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	m.CheckNow(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			// after Reset: probe soon rather than waiting a full interval
			select {
			case <-ctx.Done():
				return
			case <-time.After(min(m.cfg.Interval, time.Second)):
			}
			m.CheckNow(ctx)
		case <-t.C:
			m.CheckNow(ctx)
		}
	}
}
