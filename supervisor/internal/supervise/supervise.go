// Package supervise runs one application slot under health supervision:
// start it, run the manifest's health check, serve the optional readiness
// endpoint, restart in place when the app stays unhealthy, swap releases
// (Deploy) without the run loop mistaking the swap for an app exit, and exit
// with the app's code when it exits on its own.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/health"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/logbuf"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/metrics"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/ready"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/runner"
)

// Options for a Supervisor.
type Options struct {
	// Initial release; may be nil (managed mode waits for the Console).
	Runtime  *imagecfg.Runtime
	Manifest *manifest.Manifest
	CmdOver  []string

	ReadyListen string // "" = no endpoint
	Info        map[string]any
	Log         func(format string, args ...any)
	// Logs, when set, receives a copy of the application's stdout/stderr.
	Logs *logbuf.Buffer
	// OnUnhealthyFor, when set, is consulted before an in-place restart. Return
	// true to say "handled" (e.g. the fleet controller rolled back instead).
	OnUnhealthyFor func(st health.State) bool
	// OnRestart is called after every health-triggered restart.
	OnRestart func(reason string)
}

// Snapshot is the supervisor's state for reporting.
type Snapshot struct {
	Running       bool
	Transitioning bool
	Health        health.State
	Ready         bool
	Restarts      int
	PID           int
	DeployedAt    time.Time
	Confirmed     bool // healthy long enough after the last Deploy to trust the release
	LastExit      *Exit
}

// Exit describes how the application last stopped.
type Exit struct {
	At     time.Time
	Code   int
	Signal string // SIGKILL, SIGTERM, … when killed by a signal
	OOM    bool   // the cgroup's oom_kill counter moved: the kernel killed it for memory
	Reason string // app_exit | oom | stop_signal | restart_budget | restart
}

// Supervisor runs one application under health supervision.
type Supervisor struct {
	runStarted chan struct{} // closed once Run has taken its context (Deploy may then attach monitors)
	opts       Options
	log        func(string, ...any)
	ready      *ready.Server

	mu            sync.Mutex
	rt            imagecfg.Runtime
	man           *manifest.Manifest
	imageEnv      []string // ENV from the image config; extraEnv is merged over it
	extraEnv      []string // console-delivered NAME=VALUE pairs (override image ENV)
	mon           *health.Monitor
	monCancel     context.CancelFunc
	proc          *runner.Proc
	restarts      int
	started       time.Time
	deployedAt    time.Time
	transitioning bool
	confirmed     bool
	ctx           context.Context
	lastExit      *Exit
	oomBase       int64 // cgroup oom_kill counter when the supervisor started (-1: not visible)
	stopping      bool  // a termination signal reached PID 1; the app is being drained
}

// New builds a Supervisor; Run starts everything.
func New(opts Options) *Supervisor {
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	s := &Supervisor{opts: opts, log: opts.Log, man: manifest.Defaults(), runStarted: make(chan struct{}), oomBase: metrics.OOMKills()}
	if opts.Manifest != nil {
		s.man = opts.Manifest
	}
	if opts.Runtime != nil {
		s.rt = applyManifestOverrides(*opts.Runtime, s.man)
	}
	s.mon = s.newMonitor(s.man)
	if opts.ReadyListen != "" {
		s.ready = ready.New(s, s.man.Health.Interval)
	}
	return s
}

func applyManifestOverrides(rt imagecfg.Runtime, m *manifest.Manifest) imagecfg.Runtime {
	if len(m.Entrypoint) > 0 {
		rt.Entrypoint = m.Entrypoint
	}
	if len(m.Cmd) > 0 {
		rt.Cmd = m.Cmd
	}
	if m.WorkDir != "" {
		rt.WorkingDir = m.WorkDir
	}
	if m.User != "" {
		rt.User = m.User
	}
	return rt
}

func (s *Supervisor) newMonitor(m *manifest.Manifest) *health.Monitor {
	return health.New(health.Config{
		Interval: m.Health.Interval, Timeout: m.Health.Timeout, Grace: m.Health.Grace, FailureThreshold: m.Health.FailureThreshold,
	}, checkerFor(m, s.AppRunning), func(st health.State) {
		if st.Healthy {
			s.log("health: HEALTHY (%s)", st.Check)
		} else {
			s.log("health: UNHEALTHY after %d consecutive failures: %s", st.ConsecutiveFailures, st.LastError)
		}
	})
}

func checkerFor(m *manifest.Manifest, alive func() bool) health.Checker {
	h := m.Health
	switch h.Kind() {
	case "http":
		return health.HTTPCheck{URL: h.HTTP}
	case "tcp":
		return health.TCPCheck{Addr: h.TCP}
	case "exec":
		return health.ExecCheck{Argv: h.Exec}
	}
	return health.ProcessCheck{Alive: alive}
}

// --- ready.Source ---

func (s *Supervisor) Health() health.State {
	s.mu.Lock()
	m := s.mon
	s.mu.Unlock()
	return m.State()
}
func (s *Supervisor) CheckNow(ctx context.Context) health.State {
	s.mu.Lock()
	m := s.mon
	s.mu.Unlock()
	return m.CheckNow(ctx)
}
func (s *Supervisor) AppRunning() bool {
	s.mu.Lock()
	p := s.proc
	s.mu.Unlock()
	return p != nil && p.Running()
}
func (s *Supervisor) Transitioning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitioning
}
func (s *Supervisor) Info() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{
		"restarts":       s.restarts,
		"started":        s.started,
		"deployed_at":    s.deployedAt,
		"confirmed":      s.confirmed,
		"manifest":       map[string]any{"name": s.man.Name, "version": s.man.Version, "source": s.man.Source, "health": s.man.Health.Kind(), "strategy": s.man.Update.Strategy},
		"supervisor_pid": os.Getpid(),
		"console_env":    envNames(s.extraEnv), // names only: values never leave the process
	}
	if s.proc != nil {
		out["pid"] = s.proc.Pid()
	}
	for k, v := range s.opts.Info {
		out[k] = v
	}
	return out
}

// SetInfo replaces the extra info reported by /fleetwide/status.
func (s *Supervisor) SetInfo(info map[string]any) {
	s.mu.Lock()
	s.opts.Info = info
	s.mu.Unlock()
}

// Ready returns the readiness server (nil when disabled).
func (s *Supervisor) Ready() *ready.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// EnableReady opens the ready endpoint after construction, for an address the
// supervisor only learns when the console or a release manifest names one. A second
// call, or an address already being served, does nothing.
func (s *Supervisor) EnableReady(addr string) {
	if addr == "" {
		return
	}
	s.mu.Lock()
	if s.ready != nil {
		s.mu.Unlock()
		return
	}
	s.opts.ReadyListen = addr
	s.ready = ready.New(s, s.man.Health.Interval)
	rd, ctx := s.ready, s.ctx
	s.mu.Unlock()
	if ctx == nil {
		return // Run has not started yet and will serve it
	}
	go func() {
		if err := rd.ListenAndServe(ctx, addr); err != nil {
			s.log("ready endpoint: %v", err)
		}
	}()
	s.log("ready endpoint on %s (/fleetwide/ready, /fleetwide/live, /fleetwide/status)", addr)
}

// SetHealth replaces the health check without touching the running
// application; the next check uses the new rules. Returns whether anything
// changed.
func (s *Supervisor) SetHealth(h manifest.Health) bool {
	s.mu.Lock()
	if healthSame(s.man.Health, h) {
		s.mu.Unlock()
		return false
	}
	s.man.Health = h
	if s.monCancel != nil {
		s.monCancel()
	}
	s.mon = s.newMonitor(s.man)
	ctx := s.ctx
	s.mu.Unlock()
	if ctx != nil {
		s.startMonitor(ctx)
	}
	s.log("health check is now %s (every %s, %d failures to act, on_unhealthy=%s)", h.Kind(), h.Interval, h.FailureThreshold, h.OnUnhealthy)
	return true
}

// healthSame compares the fields that decide how the app is probed.
func healthSame(a, b manifest.Health) bool {
	if a.HTTP != b.HTTP || a.TCP != b.TCP || len(a.Exec) != len(b.Exec) {
		return false
	}
	for i := range a.Exec {
		if a.Exec[i] != b.Exec[i] {
			return false
		}
	}
	return a.Interval == b.Interval && a.Timeout == b.Timeout && a.Grace == b.Grace &&
		a.FailureThreshold == b.FailureThreshold && a.OnUnhealthy == b.OnUnhealthy && a.MaxRestarts == b.MaxRestarts
}

// Manifest returns the active manifest.
func (s *Supervisor) Manifest() *manifest.Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.man
}

// Snapshot reports state for heartbeats.
func (s *Supervisor) Snapshot() Snapshot {
	st := s.Health()
	s.mu.Lock()
	defer s.mu.Unlock()
	running := s.proc != nil && s.proc.Running()
	if !s.confirmed && running && st.Healthy && !st.LastOK.IsZero() && !s.deployedAt.IsZero() &&
		time.Since(s.deployedAt) > s.man.Health.Grace+2*s.man.Health.Interval {
		s.confirmed = true
	}
	snap := Snapshot{
		Running: running, Transitioning: s.transitioning, Health: st,
		Ready:    running && st.Healthy && !st.LastOK.IsZero(),
		Restarts: s.restarts, DeployedAt: s.deployedAt, LastExit: s.lastExit, Confirmed: s.confirmed,
	}
	if s.proc != nil {
		snap.PID = s.proc.Pid()
	}
	return snap
}

// Confirmed reports whether the current release has proven healthy.
func (s *Supervisor) Confirmed() bool { return s.Snapshot().Confirmed }

func (s *Supervisor) setTransitioning(v bool) {
	s.mu.Lock()
	s.transitioning = v
	s.mu.Unlock()
}

// start launches the current runtime. Caller must not hold the lock.
func (s *Supervisor) start() error {
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if len(rt.Argv(s.opts.CmdOver)) == 0 {
		return errors.New("no release to run")
	}
	ro := runner.Options{Root: "/", CmdOver: s.opts.CmdOver, Log: s.log}
	if s.opts.Logs != nil {
		ro.Stdout, ro.Stderr = s.opts.Logs.Writer("stdout"), s.opts.Logs.Writer("stderr")
	}
	p, err := runner.Start(rt, ro)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.proc = p
	s.started = time.Now()
	m := s.mon
	s.mu.Unlock()
	m.Reset()
	return nil
}

// recordExit remembers how the app stopped; SIGKILL with a moved oom_kill
// counter is the kernel's OOM killer.
func (s *Supervisor) recordExit(p *runner.Proc, code int, reason string) *Exit {
	e := &Exit{At: time.Now(), Code: code, Reason: reason}
	if sig := p.Signaled(); sig != 0 {
		e.Signal = signalName(sig)
		if sig == syscall.SIGKILL {
			if n := metrics.OOMKills(); n >= 0 && n > s.oomBase {
				e.OOM = true
				e.Reason = "oom"
				s.oomBase = n
			}
		}
	}
	s.mu.Lock()
	s.lastExit = e
	s.mu.Unlock()
	return e
}

// StopTimeout is how long the current manifest lets the app drain on SIGTERM.
func (s *Supervisor) StopTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.man == nil {
		return 10 * time.Second
	}
	return s.man.Health.StopTimeout
}

// LastExit is how the app last stopped (nil while it has never stopped).
func (s *Supervisor) LastExit() *Exit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastExit
}

// Stopping reports whether a termination signal has reached the supervisor.
func (s *Supervisor) Stopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGBUS:
		return "SIGBUS"
	case syscall.SIGILL:
		return "SIGILL"
	case syscall.SIGFPE:
		return "SIGFPE"
	case syscall.SIGPIPE:
		return "SIGPIPE"
	}
	return fmt.Sprintf("signal %d", int(sig))
}

// stopCurrent stops the running app if any. Caller must not hold the lock.
func (s *Supervisor) stopCurrent() {
	s.mu.Lock()
	p := s.proc
	man := s.man
	s.mu.Unlock()
	if p != nil && p.Running() {
		code, _ := p.Stop(syscall.SIGTERM, man.Health.StopTimeout)
		s.log("app stopped (code %d)", code)
		reason := "restart"
		if s.Stopping() {
			reason = "stop_signal"
		}
		s.recordExit(p, code, reason)
	}
}

// Prepared is what a gap hook produced: the release to start next.
type Prepared struct {
	Runtime  imagecfg.Runtime
	Manifest *manifest.Manifest
}

// Swap is how long a release swap took, phase by phase. Stop + Prepare +
// Start is the time the application was down.
type Swap struct{ StopMS, PrepareMS, StartMS int64 }

// PrepareError reports that the gap hook failed. The application is stopped
// and nothing was started; the filesystem may be half-written. The caller
// owns recovery.
type PrepareError struct{ Err error }

func (e *PrepareError) Error() string { return "prepare: " + e.Err.Error() }
func (e *PrepareError) Unwrap() error { return e.Err }

// DeployWith swaps releases with the filesystem work inside the gap: it stops
// the current application, calls prepare — the one moment at which no process
// is watching the filesystem — and starts what prepare returned. Readiness
// goes 503 only while the app is actually down; liveness stays 200 throughout.
//
// When prepare fails nothing is started, and the supervisor still describes
// the old release (runtime, manifest, monitor), which is what recovery needs.
func (s *Supervisor) DeployWith(prepare func() (Prepared, error)) (Swap, error) {
	var sw Swap
	s.setTransitioning(true)
	defer s.setTransitioning(false)

	t0 := time.Now()
	s.stopCurrent()
	// Drop the old process so the run loop does not spin on its closed Done
	// channel for as long as the gap lasts; Snapshot().PID is 0 meanwhile.
	s.mu.Lock()
	s.proc = nil
	s.mu.Unlock()
	sw.StopMS = time.Since(t0).Milliseconds()

	t1 := time.Now()
	p, err := prepare()
	sw.PrepareMS = time.Since(t1).Milliseconds()
	if err != nil {
		return sw, &PrepareError{Err: err}
	}
	rt, man := p.Runtime, p.Manifest

	s.mu.Lock()
	s.imageEnv = rt.Env
	rt.Env = MergeEnv(rt.Env, s.extraEnv)
	if err := WriteEnvFiles(s.extraEnv); err != nil {
		s.log("env files: %v", err)
	}
	s.rt = applyManifestOverrides(rt, man)
	s.man = man
	if s.monCancel != nil {
		s.monCancel()
	}
	s.mon = s.newMonitor(man)
	s.deployedAt = time.Now()
	s.confirmed = false
	ctx := s.ctx
	s.mu.Unlock()

	if ctx != nil {
		s.startMonitor(ctx)
	}
	t2 := time.Now()
	if err := s.start(); err != nil {
		return sw, fmt.Errorf("deploy: %w", err)
	}
	sw.StartMS = time.Since(t2).Milliseconds()
	return sw, nil
}

// Park stops the application and leaves nothing running. From here ready and
// live both answer 503 while the run loop keeps serving the endpoint and
// waits for a Deploy. The health monitor is cancelled so nothing restarts the
// app.
func (s *Supervisor) Park(reason string) {
	s.setTransitioning(true) // the run loop must read the exit as ours, not the app's
	s.mu.Lock()
	if s.monCancel != nil {
		s.monCancel()
		s.monCancel = nil
	}
	s.mu.Unlock()
	s.stopCurrent()
	s.mu.Lock()
	s.proc = nil
	s.mu.Unlock()
	s.setTransitioning(false)
	s.log("parked: %s", reason)
}

// Deploy swaps in a release whose files are already in place — a baked image,
// or a tree the caller wrote itself. between, when given, still runs in the
// gap, where residue can be removed with nothing watching.
func (s *Supervisor) Deploy(rt imagecfg.Runtime, man *manifest.Manifest, between func()) error {
	_, err := s.DeployWith(func() (Prepared, error) {
		if between != nil {
			between()
		}
		return Prepared{Runtime: rt, Manifest: man}, nil
	})
	return err
}

// SetExtraEnv replaces the console-delivered environment. When restart is
// true and the values changed while an app is running, the app is restarted
// in place so the new values take effect. Returns whether anything changed.
func (s *Supervisor) SetExtraEnv(env []string, restart bool) (bool, error) {
	s.mu.Lock()
	changed := strings.Join(env, "\x00") != strings.Join(s.extraEnv, "\x00")
	s.extraEnv = append([]string(nil), env...)
	s.rt.Env = MergeEnv(s.imageEnv, s.extraEnv)
	running := s.proc != nil && s.proc.Running()
	s.mu.Unlock()
	if changed {
		if err := WriteEnvFiles(env); err != nil {
			s.log("env files: %v", err)
		}
	}
	if !changed || !restart || !running {
		return changed, nil
	}
	return true, s.Restart("environment updated from the console")
}

func envNames(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k)
	}
	return out
}

// MergeEnv overlays extra NAME=VALUE pairs on base, replacing by name and
// keeping base order (new names appended in order).
func MergeEnv(base, extra []string) []string {
	idx := map[string]int{}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		idx[k] = len(out)
		out = append(out, kv)
	}
	for _, kv := range extra {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if i, seen := idx[k]; seen {
			out[i] = kv
		} else {
			idx[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

// WaitStarted blocks until Run has begun (or ctx ends). Call it before the
// first Deploy so the health monitor gets the supervisor's context.
func (s *Supervisor) WaitStarted(ctx context.Context) {
	select {
	case <-s.runStarted:
	case <-ctx.Done():
	}
}

// Signal delivers sig to the running application (asset reload hooks).
func (s *Supervisor) Signal(sig os.Signal) error {
	s.mu.Lock()
	p := s.proc
	s.mu.Unlock()
	if p == nil || !p.Running() {
		return errors.New("application is not running")
	}
	return p.Signal(sig)
}

// Restart stops and starts the current release (Console "restart" request).
func (s *Supervisor) Restart(reason string) error {
	s.setTransitioning(true)
	defer s.setTransitioning(false)
	s.log("restart requested: %s", reason)
	s.stopCurrent()
	s.mu.Lock()
	s.restarts++
	s.mu.Unlock()
	return s.start()
}

func (s *Supervisor) startMonitor(ctx context.Context) {
	s.mu.Lock()
	mctx, cancel := context.WithCancel(ctx)
	s.monCancel = cancel
	m := s.mon
	s.mu.Unlock()
	go m.Run(mctx)
}

// Run blocks until the app exits on its own (returns its exit code), the
// restart budget is exhausted (returns 1), or ctx is cancelled (stops the app
// and returns 0). With no initial release it waits for Deploy.
func (s *Supervisor) Run(ctx context.Context) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	s.ctx = ctx
	// Only the runtime given at construction is auto-started here; a release
	// handed over through Deploy starts itself (Deploy waits for Run via
	// WaitStarted, so it can attach the health monitor to this context).
	hasRelease := s.opts.Runtime != nil && s.proc == nil
	s.mu.Unlock()
	close(s.runStarted)

	s.mu.Lock()
	rd, addr := s.ready, s.opts.ReadyListen
	s.mu.Unlock()
	if rd != nil {
		go func() {
			if err := rd.ListenAndServe(ctx, addr); err != nil {
				s.log("ready endpoint: %v", err)
			}
		}()
		s.log("ready endpoint on %s (/fleetwide/ready, /fleetwide/live, /fleetwide/status)", addr)
	}
	if hasRelease {
		s.mu.Lock()
		s.deployedAt = time.Now()
		s.mu.Unlock()
		if err := s.start(); err != nil {
			return 0, err
		}
		s.startMonitor(ctx)
	}

	// Forward termination signals to the app; the orchestrator is stopping us.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sigs)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		s.mu.Lock()
		p := s.proc
		man := s.man
		transitioning := s.transitioning
		mon := s.mon
		s.mu.Unlock()
		var done <-chan struct{}
		if p != nil {
			done = p.Done()
		}
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.stopping = true
			s.mu.Unlock()
			s.stopCurrent()
			return 0, nil
		case sig := <-sigs:
			if sig == syscall.SIGTERM || sig == syscall.SIGINT || sig == syscall.SIGQUIT {
				s.mu.Lock()
				s.stopping = true
				s.mu.Unlock()
			}
			if p != nil {
				_ = p.Signal(sig)
			} else if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				return 0, nil
			}
		case <-done:
			// A swap in progress closes the old proc's Done; not an app exit.
			s.mu.Lock()
			swapped := s.proc != p || s.transitioning
			s.mu.Unlock()
			if swapped {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			code, err := p.Exit()
			reason := "app_exit"
			if s.Stopping() {
				reason = "stop_signal"
			}
			e := s.recordExit(p, code, reason)
			if e.OOM {
				s.log("app was killed by the kernel OOM killer (exit code %d)", code)
			} else if e.Signal != "" {
				s.log("app exited on %s (code %d)", e.Signal, code)
			} else {
				s.log("app exited with code %d", code)
			}
			return code, err
		case <-tick.C:
			if p == nil || transitioning {
				continue
			}
			st := mon.State()
			if st.Healthy || man.Health.OnUnhealthy != "restart" || st.UnhealthyFor < man.Rollback.OnUnhealthyFor {
				continue
			}
			if s.opts.OnUnhealthyFor != nil && s.opts.OnUnhealthyFor(st) {
				continue // e.g. rolled back
			}
			s.mu.Lock()
			budgetLeft := s.restarts < man.Health.MaxRestarts
			s.mu.Unlock()
			if !budgetLeft {
				s.log("unhealthy for %s and restart budget (%d) exhausted; exiting 1 for the orchestrator", st.UnhealthyFor.Round(time.Second), man.Health.MaxRestarts)
				s.stopCurrent()
				s.mu.Lock()
				if s.lastExit != nil {
					s.lastExit.Reason = "restart_budget"
				}
				s.mu.Unlock()
				return 1, nil
			}
			if err := s.restartUnhealthy(st, man); err != nil {
				return 0, err
			}
		}
	}
}

func (s *Supervisor) restartUnhealthy(st health.State, man *manifest.Manifest) error {
	s.mu.Lock()
	n := s.restarts + 1
	s.mu.Unlock()
	s.log("unhealthy for %s (%s); restarting in place (%d/%d)", st.UnhealthyFor.Round(time.Second), st.LastError, n, man.Health.MaxRestarts)
	// /fleetwide/live stays 200 while the Supervisor manages the restart.
	s.setTransitioning(true)
	defer s.setTransitioning(false)
	s.stopCurrent()
	s.log("waiting %s before restart", man.Health.RestartBackoff)
	time.Sleep(man.Health.RestartBackoff)
	s.mu.Lock()
	s.restarts++
	s.mu.Unlock()
	if err := s.start(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	if s.opts.OnRestart != nil {
		s.opts.OnRestart(st.LastError)
	}
	return nil
}
