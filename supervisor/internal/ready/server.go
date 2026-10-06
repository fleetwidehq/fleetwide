// Package ready serves the optional supervisor HTTP endpoint, which
// orchestrator probes can target instead of the app:
//
//	GET  /fleetwide/ready     200 when the app is running and its health check
//	                          passes; 503 when the app is down or failing.
//	GET  /fleetwide/live      200 while the supervisor is supervising: app running,
//	                          or a supervisor-managed restart/update in progress.
//	                          Never fails during a managed transition.
//	GET  /fleetwide/status    JSON snapshot
//	POST /fleetwide/override  {"status":"ready"|"unready"|"none"} forces the
//	                          readiness answer.
//
// Readiness mirrors the manifest's health check and adds no check of its own.
// If the cached result is older than two intervals it probes synchronously.
package ready

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/health"
)

// Source provides the state the endpoint reports.
type Source interface {
	Health() health.State
	CheckNow(ctx context.Context) health.State
	AppRunning() bool
	Transitioning() bool  // Supervisor-managed restart or update in progress
	Info() map[string]any // release, pid, restarts...
}

// Override values.
const (
	OverrideNone    = "none"
	OverrideReady   = "ready"
	OverrideUnready = "unready"
)

// Server is the readiness endpoint.
type Server struct {
	src      Source
	interval time.Duration
	override atomic.Value // string
	srv      *http.Server
}

// New builds the server; interval is the health check interval (staleness bound).
func New(src Source, interval time.Duration) *Server {
	s := &Server{src: src, interval: interval}
	s.override.Store(OverrideNone)
	mux := http.NewServeMux()
	mux.HandleFunc("/fleetwide/ready", s.handleReady)
	mux.HandleFunc("/fleetwide/live", s.handleLive)
	mux.HandleFunc("/fleetwide/status", s.handleStatus)
	mux.HandleFunc("/fleetwide/override", s.handleOverride)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

// Override returns the current forced status ("none" when not forced).
func (s *Server) Override() string { return s.override.Load().(string) }

// SetOverride forces the readiness answer; use OverrideNone to clear.
func (s *Server) SetOverride(v string) error {
	switch v {
	case OverrideNone, OverrideReady, OverrideUnready:
		s.override.Store(v)
		return nil
	}
	return errBadOverride
}

// Handler exposes the mux for tests.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// ListenAndServe serves on addr until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.srv.Shutdown(sctx)
	}()
	err = s.srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) current(r *http.Request) health.State {
	st := s.src.Health()
	if st.LastCheck.IsZero() || time.Since(st.LastCheck) > 2*s.interval {
		st = s.src.CheckNow(r.Context())
	}
	return st
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	st := s.current(r)
	running := s.src.AppRunning()
	// Not ready until the check has succeeded at least once since the last
	// (re)start: "healthy" during the grace period only means "not yet failed".
	actual := running && st.Healthy && !st.LastOK.IsZero()
	ready := actual
	ov := s.Override()
	switch ov {
	case OverrideReady:
		ready = true
	case OverrideUnready:
		ready = false
	}
	writeJSON(w, ready, map[string]any{
		"ready":    ready,
		"actual":   actual,
		"override": ov,
		"healthy":  st.Healthy,
		"running":  running,
		"check":    st.Check,
		"error":    st.LastError,
	})
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	running := s.src.AppRunning()
	transitioning := s.src.Transitioning()
	live := running || transitioning
	writeJSON(w, live, map[string]any{"live": live, "running": running, "transitioning": transitioning})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"health":        s.src.Health(),
		"override":      s.Override(),
		"running":       s.src.AppRunning(),
		"transitioning": s.src.Transitioning(),
	}
	for k, v := range s.src.Info() {
		out[k] = v
	}
	writeJSON(w, true, out)
}

func (s *Server) handleOverride(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := s.SetOverride(body.Status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, true, map[string]any{"override": body.Status})
}

func writeJSON(w http.ResponseWriter, ok bool, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(v)
}

type overrideErr struct{}

func (overrideErr) Error() string { return `override status must be "ready", "unready" or "none"` }

var errBadOverride error = overrideErr{}
