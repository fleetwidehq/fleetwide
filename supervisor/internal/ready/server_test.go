package ready

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/health"
)

type fakeSrc struct {
	st            health.State
	running       bool
	transitioning bool
	probes        int
}

func (f *fakeSrc) Health() health.State { return f.st }
func (f *fakeSrc) CheckNow(context.Context) health.State {
	f.probes++
	f.st.LastCheck = time.Now()
	return f.st
}
func (f *fakeSrc) AppRunning() bool     { return f.running }
func (f *fakeSrc) Transitioning() bool  { return f.transitioning }
func (f *fakeSrc) Info() map[string]any { return map[string]any{"pid": 42} }

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestReadyMirrorsHealthOnly(t *testing.T) {
	src := &fakeSrc{st: health.State{Healthy: true, InGrace: true, LastCheck: time.Now(), Check: "http x"}, running: true}
	h := New(src, time.Second).Handler()

	if code, _ := do(t, h, "GET", "/fleetwide/ready", ""); code != 503 {
		t.Fatalf("no successful check yet (grace) must be unready, got %d", code)
	}
	src.st.LastOK = time.Now()
	if code, body := do(t, h, "GET", "/fleetwide/ready", ""); code != 200 || body["ready"] != true || body["override"] != "none" {
		t.Fatalf("healthy running app should be ready: %d %v", code, body)
	}
	// unhealthy app → 503 with the error surfaced
	src.st.Healthy = false
	src.st.LastError = "status 500"
	if code, body := do(t, h, "GET", "/fleetwide/ready", ""); code != 503 || body["error"] != "status 500" {
		t.Fatalf("unhealthy must be 503: %d %v", code, body)
	}
	// app down → 503 even if the last check was OK
	src.st.Healthy = true
	src.running = false
	if code, body := do(t, h, "GET", "/fleetwide/ready", ""); code != 503 || body["running"] != false {
		t.Fatalf("app down must be unready: %d %v", code, body)
	}
}

func TestLiveSurvivesManagedTransition(t *testing.T) {
	src := &fakeSrc{running: true}
	h := New(src, time.Second).Handler()
	if code, _ := do(t, h, "GET", "/fleetwide/live", ""); code != 200 {
		t.Fatal("running app must be live")
	}
	// supervisor restarting the app: process is down but the supervisor is managing it.
	src.running = false
	src.transitioning = true
	if code, body := do(t, h, "GET", "/fleetwide/live", ""); code != 200 || body["transitioning"] != true {
		t.Fatalf("managed transition must stay live so k8s does not kill the pod: %d %v", code, body)
	}
	src.transitioning = false
	if code, _ := do(t, h, "GET", "/fleetwide/live", ""); code != 503 {
		t.Fatal("app down and not managed must not be live")
	}
}

func TestOverrideForcesAnswer(t *testing.T) {
	src := &fakeSrc{st: health.State{Healthy: true, LastOK: time.Now(), LastCheck: time.Now()}, running: true}
	s := New(src, time.Second)
	h := s.Handler()
	if code, _ := do(t, h, "POST", "/fleetwide/override", `{"status":"unready"}`); code != 200 {
		t.Fatal("override should be accepted")
	}
	if code, body := do(t, h, "GET", "/fleetwide/ready", ""); code != 503 || body["actual"] != true || body["override"] != "unready" {
		t.Fatalf("forced unready must be 503 while actual stays true: %d %v", code, body)
	}
	src.running = false
	do(t, h, "POST", "/fleetwide/override", `{"status":"ready"}`)
	if code, body := do(t, h, "GET", "/fleetwide/ready", ""); code != 200 || body["actual"] != false {
		t.Fatalf("forced ready must be 200 even when actual is false: %d %v", code, body)
	}
	do(t, h, "POST", "/fleetwide/override", `{"status":"none"}`)
	if code, _ := do(t, h, "GET", "/fleetwide/ready", ""); code != 503 {
		t.Fatal("clearing override must return to the actual state")
	}
	if code, _ := do(t, h, "POST", "/fleetwide/override", `{"status":"maybe"}`); code != 400 {
		t.Fatal("bad override value must be rejected")
	}
	if code, _ := do(t, h, "GET", "/fleetwide/override", ""); code != 405 {
		t.Fatal("GET override must be rejected")
	}
	if code, body := do(t, h, "GET", "/fleetwide/status", ""); code != 200 || body["pid"].(float64) != 42 || body["override"] != "none" {
		t.Fatalf("status: %d %v", code, body)
	}
}

func TestStaleResultTriggersSynchronousProbe(t *testing.T) {
	src := &fakeSrc{st: health.State{Healthy: true, LastOK: time.Now(), LastCheck: time.Now().Add(-time.Minute)}, running: true}
	s := New(src, time.Second)
	do(t, s.Handler(), "GET", "/fleetwide/ready", "")
	if src.probes != 1 {
		t.Fatalf("stale state must probe synchronously, probes=%d", src.probes)
	}
	do(t, s.Handler(), "GET", "/fleetwide/ready", "")
	if src.probes != 1 {
		t.Fatal("fresh state must not probe again")
	}
}
