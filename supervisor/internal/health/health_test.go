package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type flaky struct{ fail atomic.Bool }

func (f *flaky) String() string { return "flaky" }
func (f *flaky) Check(context.Context) error {
	if f.fail.Load() {
		return errors.New("boom")
	}
	return nil
}

func TestThresholdAndRecovery(t *testing.T) {
	f := &flaky{}
	var flips []bool
	m := New(Config{Interval: time.Second, Timeout: 100 * time.Millisecond, Grace: 0, FailureThreshold: 3}, f, func(s State) { flips = append(flips, s.Healthy) })
	ctx := context.Background()
	if !m.CheckNow(ctx).Healthy {
		t.Fatal("should start healthy")
	}
	f.fail.Store(true)
	m.CheckNow(ctx)
	m.CheckNow(ctx)
	if !m.State().Healthy {
		t.Fatal("2 failures must not trip threshold 3")
	}
	s := m.CheckNow(ctx)
	if s.Healthy || s.ConsecutiveFailures != 3 || s.LastError != "boom" {
		t.Fatalf("expected unhealthy after 3: %+v", s)
	}
	time.Sleep(20 * time.Millisecond)
	if m.State().UnhealthyFor <= 0 {
		t.Fatal("UnhealthyFor should grow while unhealthy")
	}
	f.fail.Store(false)
	s = m.CheckNow(ctx)
	if !s.Healthy || s.UnhealthyFor != 0 || s.ConsecutiveFailures != 0 {
		t.Fatalf("expected recovery: %+v", s)
	}
	if len(flips) != 2 || flips[0] || !flips[1] {
		t.Fatalf("onChange flips = %v", flips)
	}
}

func TestGraceIgnoresFailures(t *testing.T) {
	f := &flaky{}
	f.fail.Store(true)
	m := New(Config{Interval: time.Second, Timeout: 100 * time.Millisecond, Grace: 200 * time.Millisecond, FailureThreshold: 1}, f, nil)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		s := m.CheckNow(ctx)
		if !s.Healthy || !s.InGrace {
			t.Fatalf("failures during grace must not count: %+v", s)
		}
	}
	time.Sleep(250 * time.Millisecond)
	if s := m.CheckNow(ctx); s.Healthy || s.InGrace {
		t.Fatalf("after grace a failure must count: %+v", s)
	}
	// Reset (app restarted) re-arms grace.
	m.Reset()
	if s := m.CheckNow(ctx); !s.Healthy || !s.InGrace {
		t.Fatalf("Reset must re-arm grace: %+v", s)
	}
}

func TestHTTPTCPExecProcess(t *testing.T) {
	ctx := context.Background()
	code := atomic.Int32{}
	code.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(code.Load())) }))
	defer srv.Close()
	h := HTTPCheck{URL: srv.URL + "/healthz"}
	if err := h.Check(ctx); err != nil {
		t.Fatal(err)
	}
	code.Store(503)
	if err := h.Check(ctx); err == nil {
		t.Fatal("503 must be unhealthy")
	}
	code.Store(302)
	if err := h.Check(ctx); err != nil {
		t.Fatal("3xx must be healthy without following:", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	tc := TCPCheck{Addr: ln.Addr().String()}
	if err := tc.Check(ctx); err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if err := tc.Check(ctx); err == nil {
		t.Fatal("closed port must be unhealthy")
	}

	if err := (ExecCheck{Argv: []string{"true"}}).Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (ExecCheck{Argv: []string{"false"}}).Check(ctx); err == nil {
		t.Fatal("exit 1 must be unhealthy")
	}
	alive := true
	p := ProcessCheck{Alive: func() bool { return alive }}
	if err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
	alive = false
	if err := p.Check(ctx); err == nil {
		t.Fatal("dead process must be unhealthy")
	}
}

func TestTimeoutIsEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(500 * time.Millisecond) }))
	defer srv.Close()
	m := New(Config{Interval: time.Second, Timeout: 50 * time.Millisecond, FailureThreshold: 1}, HTTPCheck{URL: srv.URL}, nil)
	start := time.Now()
	s := m.CheckNow(context.Background())
	if s.Healthy || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("timeout not enforced: %+v in %v", s, time.Since(start))
	}
}
