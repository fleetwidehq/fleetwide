//go:build linux

package supervise

import (
	"errors"
	"testing"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
)

// sleeper execs sleep in place of the shell, so stopping the process leaves
// no orphan holding the test's stdout open.
func sleeper() imagecfg.Runtime {
	return imagecfg.Runtime{Entrypoint: []string{"/bin/sh"}, Cmd: []string{"-c", "exec sleep 60"}}
}

func newTestSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	s := New(Options{Log: func(string, ...any) {}})
	t.Cleanup(s.stopCurrent)
	return s
}

// The gap hook runs with the old application gone and the new one not yet
// started.
func TestDeployRunsBetweenWhileNothingIsRunning(t *testing.T) {
	s := newTestSupervisor(t)
	if err := s.Deploy(sleeper(), manifest.Defaults(), nil); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	first := s.Snapshot().PID
	if first == 0 || !s.AppRunning() {
		t.Fatalf("the first release should be running: pid=%d", first)
	}

	called := 0
	runningDuringHook := true
	if err := s.Deploy(sleeper(), manifest.Defaults(), func() {
		called++
		runningDuringHook = s.AppRunning()
	}); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	if called != 1 {
		t.Fatalf("between ran %d times, want once", called)
	}
	if runningDuringHook {
		t.Fatal("between ran while the old application was still up")
	}
	second := s.Snapshot().PID
	if second == 0 || second == first || !s.AppRunning() {
		t.Fatalf("the new release should be running afterwards: %d → %d", first, second)
	}
}

// A first deployment has nothing to clean up, and a nil hook must not panic.
func TestDeployWithoutBetween(t *testing.T) {
	s := newTestSupervisor(t)
	if err := s.Deploy(sleeper(), manifest.Defaults(), nil); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if !s.AppRunning() {
		t.Fatal("the application should be running")
	}
}

// With the filesystem work inside the gap, a failed prepare must leave the
// container in a state recovery can reason about: nothing running, nothing
// started, and the supervisor still describing the old release.
func TestDeployWithFailedPrepareStartsNothing(t *testing.T) {
	s := newTestSupervisor(t)
	if err := s.Deploy(sleeper(), manifest.Defaults(), nil); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	oldMan := s.Manifest()
	boom := errors.New("commit failed: no space left on device")
	sw, err := s.DeployWith(func() (Prepared, error) { return Prepared{}, boom })
	var pe *PrepareError
	if !errors.As(err, &pe) || !errors.Is(err, boom) {
		t.Fatalf("want a PrepareError wrapping the cause, got %v", err)
	}
	if s.AppRunning() {
		t.Fatal("nothing may be started after a failed prepare")
	}
	if s.Manifest() != oldMan {
		t.Fatal("the supervisor must still describe the old release")
	}
	if sw.StopMS < 0 || sw.StartMS != 0 {
		t.Fatalf("timings: %+v (nothing was started, so StartMS must be 0)", sw)
	}
}

// The swap timings are what the console will show as downtime; the prepare
// phase has to be measured around the hook alone.
func TestSwapTimingsAreRecorded(t *testing.T) {
	s := newTestSupervisor(t)
	sw, err := s.DeployWith(func() (Prepared, error) {
		time.Sleep(200 * time.Millisecond)
		return Prepared{Runtime: sleeper(), Manifest: manifest.Defaults()}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sw.PrepareMS < 180 {
		t.Fatalf("PrepareMS = %d, want ≥ 180 for a 200ms hook", sw.PrepareMS)
	}
	if !s.AppRunning() {
		t.Fatal("the prepared release should be running")
	}
}
