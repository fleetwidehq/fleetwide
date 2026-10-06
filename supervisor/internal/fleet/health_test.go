package fleet

import (
	"testing"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
)

// The console's definition lies over the image's manifest rather than
// replacing it: unset fields keep the manifest's values.
func TestMergeHealthKeepsUnsetFields(t *testing.T) {
	base := manifest.Health{HTTP: "http://127.0.0.1:8080/healthz", Interval: 10 * time.Second, Timeout: 2 * time.Second, Grace: 30 * time.Second, FailureThreshold: 3, OnUnhealthy: v1.OnUnhealthyRestart, MaxRestarts: 5}
	got := mergeHealth(base, &v1.Healthcheck{IntervalS: 30})
	if got.HTTP != base.HTTP || got.Timeout != base.Timeout || got.FailureThreshold != 3 || got.MaxRestarts != 5 {
		t.Fatalf("an interval-only override must keep the rest: %+v", got)
	}
	if got.Interval != 30*time.Second {
		t.Fatalf("interval = %s, want 30s", got.Interval)
	}
}

// A probe defined in the console replaces the image's, including its kind.
func TestMergeHealthReplacesTheProbe(t *testing.T) {
	base := manifest.Health{HTTP: "http://127.0.0.1:8080/healthz", Interval: 10 * time.Second}
	got := mergeHealth(base, &v1.Healthcheck{TCP: "127.0.0.1:5432", GraceS: 60, OnUnhealthy: v1.OnUnhealthyIgnore})
	if got.Kind() != "tcp" || got.TCP != "127.0.0.1:5432" || got.HTTP != "" {
		t.Fatalf("a tcp probe must replace the image's http one: %+v", got)
	}
	if got.Grace != 60*time.Second || got.OnUnhealthy != v1.OnUnhealthyIgnore {
		t.Fatalf("grace and action: %+v", got)
	}
}

// Probes switched off at the fleet leave the process as the only check, and
// nothing may restart the app on health grounds.
func TestMergeHealthProcessOnly(t *testing.T) {
	base := manifest.Health{HTTP: "http://127.0.0.1:8080/healthz", Exec: []string{"/bin/true"}, OnUnhealthy: v1.OnUnhealthyRestart, Interval: 10 * time.Second}
	got := mergeHealth(base, &v1.Healthcheck{ProcessOnly: true})
	if got.Kind() != "process" || got.HTTP != "" || got.TCP != "" || len(got.Exec) != 0 {
		t.Fatalf("every probe must be dropped: %+v", got)
	}
	if got.OnUnhealthy != v1.OnUnhealthyReport {
		t.Fatalf("with no probe, nothing may restart on health grounds: %+v", got)
	}
	if got.Interval != 10*time.Second {
		t.Fatalf("the rest of the manifest stands: %+v", got)
	}
}
