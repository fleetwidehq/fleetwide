//go:build telemetry

package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// The collector polls the application, keeps what the app declared and posts
// it. Apply(nil) stops it.
func TestCollectorScrapesAndStops(t *testing.T) {
	var scrapes atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrapes.Add(1)
		fmt.Fprintf(w, "queue_depth{queue=\"jobs\"} %d\ngo_goroutines 7\n", scrapes.Load())
	}))
	defer app.Close()

	var mu sync.Mutex
	var got []v1.MetricPoint
	posted := make(chan struct{}, 8)
	c := New(Config{
		Post: func(_ context.Context, p []v1.MetricPoint) (*v1.MetricsResponse, error) {
			mu.Lock()
			got = append(got, p...)
			mu.Unlock()
			select {
			case posted <- struct{}{}:
			default:
			}
			return &v1.MetricsResponse{Stored: len(p)}, nil
		},
		Log: func(string, ...any) {},
	})
	defer c.Close()

	decl := &v1.Telemetry{
		Scrape:  []v1.ScrapeTarget{{Name: "app", Port: portOf(t, app.URL), Path: "/metrics", IntervalS: 1}},
		Metrics: []v1.MetricDecl{{Name: "queue_depth"}},
	}
	c.Apply(decl)
	select {
	case <-posted:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was posted within 5s")
	}
	mu.Lock()
	first := got[0]
	mu.Unlock()
	if first.Name != "queue_depth" || first.Labels["queue"] != "jobs" || first.At.IsZero() {
		t.Fatalf("point: %+v", first)
	}
	for _, p := range got {
		if p.Name == "go_goroutines" {
			t.Fatal("an undeclared metric must never leave the container")
		}
	}

	// switching telemetry off stops the polling; re-applying the same
	// declaration afterwards starts it again
	c.Apply(nil)
	before := scrapes.Load()
	time.Sleep(500 * time.Millisecond)
	if after := scrapes.Load(); after != before {
		t.Fatalf("still scraping after Apply(nil): %d → %d", before, after)
	}
	c.Apply(decl)
	deadline := time.Now().Add(5 * time.Second)
	for scrapes.Load() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if scrapes.Load() == before {
		t.Fatal("re-applying the declaration did not restart the scraper")
	}
}

// Apply runs on every heartbeat, so an unchanged declaration must not restart
// the scrapers — and a changed one must.
func TestApplyIsIdempotent(t *testing.T) {
	decl := &v1.Telemetry{
		Scrape:  []v1.ScrapeTarget{{Name: "app", Port: 9999, IntervalS: 30}},
		Metrics: []v1.MetricDecl{{Name: "queue_depth"}},
	}
	same := &v1.Telemetry{
		Scrape:  []v1.ScrapeTarget{{Name: "app", Port: 9999, IntervalS: 30}},
		Metrics: []v1.MetricDecl{{Name: "queue_depth"}},
	}
	if fingerprint(decl) != fingerprint(same) {
		t.Fatal("the same declaration must fingerprint the same")
	}
	changed := *decl
	changed.Scrape = []v1.ScrapeTarget{{Name: "app", Port: 9999, IntervalS: 60}}
	if fingerprint(&changed) == fingerprint(decl) {
		t.Fatal("a changed interval must fingerprint differently")
	}
	metricAdded := *decl
	metricAdded.Metrics = append(append([]v1.MetricDecl{}, decl.Metrics...), v1.MetricDecl{Name: "requests_total"})
	if fingerprint(&metricAdded) == fingerprint(decl) {
		t.Fatal("a newly declared metric must fingerprint differently")
	}
	if fingerprint(nil) != "" {
		t.Fatal("no declaration fingerprints as empty")
	}
}

// Endpoints configured with nothing declared would post points the console
// drops, so the collector does not start at all.
func TestNoDeclaredMetricsMeansNoScraping(t *testing.T) {
	var scrapes atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrapes.Add(1)
		fmt.Fprintln(w, "queue_depth 1")
	}))
	defer app.Close()
	c := New(Config{Post: func(context.Context, []v1.MetricPoint) (*v1.MetricsResponse, error) {
		t.Error("nothing should be posted")
		return nil, nil
	}, Log: func(string, ...any) {}})
	defer c.Close()
	c.Apply(&v1.Telemetry{Scrape: []v1.ScrapeTarget{{Name: "app", Port: portOf(t, app.URL), IntervalS: 1}}})
	time.Sleep(500 * time.Millisecond)
	if scrapes.Load() != 0 {
		t.Fatalf("scraped %d times with nothing declared", scrapes.Load())
	}
}

func portOf(t *testing.T, url string) int {
	t.Helper()
	var p int
	if _, err := fmt.Sscanf(url, "http://127.0.0.1:%d", &p); err != nil {
		t.Fatalf("port of %s: %v", url, err)
	}
	return p
}
