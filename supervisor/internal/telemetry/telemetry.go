package telemetry

import (
	"context"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// Config for a Collector.
type Config struct {
	// Post sends a batch to the console. The collector calls it from its own
	// goroutine, never from the heartbeat path.
	Post func(ctx context.Context, points []v1.MetricPoint) (*v1.MetricsResponse, error)
	Log  func(format string, args ...any)
}

// Collector scrapes the application's endpoints on the schedule the console
// sends. Apply(nil) stops everything.
type Collector interface {
	Apply(t *v1.Telemetry)
	// Missing lists declared metrics the last scrape of each endpoint did not
	// find, so the console can say so instead of showing an empty chart.
	Missing() []string
	Close()
}

// scrapeTimeout bounds one request to the application. An endpoint that hangs
// must not hold a scrape goroutine past its own interval.
const scrapeTimeout = 10 * time.Second
