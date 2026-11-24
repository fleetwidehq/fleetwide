//go:build telemetry

package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// New returns the real collector: this image was built with the telemetry
// feature.
func New(cfg Config) Collector {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	return &collector{cfg: cfg, hc: &http.Client{Timeout: scrapeTimeout}}
}

type collector struct {
	cfg     Config
	hc      *http.Client
	mu      sync.Mutex
	cur     string             // fingerprint of the applied declaration
	stop    context.CancelFunc // stops every scrape goroutine
	wg      sync.WaitGroup
	missing map[string][]string // endpoint → declared metrics its last scrape did not expose
}

// Missing lists declared metrics no endpoint exposed at its last scrape.
func (c *collector) Missing() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := map[string]bool{}
	for _, names := range c.missing {
		for _, n := range names {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// noteMissing records what a successful scrape of target did not find and
// logs the change once.
func (c *collector) noteMissing(target v1.ScrapeTarget, declared map[string]bool, seen map[string]bool, series int) {
	var missing []string
	for n := range declared {
		if !seen[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	c.mu.Lock()
	if c.missing == nil {
		c.missing = map[string][]string{}
	}
	prev, had := c.missing[target.Name]
	c.missing[target.Name] = missing
	c.mu.Unlock()
	if had && strings.Join(prev, ",") == strings.Join(missing, ",") {
		return
	}
	if len(missing) == 0 {
		c.cfg.Log("telemetry: %s: %s exposes %d series; all %d declared metrics present", target.Name, target.URL(), series, len(declared))
		return
	}
	c.cfg.Log("telemetry: %s: %s exposes %d series; declared but not exported: %s", target.Name, target.URL(), series, strings.Join(missing, ", "))
}

// Apply starts, replaces or stops the scrapers. It is called from the
// heartbeat loop every beat, so an unchanged declaration must cost nothing.
func (c *collector) Apply(t *v1.Telemetry) {
	want := fingerprint(t)
	c.mu.Lock()
	if want == c.cur {
		c.mu.Unlock()
		return
	}
	if c.stop != nil {
		c.stop()
	}
	c.mu.Unlock()
	c.wg.Wait() // the old scrapers are gone before the new ones start

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur, c.stop, c.missing = want, nil, nil
	if t == nil || len(t.Scrape) == 0 {
		c.cfg.Log("telemetry: nothing to scrape")
		return
	}
	declared := map[string]bool{}
	for _, m := range t.Metrics {
		declared[m.Name] = true
	}
	if len(declared) == 0 {
		// Scraping with nothing declared would post points the console drops.
		c.cfg.Log("telemetry: %d endpoint(s) configured but no metrics declared; not scraping", len(t.Scrape))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.stop = cancel
	for _, target := range t.Scrape {
		c.wg.Add(1)
		go func(target v1.ScrapeTarget) {
			defer c.wg.Done()
			c.run(ctx, target, declared)
		}(target)
	}
	c.cfg.Log("telemetry: scraping %d endpoint(s) for %d declared metric(s)", len(t.Scrape), len(declared))
}

func (c *collector) Close() {
	c.mu.Lock()
	if c.stop != nil {
		c.stop()
		c.stop = nil
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// run scrapes one endpoint until the context is cancelled. The first scrape
// is immediate; failures are logged once per run of failures, not once per tick.
func (c *collector) run(ctx context.Context, target v1.ScrapeTarget, declared map[string]bool) {
	t := time.NewTicker(target.Interval())
	defer t.Stop()
	var lastErr string
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
		points, err := c.scrape(ctx, target, declared)
		if err != nil {
			if msg := err.Error(); msg != lastErr {
				lastErr = msg
				c.cfg.Log("telemetry: %s: %v", target.Name, err)
			}
			continue
		}
		lastErr = ""
		if len(points) == 0 {
			continue
		}
		resp, err := c.cfg.Post(ctx, points)
		if err != nil {
			if ctx.Err() == nil {
				c.cfg.Log("telemetry: %s: posting %d point(s): %v", target.Name, len(points), err)
			}
			continue
		}
		if resp != nil && resp.Stored == 0 && resp.Reason != "" {
			c.cfg.Log("telemetry: %s: the console kept nothing (%s)", target.Name, resp.Reason)
		}
	}
}

// scrape fetches one endpoint and keeps the declared metrics.
func (c *collector) scrape(ctx context.Context, target v1.ScrapeTarget, declared map[string]bool) ([]v1.MetricPoint, error) {
	ctx, cancel := context.WithTimeout(ctx, scrapeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain;version=0.0.4,*/*;q=0.1")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", target.URL(), resp.StatusCode)
	}
	at := time.Now().UTC()
	seen := map[string]bool{}
	points := parsePrometheus(resp.Body, func(n string) bool { return declared[n] }, v1.MaxScrapePoints, seen)
	for i := range points {
		points[i].At = at
	}
	c.noteMissing(target, declared, seen, len(seen))
	return points, nil
}

// fingerprint identifies a declaration; it covers every field the scrapers
// use, so only a real change restarts them.
func fingerprint(t *v1.Telemetry) string {
	if t == nil {
		return ""
	}
	var b []byte
	for _, s := range t.Scrape {
		b = append(b, fmt.Sprintf("%s|%s|%s;", s.Name, s.URL(), s.Interval())...)
	}
	b = append(b, '#')
	for _, m := range t.Metrics {
		b = append(b, m.Name...)
		b = append(b, ',')
	}
	return string(b)
}
