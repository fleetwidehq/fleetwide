// Package progress reports what the supervisor is downloading while it
// downloads it: fetchers feed a tracker, and the heartbeat carries bytes done
// and total.
package progress

import (
	"io"
	"sync"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// Reporter is what a fetcher tells about the download it is running. A nil
// Reporter is valid and ignored, so callers never branch.
type Reporter interface {
	Begin(what, name string, total int64)
	Add(n int64)
	End()
}

// Tracker holds the download in flight. One per supervisor; fetchers call Begin,
// Add and End, the heartbeat reads State.
type Tracker struct {
	mu   sync.Mutex
	cur  *v1.Download
	done func(v1.Download, time.Duration)
}

// New returns a tracker. done, when set, is called after each finished
// download with what was fetched and how long it took.
func New(done func(v1.Download, time.Duration)) *Tracker { return &Tracker{done: done} }

func (t *Tracker) Begin(what, name string, total int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.cur = &v1.Download{What: what, Name: name, Total: total, StartedAt: time.Now()}
	t.mu.Unlock()
}

func (t *Tracker) Add(n int64) {
	if t == nil || n <= 0 {
		return
	}
	t.mu.Lock()
	if t.cur != nil {
		t.cur.Done += n
	}
	t.mu.Unlock()
}

// End clears the current download and reports it. A download that moved no
// bytes (everything was cached) is dropped rather than announced.
func (t *Tracker) End() {
	if t == nil {
		return
	}
	t.mu.Lock()
	cur := t.cur
	t.cur = nil
	done := t.done
	t.mu.Unlock()
	if cur != nil && done != nil && cur.Done > 0 {
		done(*cur, time.Since(cur.StartedAt))
	}
}

// State is a copy of the download in flight, or nil when idle.
func (t *Tracker) State() *v1.Download {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil {
		return nil
	}
	cp := *t.cur
	return &cp
}

// Wrap counts the bytes read through r. It is safe with a nil reporter.
func Wrap(r io.Reader, rep Reporter) io.Reader {
	if rep == nil {
		return r
	}
	return &counter{r: r, rep: rep}
}

type counter struct {
	r   io.Reader
	rep Reporter
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.rep.Add(int64(n))
	return n, err
}
