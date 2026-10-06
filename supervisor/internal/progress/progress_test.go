package progress

import (
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

func TestTracker(t *testing.T) {
	var got v1.Download
	var took time.Duration
	n := 0
	tr := New(func(d v1.Download, dur time.Duration) { got, took, n = d, dur, n+1 })

	if tr.State() != nil {
		t.Fatal("idle tracker must report nothing")
	}
	tr.Begin("asset", "gemma", 12)
	body, err := io.ReadAll(Wrap(strings.NewReader("hello world!"), tr))
	if err != nil || len(body) != 12 {
		t.Fatalf("read through the wrapper: %v %q", err, body)
	}
	st := tr.State()
	if st == nil || st.Done != 12 || st.Total != 12 || st.Name != "gemma" || st.What != "asset" {
		t.Fatalf("state: %+v", st)
	}
	if st.Pct() != 100 {
		t.Fatalf("pct: %d", st.Pct())
	}
	st.Done = 0 // the caller holds a copy, not the tracker's own record
	if tr.State().Done != 12 {
		t.Fatal("State must hand out a copy")
	}
	tr.End()
	if n != 1 || got.Done != 12 || took <= 0 {
		t.Fatalf("done callback: n=%d got=%+v took=%v", n, got, took)
	}
	if tr.State() != nil {
		t.Fatal("End must clear the download")
	}

	// everything cached: nothing crossed the network, so nothing is announced
	tr.Begin("image", "acme/app", 500)
	tr.End()
	if n != 1 {
		t.Fatalf("a download that moved no bytes must not be announced, n=%d", n)
	}

	// a nil tracker and a nil reporter are both usable
	var nilT *Tracker
	nilT.Begin("asset", "x", 1)
	nilT.Add(5)
	nilT.End()
	if nilT.State() != nil {
		t.Fatal("nil tracker")
	}
	if _, err := io.ReadAll(Wrap(strings.NewReader("abc"), nil)); err != nil {
		t.Fatalf("nil reporter: %v", err)
	}

	// an unknown total has no percentage to show
	tr.Begin("asset", "git-bundle", 0)
	tr.Add(10)
	if p := tr.State().Pct(); p != -1 {
		t.Fatalf("unknown total must be -1, got %d", p)
	}
}
