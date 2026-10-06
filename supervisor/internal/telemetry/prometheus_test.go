package telemetry

import (
	"strings"
	"testing"
)

const exposition = `# HELP queue_depth Jobs waiting
# TYPE queue_depth gauge
queue_depth{queue="jobs",shard="a"} 12
queue_depth{queue="mail"} 9.5
queue_depth 1
requests_total 1.0e3 1700000000000
go_goroutines 41
broken_metric NaN
missing_value{a="b"}
odd{label="with } brace",other="x"} 7
escaped{path="a\"b",nl="x\ny"} 3
`

func TestParsePrometheus(t *testing.T) {
	want := map[string]bool{"queue_depth": true, "requests_total": true, "broken_metric": true, "missing_value": true, "odd": true, "escaped": true}
	pts := parsePrometheus(strings.NewReader(exposition), func(n string) bool { return want[n] }, 100, nil)

	// go_goroutines is not declared, NaN says nothing, and a line with no
	// value is not a reading.
	names := map[string]int{}
	for _, p := range pts {
		names[p.Name]++
	}
	if names["go_goroutines"] != 0 || names["broken_metric"] != 0 || names["missing_value"] != 0 {
		t.Fatalf("undeclared, NaN and value-less lines must be skipped: %v", names)
	}
	if names["queue_depth"] != 3 || names["requests_total"] != 1 {
		t.Fatalf("declared metrics: %v", names)
	}
	by := map[string]float64{}
	for _, p := range pts {
		by[p.Name+"|"+p.Labels["queue"]+p.Labels["label"]+p.Labels["path"]] = p.Value
	}
	if by["queue_depth|jobs"] != 12 || by["queue_depth|mail"] != 9.5 || by["queue_depth|"] != 1 {
		t.Fatalf("label sets and values: %v", by)
	}
	if by["requests_total|"] != 1000 {
		t.Fatalf("a scientific-notation value with a trailing timestamp: %v", by)
	}
	// a brace inside a quoted value must not end the label set
	if by["odd|with } brace"] != 7 {
		t.Fatalf("brace inside a label value: %v", by)
	}
	if by[`escaped|a"b`] != 3 {
		t.Fatalf("escaped quote in a label value: %v", by)
	}
	for _, p := range pts {
		if p.Name == "escaped" && p.Labels["nl"] != "x\ny" {
			t.Fatalf(`\n escape: %q`, p.Labels["nl"])
		}
		if p.Name == "queue_depth" && p.Labels["shard"] == "a" && p.Labels["queue"] != "jobs" {
			t.Fatalf("two labels on one sample: %v", p.Labels)
		}
	}
}

// A big exporter must not turn into a big request: the scrape stops at the
// limit rather than posting everything it found.
func TestParseStopsAtLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("m 1\n")
	}
	if got := len(parsePrometheus(strings.NewReader(b.String()), func(string) bool { return true }, 10, nil)); got != 10 {
		t.Fatalf("limit ignored: got %d points", got)
	}
}

func TestParseEmptyAndComments(t *testing.T) {
	if got := parsePrometheus(strings.NewReader("\n# HELP x y\n# TYPE x gauge\n\n"), func(string) bool { return true }, 10, nil); len(got) != 0 {
		t.Fatalf("comments and blank lines are not readings: %v", got)
	}
}
