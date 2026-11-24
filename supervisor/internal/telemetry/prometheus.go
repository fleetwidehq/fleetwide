// Package telemetry scrapes the application's own metrics endpoint and hands
// the readings to the console. It is compiled in only with the telemetry
// build tag; otherwise the stub in this package does nothing.
package telemetry

import (
	"bufio"
	"io"
	"math"
	"strconv"
	"strings"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// parsePrometheus reads the text exposition format and returns the points
// whose names the app declared. Everything else — help and type comments,
// undeclared metrics, NaN and infinities — is skipped.
//
// The grammar handled here is one sample per line:
//
//	name{label="value",other="v"} 12.5 [unix-millis]
//
// Histogram and summary children (_bucket, _sum, _count) arrive as ordinary
// names; declare the child you want and it is kept like any other.
// When seen is not nil, every sample name in the exposition is recorded in
// it, declared or not.
func parsePrometheus(r io.Reader, want func(string) bool, limit int, seen map[string]bool) []v1.MetricPoint {
	var out []v1.MetricPoint
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() && len(out) < limit {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, rest := line, ""
		labels := map[string]string(nil)
		if i := strings.IndexAny(line, "{ \t"); i >= 0 {
			name, rest = line[:i], line[i:]
		}
		if seen != nil {
			seen[name] = true
		}
		if !want(name) {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "{") {
			end := closingBrace(rest)
			if end < 0 {
				continue // truncated line
			}
			labels = parseLabels(rest[1:end])
			rest = rest[end+1:]
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue // a metric with no value yet says nothing worth storing
		}
		out = append(out, v1.MetricPoint{Name: name, Value: v, Labels: labels})
	}
	return out
}

// closingBrace finds the } that ends a label set, ignoring braces inside
// quoted values.
func closingBrace(s string) int {
	inQuote, esc := false, false
	for i := 0; i < len(s); i++ {
		switch {
		case esc:
			esc = false
		case s[i] == '\\' && inQuote:
			esc = true
		case s[i] == '"':
			inQuote = !inQuote
		case s[i] == '}' && !inQuote:
			return i
		}
	}
	return -1
}

// parseLabels reads name="value" pairs. Malformed pairs are skipped rather
// than failing the line.
func parseLabels(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, ", \t")
		eq := strings.Index(s, "=")
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[:eq])
		s = strings.TrimLeft(s[eq+1:], " \t")
		if len(s) == 0 || s[0] != '"' {
			break
		}
		val, rest, ok := readQuoted(s)
		if !ok {
			break
		}
		if key != "" {
			out[key] = val
		}
		s = rest
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readQuoted reads a quoted label value with the escapes the format allows.
func readQuoted(s string) (val, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", false
}
