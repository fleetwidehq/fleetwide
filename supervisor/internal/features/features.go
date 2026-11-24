// Package features says what this supervisor binary can do. Optional features
// (telemetry, access, logs) are compiled in with build tags; the resulting set
// is fixed per image and reported at enrollment and on every heartbeat.
package features

import (
	"sort"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// compiled is filled by the build-tag files in this package.
var compiled []string

func add(f string) { compiled = append(compiled, f) }

// Compiled is what this image was built with.
func Compiled() []string { return append([]string(nil), compiled...) }

// Variant names the image whose feature set matches, or "custom".
func Variant() string {
	for _, name := range []string{v1.VariantSlim, v1.VariantTelemetry, v1.VariantDeveloper} {
		if same(compiled, v1.VariantFeatures[name]) {
			return name
		}
	}
	return "custom"
}

// Live is what this container can do, as a list in v1.Features order.
func Live() []string {
	var out []string
	for _, f := range v1.Features {
		if has(compiled, f) {
			out = append(out, f)
		}
	}
	return out
}

// Has reports whether this image carries a feature.
func Has(f string) bool { return has(compiled, f) }

func has(list []string, f string) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
