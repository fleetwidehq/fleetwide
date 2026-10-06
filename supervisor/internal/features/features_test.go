package features

import (
	"strings"
	"testing"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// The default test build carries no build tags, so this binary is the slim
// image: it must report that, and no feature may be live.
func TestSlimBuild(t *testing.T) {
	if got := Variant(); got != v1.VariantSlim {
		t.Fatalf("Variant() = %q, want %q (this package is built without tags)", got, v1.VariantSlim)
	}
	for _, f := range v1.Features {
		if Has(f) {
			t.Fatalf("%s must not be live in a slim build", f)
		}
	}
}

// Every published variant's feature set has to name a real feature, otherwise
// a typo in a build tag would silently produce a "custom" image.
func TestVariantFeaturesAreKnown(t *testing.T) {
	for variant, feats := range v1.VariantFeatures {
		for _, f := range feats {
			if !has(v1.Features, f) {
				t.Fatalf("variant %s lists unknown feature %q", variant, f)
			}
		}
	}
	if got := v1.VariantFor(v1.CapTelemetry); got != v1.VariantTelemetry {
		t.Fatalf("telemetry alone wants the telemetry image, got %q", got)
	}
	if got := v1.VariantFor(v1.CapLogs); got != v1.VariantDeveloper {
		t.Fatalf("logs needs the dev image, got %q", got)
	}
	if got := v1.VariantFor(); got != v1.VariantSlim {
		t.Fatalf("no feature wants the slim image, got %q", got)
	}
}

// A supervisor reports the features of the image it runs, in a stable order,
// and nothing in the environment can change that.
func TestLiveIsTheImage(t *testing.T) {
	old := compiled
	compiled = []string{v1.CapTelemetry, v1.CapAccess, v1.CapLogs} // any order
	t.Cleanup(func() { compiled = old })
	if got := strings.Join(Live(), ","); got != "logs,access,telemetry" {
		t.Fatalf("Live() = %q, want every feature in v1.Features order", got)
	}
	t.Setenv("FLEETWIDE_ACCESS", "0")
	t.Setenv("FLEETWIDE_LOGS", "0")
	if got := strings.Join(Live(), ","); got != "logs,access,telemetry" {
		t.Fatalf("the environment must not change what the supervisor can do, got %q", got)
	}
	if !Has(v1.CapAccess) || Variant() != v1.VariantDeveloper {
		t.Fatalf("this is the developer image whatever the environment says: %v %s", Live(), Variant())
	}
}
