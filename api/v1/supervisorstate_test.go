package v1

import "testing"

// An older supervisor reports a single "tunnel" capability and no variant;
// Normalize maps it to logs + access on the developer image.
func TestNormalizeLegacyHeartbeat(t *testing.T) {
	st := SupervisorState{Capabilities: []string{"tunnel"}}
	st.Normalize()
	if !st.Can(CapAccess) || !st.Can(CapLogs) {
		t.Fatalf("legacy tunnel capability must become logs+access, got %v", st.Capabilities)
	}
	if st.Can("tunnel") {
		t.Fatalf("the legacy name must not survive: %v", st.Capabilities)
	}
	if st.Variant != VariantDeveloper {
		t.Fatalf("variant = %q, want %q", st.Variant, VariantDeveloper)
	}
}

// An older supervisor reports the state volume's bytes but no percentage;
// Normalize derives it.
func TestNormalizeDerivesStateVolumePercent(t *testing.T) {
	st := SupervisorState{Variant: VariantSlim, Metrics: &Metrics{DataUsed: 1 << 30, DataTotal: 4 << 30}}
	st.Normalize()
	if st.Metrics.DataPercent != 25 {
		t.Fatalf("data_pct = %v, want 25", st.Metrics.DataPercent)
	}
	// nothing to derive from, and nothing invented
	empty := SupervisorState{Metrics: &Metrics{}}
	empty.Normalize()
	if empty.Metrics.DataPercent != 0 {
		t.Fatalf("a container with no state volume must report no percentage, got %v", empty.Metrics.DataPercent)
	}
}

// Older names of the developer image are normalized to the current one.
func TestNormalizeRenamesTheDeveloperVariant(t *testing.T) {
	for _, old := range []string{"dev", "development"} {
		st := SupervisorState{Variant: old, Capabilities: []string{CapLogs, CapAccess, CapTelemetry}}
		st.Normalize()
		if st.Variant != VariantDeveloper {
			t.Fatalf("variant %q → %q, want %q", old, st.Variant, VariantDeveloper)
		}
	}
}

// A current supervisor is left exactly as it reported: Normalize must not
// invent a capability, and must not overwrite a variant the supervisor chose.
func TestNormalizeLeavesCurrentSupervisors(t *testing.T) {
	st := SupervisorState{Variant: VariantTelemetry, Capabilities: []string{CapTelemetry}}
	st.Normalize()
	if st.Variant != VariantTelemetry || len(st.Capabilities) != 1 || st.Capabilities[0] != CapTelemetry {
		t.Fatalf("unchanged supervisor was rewritten: %q %v", st.Variant, st.Capabilities)
	}
	slim := SupervisorState{Variant: VariantSlim}
	slim.Normalize()
	if len(slim.Capabilities) != 0 || slim.Variant != VariantSlim {
		t.Fatalf("slim supervisor was rewritten: %q %v", slim.Variant, slim.Capabilities)
	}
}
