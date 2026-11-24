package hostfacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWholeCPUs(t *testing.T) {
	for in, want := range map[float64]int{0: 1, 0.5: 1, 1: 1, 1.9: 1, 2: 2, 3.5: 3} {
		if got := wholeCPUs(in); got != want {
			t.Errorf("wholeCPUs(%v) = %d, want %d", in, got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	f := Detect(t.TempDir(), "linux/arm/v7")
	if f.OS != "linux" || f.Arch != "arm/v7" {
		t.Fatalf("platform split: os=%q arch=%q", f.OS, f.Arch)
	}
	if f.CPUs < 1 {
		t.Fatalf("cpus = %d", f.CPUs)
	}
	if f.DiskFreeMB <= 0 {
		t.Fatalf("disk free = %d", f.DiskFreeMB)
	}
}

func TestTPM(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "none")
	if got := tpm([]string{missing}); got != "" {
		t.Fatalf("missing node: %q", got)
	}
	node := filepath.Join(dir, "tpm")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := tpm([]string{missing, node}); got != "present" {
		t.Fatalf("readable node: %q", got)
	}
	if os.Geteuid() != 0 {
		os.Chmod(node, 0)
		if got := tpm([]string{node}); got != "denied" {
			t.Fatalf("unreadable node: %q", got)
		}
	}
}
