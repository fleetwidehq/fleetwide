// Package hostfacts reports the machine a supervisor runs on as its
// container sees it: architecture, CPUs and memory within the container's
// limits, free space on the state volume, and whether a TPM is visible.
package hostfacts

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/fsinfo"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/metrics"
)

// TPM device nodes, the kernel resource manager first.
var tpmNodes = []string{"/dev/tpmrm0", "/dev/tpm0"}

// Detect reads the facts. stateDir is the volume whose free space is
// reported; platform is "os/arch[/variant]".
func Detect(stateDir, platform string) v1.HostFacts {
	f := v1.HostFacts{TPM: tpm(tpmNodes)}
	f.OS, f.Arch, _ = strings.Cut(platform, "/")
	cores, mem := metrics.Limits()
	f.CPUs = wholeCPUs(cores)
	f.MemoryMB = int64(mem >> 20)
	if free, _, ok := fsinfo.Free(stateDir); ok {
		f.DiskFreeMB = int64(free >> 20)
	}
	return f
}

// wholeCPUs rounds a CPU limit down to whole CPUs, never below one.
func wholeCPUs(cores float64) int {
	if cores < 1 {
		return 1
	}
	return int(cores)
}

func tpm(nodes []string) string {
	denied := false
	for _, p := range nodes {
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err == nil {
			f.Close()
			return "present"
		}
		if errors.Is(err, fs.ErrPermission) {
			denied = true
		}
	}
	if denied {
		return "denied"
	}
	return ""
}
