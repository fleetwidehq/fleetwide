// Package metrics samples CPU, memory and disk usage of the container the
// supervisor runs in. It reads cgroup v2 first (what Docker, containerd and
// Kubernetes give a container today), falls back to cgroup v1, and finally to
// /proc when the supervisor is not confined to a cgroup at all. Everything is
// best-effort: a missing file leaves that field zero rather than failing.
package metrics

import (
	"github.com/fleetwidehq/fleetwide/supervisor/internal/fsinfo"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

const cg2 = "/sys/fs/cgroup"

// Sampler keeps the previous CPU reading so it can turn cumulative CPU time
// into a utilization percentage over the interval between two calls.
type Sampler struct {
	mu       sync.Mutex
	lastCPU  uint64 // cumulative usage in microseconds
	lastAt   time.Time
	lastPct  float64
	DataDir  string // state/cache volume to report separately when it is its own filesystem
	RootPath string // filesystem to report as "disk" (default "/")
}

// Sample reads the current values. The first call reports 0% CPU.
func (s *Sampler) Sample() *v1.Metrics {
	m := &v1.Metrics{Source: "proc"}
	root := s.RootPath
	if root == "" {
		root = "/"
	}
	// memory + cpu time
	var cpuUsec uint64
	if b, err := os.ReadFile(cg2 + "/memory.current"); err == nil {
		m.Source = "cgroup2"
		m.MemUsed = parseUint(string(b))
		m.MemLimit = parseUint(readFile(cg2 + "/memory.max")) // "max" → 0
		// working set: subtract inactive file cache like kubectl top does
		if st := kv(readFile(cg2 + "/memory.stat")); st != nil {
			if f, ok := st["inactive_file"]; ok && f < m.MemUsed {
				m.MemUsed -= f
			}
		}
		if st := kv(readFile(cg2 + "/cpu.stat")); st != nil {
			cpuUsec = st["usage_usec"]
		}
		m.CPUCores = cpuLimitV2(readFile(cg2 + "/cpu.max"))
	} else if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		m.Source = "cgroup1"
		m.MemUsed = parseUint(string(b))
		if lim := parseUint(readFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")); lim < 1<<60 {
			m.MemLimit = lim
		}
		if st := kv(readFile("/sys/fs/cgroup/memory/memory.stat")); st != nil {
			if f, ok := st["total_inactive_file"]; ok && f < m.MemUsed {
				m.MemUsed -= f
			}
		}
		for _, p := range []string{"/sys/fs/cgroup/cpu/cpuacct.usage", "/sys/fs/cgroup/cpuacct/cpuacct.usage", "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage"} {
			if b, err := os.ReadFile(p); err == nil {
				cpuUsec = parseUint(string(b)) / 1000 // ns → µs
				break
			}
		}
		q, per := int64(parseUint(readFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"))), parseUint(readFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us"))
		if q > 0 && per > 0 {
			m.CPUCores = float64(q) / float64(per)
		}
	} else {
		// no cgroup view: whole machine from /proc
		if st := kv(readFile("/proc/meminfo")); st != nil {
			m.MemLimit = st["MemTotal"] * 1024
			m.MemUsed = (st["MemTotal"] - st["MemAvailable"]) * 1024
		}
		cpuUsec = procCPUUsec()
	}
	if m.MemLimit == 0 {
		// unlimited container: the node's memory is the ceiling
		if st := kv(readFile("/proc/meminfo")); st != nil {
			m.MemLimit = st["MemTotal"] * 1024
		}
	}
	if m.CPUCores == 0 {
		m.CPUCores = float64(numCPU())
	}
	if m.MemLimit > 0 {
		m.MemPercent = round1(float64(m.MemUsed) / float64(m.MemLimit) * 100)
	}

	// cpu percent of the limit over the sampling interval
	now := time.Now()
	s.mu.Lock()
	if !s.lastAt.IsZero() && cpuUsec >= s.lastCPU && now.After(s.lastAt) {
		el := now.Sub(s.lastAt).Seconds()
		used := float64(cpuUsec-s.lastCPU) / 1e6 // cpu-seconds
		if el > 0 && m.CPUCores > 0 {
			s.lastPct = round1(used / el / m.CPUCores * 100)
		}
	}
	s.lastCPU, s.lastAt = cpuUsec, now
	m.CPUPercent = s.lastPct
	s.mu.Unlock()

	// Disk is the state volume, and only when it is a filesystem of its own;
	// "/" (the host's overlay) is never reported.
	if s.DataDir != "" {
		var a, b syscall.Stat_t
		if syscall.Stat(root, &a) == nil && syscall.Stat(s.DataDir, &b) == nil && a.Dev != b.Dev {
			if used, total, ok := fsinfo.Usage(s.DataDir); ok {
				m.DataUsed, m.DataTotal = used, total
				if total > 0 {
					m.DataPercent = round1(float64(used) / float64(total) * 100)
				}
			}
		}
	}
	return m
}

// OOMKills returns the cgroup's oom_kill counter (v2 memory.events or v1
// memory.oom_control), or -1 when it is not visible.
func OOMKills() int64 {
	if st := kv(readFile(cg2 + "/memory.events")); st != nil {
		if v, ok := st["oom_kill"]; ok {
			return int64(v)
		}
	}
	if st := kv(readFile("/sys/fs/cgroup/memory/memory.oom_control")); st != nil {
		if v, ok := st["oom_kill"]; ok {
			return int64(v)
		}
	}
	return -1
}

func cpuLimitV2(s string) float64 {
	f := strings.Fields(s) // "max 100000" | "200000 100000"
	if len(f) != 2 || f[0] == "max" {
		return 0
	}
	q, p := parseUint(f[0]), parseUint(f[1])
	if q == 0 || p == 0 {
		return 0
	}
	return float64(q) / float64(p)
}

func numCPU() int {
	// respect cpuset when present
	if b, err := os.ReadFile(cg2 + "/cpuset.cpus.effective"); err == nil {
		if n := countCPUList(strings.TrimSpace(string(b))); n > 0 {
			return n
		}
	}
	if st := kv(readFile("/proc/stat")); st != nil {
		n := 0
		for k := range st {
			if len(k) > 3 && strings.HasPrefix(k, "cpu") {
				n++
			}
		}
		if n > 0 {
			return n
		}
	}
	return 1
}

func countCPUList(s string) int {
	n := 0
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			continue
		}
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi := parseUint(a), parseUint(b)
			if hi >= lo {
				n += int(hi-lo) + 1
			}
		} else {
			n++
		}
	}
	return n
}

// procCPUUsec is the whole machine's busy time from /proc/stat, in µs.
func procCPUUsec() uint64 {
	for _, line := range strings.Split(readFile("/proc/stat"), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		var busy uint64
		for i, v := range f[1:] {
			if i == 3 || i == 4 { // idle, iowait
				continue
			}
			busy += parseUint(v)
		}
		return busy * 10000 // USER_HZ=100 ticks → µs
	}
	return 0
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// kv parses "key value" lines (cpu.stat, memory.stat, meminfo with a colon).
func kv(s string) map[string]uint64 {
	if s == "" {
		return nil
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		out[strings.TrimSuffix(f[0], ":")] = parseUint(f[1])
	}
	return out
}

func parseUint(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		if f, ferr := strconv.ParseFloat(s, 64); ferr == nil && f > 0 {
			return uint64(f)
		}
		return 0
	}
	return v
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }
