// Package identity derives a best-effort fingerprint of the container the
// supervisor runs in: pod UID, container id, hostname and host ids. The hostname
// is the container's identity in its deployment (set --hostname where a
// recreated container should take over its record); the rest is reported for
// display and conflict detection.
package identity

import (
	"os"
	"regexp"
	"strings"
)

// Fingerprint is what could be detected; empty fields were not available.
type Fingerprint struct {
	Hostname    string `json:"hostname,omitempty"`
	ContainerID string `json:"container_id,omitempty"` // 64-hex docker/containerd id
	PodUID      string `json:"pod_uid,omitempty"`      // kubernetes pod UID
	MachineID   string `json:"machine_id,omitempty"`   // /etc/machine-id (host or image), if present
	BootID      string `json:"boot_id,omitempty"`      // host kernel boot id: same for every container on the node
}

var (
	hex64      = regexp.MustCompile(`([0-9a-f]{64})`)
	podUIDRE   = regexp.MustCompile(`/pods/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/`)
	podUIDCgRE = regexp.MustCompile(`/kubepods[^ ]*?pod([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})`)
)

// Detect reads /proc and /etc. It never fails; missing sources stay empty.
func Detect() Fingerprint {
	var f Fingerprint
	f.Hostname, _ = os.Hostname()
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	mountinfo, _ := os.ReadFile("/proc/self/mountinfo")
	f.ContainerID, f.PodUID = Parse(string(cgroup), string(mountinfo))
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		f.MachineID = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		f.BootID = strings.TrimSpace(string(b))
	}
	return f
}

// Parse extracts the container id and pod UID from cgroup and mountinfo text.
func Parse(cgroup, mountinfo string) (containerID, podUID string) {
	for _, src := range []string{cgroup, mountinfo} {
		for _, line := range strings.Split(src, "\n") {
			if containerID == "" {
				// docker: /docker/<id>, /docker/containers/<id>/…; containerd/cri: cri-containerd-<id>.scope, <id>.scope
				if strings.Contains(line, "docker") || strings.Contains(line, "containerd") || strings.Contains(line, "kubepods") || strings.Contains(line, ".scope") {
					if m := hex64.FindStringSubmatch(line); m != nil {
						containerID = m[1]
					}
				}
			}
			if podUID == "" {
				if m := podUIDRE.FindStringSubmatch(line); m != nil {
					podUID = m[1]
				} else if m := podUIDCgRE.FindStringSubmatch(line); m != nil {
					podUID = strings.ReplaceAll(m[1], "_", "-")
				}
			}
		}
	}
	return
}

// Runtime guesses where the container runs: k8s when a pod UID is visible, else docker.
func (f Fingerprint) Runtime() string {
	if f.PodUID != "" {
		return "k8s"
	}
	if f.ContainerID != "" {
		return "docker"
	}
	return "other"
}
