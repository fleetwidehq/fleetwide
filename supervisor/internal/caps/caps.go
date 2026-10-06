// Package caps names Linux capabilities and reads the process's own from
// /proc/self/status, so the supervisor can report which of the capabilities
// it needs to extract images in place it holds and which it lacks.
package caps

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Mask is a set of capabilities, bit n for capability number n.
type Mask uint64

// Capability numbers the supervisor cares about (linux/capability.h).
const (
	Chown       = 0
	DacOverride = 1
	Fowner      = 3
	Fsetid      = 4
	Kill        = 5
	Setgid      = 6
	Setuid      = 7
	Mknod       = 27
	Setfcap     = 31
)

var names = [...]string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
	"setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
	"ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
	"sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
	"lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
	"wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
}

// Bit is the mask of one capability.
func Bit(n int) Mask { return Mask(1) << uint(n) }

// Required is what extracting an image over "/" and starting the app as its
// USER cannot do without: root-owned paths written with the image's uids,
// modes on files the supervisor does not own, setuid bits kept, the user switch,
// signals to the app. Missing one of these, updates fail.
var Required = Bit(Chown) | Bit(DacOverride) | Bit(Fowner) | Bit(Fsetid) | Bit(Setuid) | Bit(Setgid) | Bit(Kill)

// Optional is what makes extraction byte-faithful but not what makes it
// work: without MKNOD device nodes in a layer are skipped, without SETFCAP
// file capabilities in a layer are not written and the image's binaries run
// without them. Docker and containerd grant both by default; CRI-O's
// default set has neither.
var Optional = Bit(Mknod) | Bit(Setfcap)

// Names lists the capabilities in m, lowest first, as capsh prints them.
func (m Mask) Names() []string {
	var out []string
	for n := 0; n < 64; n++ {
		if m&Bit(n) == 0 {
			continue
		}
		if n < len(names) {
			out = append(out, names[n])
		} else {
			out = append(out, "cap_"+strconv.Itoa(n))
		}
	}
	return out
}

// String is the names joined with commas, or "none".
func (m Mask) String() string {
	if m == 0 {
		return "none"
	}
	return strings.Join(m.Names(), ",")
}

// Effective is what the process holds now, from /proc/self/status; ok is
// false where that cannot be read (not Linux).
func Effective() (Mask, bool) { return statusSet("CapEff:") }

// Missing is the part of Required and Optional the process does not hold,
// returned separately. Both zero where the status file cannot be read.
func Missing() (required, optional Mask) {
	eff, ok := Effective()
	if !ok {
		return 0, 0
	}
	return Required &^ eff, Optional &^ eff
}

func statusSet(key string) (Mask, bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return Mask(n), err == nil
		}
	}
	return 0, false
}
