//go:build linux

// Package mounts lists the mount points visible to this process so the
// unpacker can leave them alone when extracting over "/".
package mounts

import (
	"bufio"
	"os"
	"strings"
)

// Points returns every mount point in /proc/self/mountinfo, with octal
// escapes decoded. "/" itself is included.
func Points() ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
		if len(fields) < 5 {
			continue
		}
		out = append(out, unescape(fields[4]))
	}
	return out, sc.Err()
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v byte
			ok := true
			for j := 1; j <= 3; j++ {
				c := s[i+j]
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + (c - '0')
			}
			if ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
