// Package passwd resolves a container USER — "uid", "uid:gid", "name",
// "name:group" — against /etc/passwd and /etc/group, the way a runtime does.
package passwd

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Lookup resolves spec. passwd and group are the file contents (group may be
// nil when spec names no group). A numeric uid absent from passwd gets gid 0,
// as runc does; a numeric gid needs no lookup.
func Lookup(passwd, group io.Reader, spec string) (uid, gid uint32, err error) {
	u, g, hasGroup := strings.Cut(spec, ":")
	var lines []string
	if passwd != nil {
		lines = readLines(passwd)
	}
	if n, perr := strconv.ParseUint(u, 10, 32); perr == nil {
		uid = uint32(n)
		if _, pg, ok := scan(lines, 2, u); ok {
			gid = pg
		} else {
			gid = 0
		}
	} else {
		var ok bool
		if uid, gid, ok = scan(lines, 0, u); !ok {
			return 0, 0, fmt.Errorf("user %q not found in /etc/passwd", u)
		}
	}
	if hasGroup {
		if n, gerr := strconv.ParseUint(g, 10, 32); gerr == nil {
			return uid, uint32(n), nil
		}
		if group == nil {
			return 0, 0, fmt.Errorf("group %q: no /etc/group to look it up in", g)
		}
		for _, line := range readLines(group) {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[0] == g {
				n, err := strconv.ParseUint(parts[2], 10, 32)
				if err != nil {
					return 0, 0, fmt.Errorf("group %q: bad gid %q", g, parts[2])
				}
				return uid, uint32(n), nil
			}
		}
		return 0, 0, fmt.Errorf("group %q not found in /etc/group", g)
	}
	return uid, gid, nil
}

// Home is the home directory of uid in passwd, or "".
func Home(passwd io.Reader, uid uint32) string {
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range readLines(passwd) {
		parts := strings.Split(line, ":")
		if len(parts) >= 6 && parts[2] == want {
			return parts[5]
		}
	}
	return ""
}

func readLines(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// scan finds the passwd line whose field[matchField] == value and returns
// (uid, gid).
func scan(lines []string, matchField int, value string) (uint32, uint32, bool) {
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && matchField < len(parts) && parts[matchField] == value {
			uid, e1 := strconv.ParseUint(parts[2], 10, 32)
			gid, e2 := strconv.ParseUint(parts[3], 10, 32)
			if e1 == nil && e2 == nil {
				return uint32(uid), uint32(gid), true
			}
		}
	}
	return 0, 0, false
}
