//go:build linux

package unpack

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// applyXattrs sets SCHILY.xattr.* PAX records (e.g. security.capability for
// ping-style binaries). Best effort: unsupported filesystems and missing
// privileges only produce a warning, once per attribute and error (seen).
func applyXattrs(p string, pax map[string]string, warn func(string, ...any), seen map[string]bool) {
	for k, v := range pax {
		name, ok := strings.CutPrefix(k, "SCHILY.xattr.")
		if !ok {
			continue
		}
		if err := unix.Lsetxattr(p, name, []byte(v), 0); err != nil {
			warnXattr(warn, seen, name, p, err)
		}
	}
}

// warnXattr reports an attribute that could not be set. A filesystem that
// refuses an attribute refuses it everywhere, so the first path is named and
// the rest are counted silently.
func warnXattr(warn func(string, ...any), seen map[string]bool, name, p string, err error) {
	key := name + "\x00" + err.Error()
	if seen[key] {
		return
	}
	seen[key] = true
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
		warn("xattr %s on %s: %v (not repeated for other paths)", name, p, err)
		return
	}
	warn("xattr %s on %s: %v", name, p, err)
}

// CopyXattrs copies every extended attribute of src onto dst without
// following symlinks (used for directories, which a commit cannot hard-link).
// Best effort, like applyXattrs; seen dedupes the warnings the same way.
func CopyXattrs(src, dst string, warn func(string, ...any), seen map[string]bool) {
	buf := make([]byte, 64*1024)
	n, err := unix.Llistxattr(src, buf)
	if err != nil || n == 0 {
		return
	}
	for _, name := range strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		val := make([]byte, 64*1024)
		vn, err := unix.Lgetxattr(src, name, val)
		if err != nil {
			continue
		}
		if err := unix.Lsetxattr(dst, name, val[:vn], 0); err != nil {
			warnXattr(warn, seen, name, dst, err)
		}
	}
}
