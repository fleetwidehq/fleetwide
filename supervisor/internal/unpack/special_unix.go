//go:build unix

package unpack

import (
	"os"

	"golang.org/x/sys/unix"
)

func mknod(p string, mode os.FileMode, major, minor int) error {
	m := uint32(mode.Perm())
	switch {
	case mode&os.ModeCharDevice != 0:
		m |= unix.S_IFCHR
	default:
		m |= unix.S_IFBLK
	}
	if err := unix.Mknod(p, m, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
		return &os.PathError{Op: "mknod", Path: p, Err: err}
	}
	return nil
}

func mkfifo(p string, mode os.FileMode) error {
	if err := unix.Mkfifo(p, uint32(mode.Perm())); err != nil {
		return &os.PathError{Op: "mkfifo", Path: p, Err: err}
	}
	return nil
}
