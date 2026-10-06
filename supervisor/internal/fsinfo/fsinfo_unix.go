//go:build unix

package fsinfo

import "syscall"

func statfs(path string) (free, total uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bs := blockSize(&st)
	if bs == 0 {
		return 0, 0, false
	}
	return st.Bavail * bs, st.Blocks * bs, true
}
