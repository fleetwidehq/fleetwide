//go:build linux

package fsinfo

import "syscall"

// Block counts are in fragment-size units. f_bsize is only the preferred
// transfer size and is 1 MiB on a Docker Desktop bind mount whose real
// fragment size is 4 KiB.
func blockSize(st *syscall.Statfs_t) uint64 {
	if st.Frsize > 0 {
		return uint64(st.Frsize)
	}
	return uint64(st.Bsize)
}
