//go:build unix && !linux

package fsinfo

import "syscall"

// Darwin and the BSDs have no f_frsize; their block counts are in f_bsize.
func blockSize(st *syscall.Statfs_t) uint64 { return uint64(st.Bsize) }
