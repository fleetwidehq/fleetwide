// Package fsinfo answers how big a filesystem is and how much of it is left.
// statfs block counts are in units of the fragment size, not the transfer
// block size; a Docker Desktop bind mount reports f_bsize = 1 MiB and
// f_frsize = 4 KiB.
package fsinfo

// Usage returns the used and total bytes of the filesystem holding path.
// ok is false when path cannot be stat'ed or the numbers are nonsense.
func Usage(path string) (used, total uint64, ok bool) {
	free, total, ok := Free(path)
	if !ok || free > total {
		return 0, 0, false
	}
	return total - free, total, true
}

// Free returns the bytes available to an unprivileged writer and the total
// size of the filesystem holding path.
func Free(path string) (free, total uint64, ok bool) { return statfs(path) }
