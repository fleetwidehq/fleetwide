package rootfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/unpack"
)

// CommitOptions controls how a staged tree is moved into a root.
type CommitOptions struct {
	// Protected paths under dst that must never be written, replaced or
	// removed: mount points, the supervisor binary, the state dir, asset dirs.
	// Anything under a protected path is protected too.
	Protected []string
	// Chown gives directories the staged tree's owner. Leaves keep theirs:
	// a hard link is the same inode.
	Chown bool
	Log   func(format string, args ...any)
	Warn  func(format string, args ...any)
}

// CommitResult summarises a commit.
type CommitResult struct {
	// Paths is every destination path the commit created or replaced, for
	// the release's paths file. Skipped entries are not in it.
	Paths    []string
	Files    int // files, devices and fifos linked into place
	Symlinks int
	Dirs     int
	Replaced int // destination entries removed to make room
	Skipped  int // protected destinations, left exactly as they were
	CommitMS int64
}

// linkFile is os.Link, replaceable so a test can make it fail the way
// protected_hardlinks does without needing that sysctl.
var linkFile = os.Link

// Commit moves a staged tree into dst. It is meant to be called with nothing
// running in dst: the staged tree is complete and verified, so the only work
// left is naming. Directories are created and given the staged tree's mode,
// owner, xattrs and mtime; leaves — files, devices, fifos — are hard-linked
// into place and the staged copy dropped, so staged and dst must share a
// filesystem (checked first). Symlinks are recreated rather than linked.
//
// Destinations are resolved by the same rules layer application uses
// (unpack.Applier.Resolve), and protection is checked on the resolved path:
// a symlink at /a pointing into a volume cannot make /a/file land there.
// Protected destinations are skipped, never attempted, and Commit never opens
// a destination for writing.
//
// A commit interrupted halfway leaves every staged leaf that was not yet
// moved still in place, so it can be run again.
func Commit(staged, dst string, o CommitOptions) (*CommitResult, error) {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Warn == nil {
		o.Warn = func(string, ...any) {}
	}
	staged, err := filepath.Abs(staged)
	if err != nil {
		return nil, err
	}
	same, err := sameDevice(staged, dst)
	if err != nil {
		return nil, err
	}
	if !same {
		return nil, fmt.Errorf("commit: %s and %s are on different filesystems; a staged tree can only be moved, not copied", staged, dst)
	}
	applier, err := unpack.New(dst, unpack.Options{Protected: o.Protected, Chown: o.Chown, Warn: o.Warn})
	if err != nil {
		return nil, err
	}

	t0 := time.Now()
	res := &CommitResult{}
	seen := map[string]struct{}{}
	record := func(abs string) {
		if _, ok := seen[abs]; !ok {
			seen[abs] = struct{}{}
			res.Paths = append(res.Paths, abs)
		}
	}
	type dirMeta struct {
		abs, src string
		mode     os.FileMode
		uid, gid int
		mt       time.Time
	}
	var dirs []dirMeta

	err = filepath.WalkDir(staged, func(src string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if src == staged {
			return nil
		}
		rel, err := filepath.Rel(staged, src)
		if err != nil {
			return err
		}
		_, _, full, err := applier.Resolve(rel)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", rel, err)
		}
		if applier.IsProtected(full) {
			res.Skipped++
			if d.IsDir() {
				return filepath.SkipDir // everything under a mount point stays as it is
			}
			return nil
		}
		fi, err := os.Lstat(src)
		if err != nil {
			return err
		}
		uid, gid := owner(fi)

		if d.IsDir() {
			if cur, err := os.Lstat(full); err == nil && !cur.IsDir() {
				n, err := applier.RemoveTree(full)
				res.Replaced += n
				if err != nil {
					return fmt.Errorf("replace %s with a directory: %w", full, err)
				}
			}
			if err := os.MkdirAll(full, fi.Mode().Perm()|0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirMeta{abs: full, src: src, mode: fi.Mode(), uid: uid, gid: gid, mt: fi.ModTime()})
			record(full)
			res.Dirs++
			return nil
		}

		// A leaf. Whatever is at the destination goes first.
		if cur, err := os.Lstat(full); err == nil {
			n, err := applier.RemoveTree(full)
			res.Replaced += n
			if err != nil {
				return fmt.Errorf("replace %s: %w", full, err)
			}
			if _, err := os.Lstat(full); err == nil && cur.IsDir() {
				// A directory that could not go because it holds a mount
				// point: the staged leaf has nowhere to land.
				o.Warn("%s: keeping the directory (it contains a mount point); %s not committed", full, rel)
				res.Skipped++
				return nil
			}
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, full); err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", full, target, err)
			}
			if o.Chown {
				if err := os.Lchown(full, uid, gid); err != nil {
					o.Warn("chown %s: %v", full, err)
				}
			}
			os.Remove(src)
			record(full)
			res.Symlinks++
			return nil
		}
		if err := linkFile(src, full); err != nil {
			// protected_hardlinks without CAP_FOWNER, or a filesystem that
			// refuses the link: a rename moves the inode just the same, but
			// a half-done commit is then not rerunnable.
			if rerr := os.Rename(src, full); rerr != nil {
				return fmt.Errorf("link %s: %v (rename: %w)", full, err, rerr)
			}
		} else {
			os.Remove(src)
		}
		record(full)
		res.Files++
		return nil
	})
	if err != nil {
		return res, err
	}

	// Directory metadata last, deepest first, as layer application does: a
	// read-only directory must not block its own children, and creating
	// children would clobber the mtime. Order per directory: chown, chmod,
	// xattrs, mtime — chown clears setuid/setgid.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].abs) > len(dirs[j].abs) })
	xattrWarned := map[string]bool{}
	for _, d := range dirs {
		if o.Chown {
			if err := os.Lchown(d.abs, d.uid, d.gid); err != nil {
				o.Warn("chown %s: %v", d.abs, err)
			}
		}
		if err := os.Chmod(d.abs, d.mode.Perm()|d.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)); err != nil {
			o.Warn("chmod %s: %v", d.abs, err)
		}
		unpack.CopyXattrs(d.src, d.abs, o.Warn, xattrWarned)
		if !d.mt.IsZero() {
			_ = os.Chtimes(d.abs, d.mt, d.mt)
		}
	}
	res.CommitMS = time.Since(t0).Milliseconds()
	o.Log("committed %s into %s: %d files, %d symlinks, %d dirs, %d replaced, %d skipped, %dms",
		staged, dst, res.Files, res.Symlinks, res.Dirs, res.Replaced, res.Skipped, res.CommitMS)
	return res, nil
}

// SameFilesystem reports whether two paths share a filesystem — and so a
// pool of free space. Unknown counts as shared: the cautious answer.
func SameFilesystem(a, b string) bool {
	same, err := sameDevice(a, b)
	return err != nil || same
}

// sameDevice reports whether two paths are on the same filesystem, which is
// what makes moving a tree between them metadata work.
func sameDevice(a, b string) (bool, error) {
	var sa, sb syscall.Stat_t
	if err := syscall.Stat(a, &sa); err != nil {
		return false, fmt.Errorf("stat %s: %w", a, err)
	}
	if err := syscall.Stat(b, &sb); err != nil {
		return false, fmt.Errorf("stat %s: %w", b, err)
	}
	return sa.Dev == sb.Dev, nil
}

// owner returns an entry's uid and gid, or -1/-1 where the platform does not
// say (then Lchown is skipped by the caller's Chown check anyway).
func owner(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// errIsPerm is used by tests to build a protected_hardlinks-shaped failure.
var errIsPerm = errors.New("operation not permitted")
