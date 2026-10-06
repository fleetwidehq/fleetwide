// Package unpack applies OCI image layers (uncompressed tar streams) onto a
// directory, implementing whiteouts and opaque whiteouts per the OCI image
// spec, hardlinks, symlinks, devices (best effort) and a set of protected
// paths (mount points, the supervisor's own binary) that are never written or
// removed. All destination paths are resolved with SecureJoin so a malicious
// layer cannot escape the root through ".." or symlinks.
package unpack

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
)

const (
	whiteoutPrefix = ".wh."
	opaqueWhiteout = ".wh..wh..opq"
)

// Stats counts what a layer application did.
type Stats struct {
	Files       int   `json:"files"`
	Dirs        int   `json:"dirs"`
	Symlinks    int   `json:"symlinks"`
	Hardlinks   int   `json:"hardlinks"`
	Devices     int   `json:"devices"`
	Fifos       int   `json:"fifos"`
	Whiteouts   int   `json:"whiteouts"`
	Opaques     int   `json:"opaques"`
	Removed     int   `json:"removed"` // entries deleted by whiteouts or type replacement
	Skipped     int   `json:"skipped"` // protected paths and unsupported entries
	BytesWriten int64 `json:"bytes_written"`
}

// Add accumulates.
func (s *Stats) Add(o Stats) {
	s.Files += o.Files
	s.Dirs += o.Dirs
	s.Symlinks += o.Symlinks
	s.Hardlinks += o.Hardlinks
	s.Devices += o.Devices
	s.Fifos += o.Fifos
	s.Whiteouts += o.Whiteouts
	s.Opaques += o.Opaques
	s.Removed += o.Removed
	s.Skipped += o.Skipped
	s.BytesWriten += o.BytesWriten
}

// Options controls layer application.
type Options struct {
	// Protected paths (absolute, inside root) that must never be written,
	// replaced or removed. Anything under a protected path is protected too.
	// Used for mount points and the supervisor binary when extracting over "/".
	Protected []string
	// Chown applies uid/gid from the tar. Requires root; auto-disabled if
	// the process is not root.
	Chown bool
	// Warn receives non-fatal problems (unsupported entry, mknod EPERM...).
	Warn func(format string, args ...any)
	// Record, when set, receives every absolute path this applier created or
	// replaced. Used to compute residue when a different image is extracted
	// over the same root later.
	Record func(abs string)
	// Only, when set, restricts application to entries at or below these
	// image-absolute paths (the embedded runtime's sync paths); everything
	// else in the layer is skipped, whiteouts included. Directories on the
	// way to an Only path are created as needed with default modes.
	Only []string
}

// Applier applies successive layers to one root directory.
type Applier struct {
	root        string
	opts        Options
	protected   []string        // cleaned absolute paths
	only        []string        // Options.Only under root, cleaned; nil = everything
	xattrWarned map[string]bool // attribute+error pairs already warned about
}

// New creates an Applier for root. root must exist.
func New(root string, opts Options) (*Applier, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	if opts.Chown && os.Geteuid() != 0 {
		opts.Chown = false
	}
	if opts.Warn == nil {
		opts.Warn = func(string, ...any) {}
	}
	a := &Applier{root: abs, opts: opts, xattrWarned: map[string]bool{}}
	for _, p := range opts.Protected {
		p = filepath.Clean(p)
		if p == abs || p == "/" {
			continue
		}
		a.protected = append(a.protected, p)
	}
	for _, p := range opts.Only {
		a.only = append(a.only, filepath.Join(abs, filepath.Clean("/"+p)))
	}
	return a, nil
}

// inOnly reports whether abs is at or below one of the Only paths (root
// paths of the applier's own root); true when no filter is set.
func (a *Applier) inOnly(abs string) bool {
	if a.only == nil {
		return true
	}
	for _, p := range a.only {
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// isProtected reports whether abs is a protected path or lies under one.
func (a *Applier) isProtected(abs string) bool {
	for _, p := range a.protected {
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// containsProtected reports whether any protected path lies under abs.
func (a *Applier) containsProtected(abs string) bool {
	for _, p := range a.protected {
		if strings.HasPrefix(p, abs+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolve maps a tar entry name to (parentDirAbs, base, fullAbs). The parent
// is resolved through symlinks inside root; the final component is not, so
// an existing symlink at the destination is replaced rather than followed.
func (a *Applier) resolve(name string) (parent, base, full string, err error) {
	clean := path.Clean("/" + name)
	if clean == "/" {
		return a.root, "", a.root, nil
	}
	dir, b := path.Split(clean)
	parent, err = securejoin.SecureJoin(a.root, dir)
	if err != nil {
		return "", "", "", err
	}
	return parent, b, filepath.Join(parent, b), nil
}

// removeTree removes abs (file, symlink or directory) while leaving protected
// entries in place. Returns number of entries removed.
func (a *Applier) removeTree(abs string) (int, error) {
	if a.isProtected(abs) {
		return 0, nil
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	if !fi.IsDir() {
		return 1, os.Remove(abs)
	}
	if !a.containsProtected(abs) {
		n := countEntries(abs)
		return n, os.RemoveAll(abs)
	}
	// Directory contains a mount point or other protected path: remove
	// children selectively and keep the directory itself.
	entries, err := os.ReadDir(abs)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, e := range entries {
		n, err := a.removeTree(filepath.Join(abs, e.Name()))
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func countEntries(abs string) int {
	n := 0
	filepath.WalkDir(abs, func(string, os.DirEntry, error) error { n++; return nil })
	return n
}

// Apply applies one uncompressed tar layer.
func (a *Applier) Apply(r io.Reader) (Stats, error) {
	var st Stats
	tr := tar.NewReader(r)
	// Paths written by this layer; opaque/whiteout handling must not delete
	// same-layer siblings (OCI image-spec layer.md).
	written := map[string]bool{}
	type deferredDir struct {
		abs  string
		mode os.FileMode
		mt   time.Time
	}
	var dirs []deferredDir

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, fmt.Errorf("read tar: %w", err)
		}
		name := hdr.Name
		if name == "" || name == "." || name == "./" {
			continue
		}
		parent, base, full, err := a.resolve(name)
		if err != nil {
			return st, fmt.Errorf("resolve %q: %w", name, err)
		}
		if base == "" {
			continue // the root itself
		}
		if a.isProtected(full) || !a.inOnly(full) {
			st.Skipped++
			continue
		}

		// Whiteouts.
		if base == opaqueWhiteout {
			st.Opaques++
			entries, err := os.ReadDir(parent)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return st, err
			}
			for _, e := range entries {
				child := filepath.Join(parent, e.Name())
				if written[child] {
					continue
				}
				n, err := a.removeTree(child)
				st.Removed += n
				if err != nil {
					return st, fmt.Errorf("opaque whiteout %s: %w", child, err)
				}
			}
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			st.Whiteouts++
			target := filepath.Join(parent, strings.TrimPrefix(base, whiteoutPrefix))
			if written[target] {
				continue
			}
			n, err := a.removeTree(target)
			st.Removed += n
			if err != nil {
				return st, fmt.Errorf("whiteout %s: %w", target, err)
			}
			continue
		}

		if err := os.MkdirAll(parent, 0o755); err != nil {
			return st, err
		}

		// Replace whatever is at the destination unless it is a directory
		// and we are writing a directory.
		if fi, err := os.Lstat(full); err == nil {
			if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
				n, err := a.removeTree(full)
				st.Removed += n
				if err != nil {
					return st, fmt.Errorf("replace %s: %w", full, err)
				}
			}
		}

		mode := hdr.FileInfo().Mode()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, mode.Perm()|0o700); err != nil {
				return st, err
			}
			dirs = append(dirs, deferredDir{abs: full, mode: mode, mt: hdr.ModTime})
			st.Dirs++

		case tar.TypeReg, tar.TypeRegA:
			f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return st, err
			}
			n, err := io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return st, fmt.Errorf("write %s: %w", full, err)
			}
			st.BytesWriten += n
			// mode is applied after chown below: chown clears setuid/setgid.
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(full, hdr.ModTime, hdr.ModTime)
			}
			st.Files++

		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, full); err != nil {
				return st, fmt.Errorf("symlink %s -> %s: %w", full, hdr.Linkname, err)
			}
			st.Symlinks++

		case tar.TypeLink:
			// Hardlink target is relative to the layer root.
			_, _, target, err := a.resolve(hdr.Linkname)
			if err != nil {
				return st, fmt.Errorf("hardlink target %q: %w", hdr.Linkname, err)
			}
			if err := os.Link(target, full); err != nil {
				// Target may be a protected path or on another filesystem;
				// fall back to a copy so the entry still exists.
				if cerr := copyFile(target, full); cerr != nil {
					return st, fmt.Errorf("hardlink %s -> %s: %v (copy fallback: %w)", full, target, err, cerr)
				}
			}
			st.Hardlinks++

		case tar.TypeChar, tar.TypeBlock:
			if err := mknod(full, mode, int(hdr.Devmajor), int(hdr.Devminor)); err != nil {
				if errors.Is(err, os.ErrPermission) || errors.Is(err, errUnsupported) {
					a.opts.Warn("skip device %s: %v", name, err)
					st.Skipped++
					continue
				}
				return st, fmt.Errorf("mknod %s: %w", full, err)
			}
			st.Devices++

		case tar.TypeFifo:
			if err := mkfifo(full, mode); err != nil {
				a.opts.Warn("skip fifo %s: %v", name, err)
				st.Skipped++
				continue
			}
			st.Fifos++

		default:
			a.opts.Warn("skip unsupported tar entry type %q for %s", hdr.Typeflag, name)
			st.Skipped++
			continue
		}

		written[full] = true
		if a.opts.Record != nil {
			a.opts.Record(full)
		}

		if a.opts.Chown && hdr.Typeflag != tar.TypeLink {
			if err := os.Lchown(full, hdr.Uid, hdr.Gid); err != nil {
				a.opts.Warn("chown %s: %v", name, err)
			}
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			// After chown, so setuid/setgid/sticky survive (chown drops them).
			if err := os.Chmod(full, mode); err != nil {
				return st, err
			}
		}
		if len(hdr.PAXRecords) > 0 && hdr.Typeflag != tar.TypeSymlink && hdr.Typeflag != tar.TypeLink {
			applyXattrs(full, hdr.PAXRecords, a.opts.Warn, a.xattrWarned)
		}
	}

	// Directory modes last, deepest first, so read-only dirs don't block
	// their own children and mtimes aren't clobbered by child creation.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := os.Chmod(d.abs, d.mode); err != nil {
			a.opts.Warn("chmod dir %s: %v", d.abs, err)
		}
		if !d.mt.IsZero() {
			_ = os.Chtimes(d.abs, d.mt, d.mt)
		}
	}
	return st, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

var errUnsupported = errors.New("unsupported on this platform")

// The four methods below expose the applier's path and protection rules to a
// caller that moves an already-unpacked tree into a root, so both use one
// answer to "where does this name land and may I touch it".

// Resolve maps a path relative to root to (parentAbs, base, fullAbs). The
// parent is resolved through symlinks inside root; the final component is
// not, so an existing symlink at the destination is replaced, not followed.
func (a *Applier) Resolve(name string) (parent, base, full string, err error) { return a.resolve(name) }

// IsProtected reports whether abs is a protected path or lies under one.
func (a *Applier) IsProtected(abs string) bool { return a.isProtected(abs) }

// ContainsProtected reports whether a protected path lies under abs.
func (a *Applier) ContainsProtected(abs string) bool { return a.containsProtected(abs) }

// RemoveTree removes abs while leaving protected entries in place, and
// returns how many entries went.
func (a *Applier) RemoveTree(abs string) (int, error) { return a.removeTree(abs) }
