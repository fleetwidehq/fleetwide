package unpack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PreflightError names the first destination a layer could not be written
// to by this process, and why.
type PreflightError struct {
	Path   string
	Reason string
}

func (e *PreflightError) Error() string { return e.Path + ": " + e.Reason }

// Preflight reads a layer and checks, without writing anything, that this
// process could apply it into the root: every destination's nearest existing
// ancestor is writable, a whiteout or a directory replaced by something else
// has a writable parent and a writable subtree, and a hard link's target is
// readable. Paths this layer set creates on the way are remembered in
// created, shared across the layers of one release.
func (a *Applier) Preflight(r io.Reader, created map[string]bool) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		name := hdr.Name
		if name == "" || name == "." || name == "./" {
			continue
		}
		parent, base, full, err := a.resolve(name)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", name, err)
		}
		if base == "" || a.isProtected(full) || !a.inOnly(full) {
			continue
		}
		if base == opaqueWhiteout {
			if err := a.needSubtreeWritable(parent, created); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			target := filepath.Join(parent, strings.TrimPrefix(base, whiteoutPrefix))
			if err := a.needRemovable(target, created); err != nil {
				return err
			}
			continue
		}
		fi, lerr := os.Lstat(full)
		switch {
		case lerr == nil && fi.IsDir() && hdr.Typeflag == tar.TypeDir:
			// exists as a directory and stays one: nothing to write
		case lerr == nil:
			// replaced (file over file, or a type change): unlink + create
			if err := a.needRemovable(full, created); err != nil {
				return err
			}
		default:
			if err := a.needWritableAncestor(full, created); err != nil {
				return err
			}
		}
		if hdr.Typeflag == tar.TypeLink {
			_, _, target, err := a.resolve(hdr.Linkname)
			if err == nil && !created[target] {
				if unix.Access(target, unix.R_OK) != nil {
					return &PreflightError{Path: full, Reason: "hard link target " + target + " is not readable"}
				}
			}
		}
		created[full] = true
	}
}

// needWritableAncestor: the nearest existing ancestor of abs must be a
// directory this process can write and search.
func (a *Applier) needWritableAncestor(abs string, created map[string]bool) error {
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		if created[p] {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			if p == "/" || p == a.root {
				return &PreflightError{Path: abs, Reason: "no existing ancestor directory"}
			}
			continue
		}
		if !fi.IsDir() {
			return &PreflightError{Path: abs, Reason: p + " is not a directory"}
		}
		if unix.Access(p, unix.W_OK|unix.X_OK) != nil {
			return &PreflightError{Path: abs, Reason: p + " is not writable by this user"}
		}
		return nil
	}
}

// needRemovable: abs exists (or is being whited out); its parent must be
// writable, and if it is a directory, everything under it too.
func (a *Applier) needRemovable(abs string, created map[string]bool) error {
	if created[abs] {
		return nil
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil // nothing there to remove
	}
	if err := a.needWritableAncestor(abs, created); err != nil {
		return err
	}
	if fi.IsDir() {
		return a.needSubtreeWritable(abs, created)
	}
	return nil
}

// needSubtreeWritable: every directory at or below abs must be writable, so
// its contents can be removed.
func (a *Applier) needSubtreeWritable(abs string, created map[string]bool) error {
	if created[abs] {
		return nil
	}
	return filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return &PreflightError{Path: abs, Reason: err.Error()}
		}
		if d.IsDir() && unix.Access(p, unix.W_OK|unix.X_OK) != nil {
			return &PreflightError{Path: abs, Reason: p + " is not writable by this user"}
		}
		return nil
	})
}
