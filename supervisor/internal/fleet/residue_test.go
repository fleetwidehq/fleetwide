package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

// An old release wrote /bin/sh as a real file; the new one is usr-merged, so
// /bin is now a symlink to usr/bin. Removing the "missing" /bin/sh must not
// follow the new symlink and delete /usr/bin/sh.
func TestResidueDoesNotDeleteThroughANewSymlink(t *testing.T) {
	root := t.TempDir()
	usrbin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrbin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dash", "sh", "nginx"} {
		if err := os.WriteFile(filepath.Join(usrbin, name), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// the new release replaced the old /bin directory with a symlink
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	// and left a file of its own that the old release never had
	if err := os.WriteFile(filepath.Join(root, "leftover.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldPaths := []string{
		filepath.Join(root, "bin", "sh"),    // resolves onto the new /usr/bin/sh
		filepath.Join(root, "bin", "nginx"), // resolves onto the new /usr/bin/nginx
		filepath.Join(root, "leftover.txt"), // genuine residue
	}
	newPaths := []string{
		filepath.Join(root, "usr", "bin", "sh"),
		filepath.Join(root, "usr", "bin", "dash"),
		filepath.Join(root, "usr", "bin", "nginx"),
		filepath.Join(root, "bin"),
	}
	removed := (&Controller{}).removeResidue(oldPaths, newPaths, nil)

	for _, keep := range []string{"usr/bin/sh", "usr/bin/dash", "usr/bin/nginx"} {
		if _, err := os.Lstat(filepath.Join(root, keep)); err != nil {
			t.Fatalf("%s was deleted through the new /bin symlink: %v", keep, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "bin")); err != nil {
		t.Fatalf("the new /bin symlink was deleted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "leftover.txt")); !os.IsNotExist(err) {
		t.Fatalf("genuine residue must still be removed: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d entries, want only the leftover", removed)
	}
}

// The ordinary case still has to work: files the old release wrote and the new
// one does not are removed, deepest first, and protected paths are never
// touched.
func TestResidueRemovesWhatIsReallyGone(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "opt", "old")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "config.yaml")
	kept := filepath.Join(root, "opt", "keep.txt")
	state := filepath.Join(root, "var", "lib", "fleetwide")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(state, "identity")
	for _, f := range []string{gone, kept, identity} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	removed := (&Controller{}).removeResidue(
		[]string{gone, dir, kept, identity},
		[]string{kept},
		[]string{state},
	)
	if _, err := os.Lstat(gone); !os.IsNotExist(err) {
		t.Fatalf("a file only the old release had must go: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("its directory must go once empty: %v", err)
	}
	if _, err := os.Lstat(kept); err != nil {
		t.Fatalf("a file both releases have must stay: %v", err)
	}
	if _, err := os.Lstat(identity); err != nil {
		t.Fatalf("the state directory is protected: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed %d, want the file and its directory", removed)
	}
}

// unlink follows every directory symlink but the last component: with
// /a -> /data, removing "/a/file" removes /data/file — on the volume. A victim
// whose real location is under a protected mount is therefore never removed,
// however it is spelled.
func TestResidueNeverReachesAVolumeThroughASymlink(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "customer.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	removed := (&Controller{}).removeResidue(
		[]string{filepath.Join(root, "a", "customer.db")}, // spelled through the symlink
		nil,
		[]string{data},
	)
	if _, err := os.Lstat(filepath.Join(data, "customer.db")); err != nil {
		t.Fatalf("the volume's file was removed through the symlink: %v", err)
	}
	if removed != 0 {
		t.Fatalf("removed %d, want 0", removed)
	}
}
