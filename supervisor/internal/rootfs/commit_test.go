package rootfs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func write(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func newTree(t *testing.T) (staged, dst string) {
	t.Helper()
	base := t.TempDir()
	staged, dst = filepath.Join(base, "staged"), filepath.Join(base, "root")
	for _, d := range []string{staged, dst} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return staged, dst
}

// The old root has a real /bin with /bin/sh in it; the new release is
// usr-merged, so its /bin is a symlink to usr/bin and the shell lives at
// /usr/bin/sh. After the commit the symlink is in place, the shell is
// reachable through it, and nothing the new release needs has been deleted
// through the new symlink.
func TestCommitUsrMerge(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(dst, "bin", "sh"), "old dash", 0o755)
	write(t, filepath.Join(dst, "bin", "oldtool"), "gone in the new release", 0o755)
	write(t, filepath.Join(dst, "usr", "bin", "nginx"), "old nginx", 0o755)

	write(t, filepath.Join(staged, "usr", "bin", "sh"), "new dash", 0o755)
	write(t, filepath.Join(staged, "usr", "bin", "nginx"), "new nginx", 0o755)
	if err := os.Symlink("usr/bin", filepath.Join(staged, "bin")); err != nil {
		t.Fatal(err)
	}

	res, err := Commit(staged, dst, CommitOptions{Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dst, "bin")); err != nil || target != "usr/bin" {
		t.Fatalf("/bin should now be a symlink to usr/bin: %q %v", target, err)
	}
	if got := read(t, filepath.Join(dst, "bin", "sh")); got != "new dash" {
		t.Fatalf("/bin/sh through the symlink = %q", got)
	}
	if got := read(t, filepath.Join(dst, "usr", "bin", "nginx")); got != "new nginx" {
		t.Fatalf("/usr/bin/nginx = %q", got)
	}
	// the old real /bin went with its contents: that is what a symlink
	// replacing a directory means, and oldtool is residue either way
	if exists(filepath.Join(dst, "usr", "bin", "oldtool")) {
		t.Fatal("the old /bin's contents must not leak into /usr/bin")
	}
	if res.Files != 2 || res.Symlinks != 1 {
		t.Fatalf("counts: %+v", res)
	}
	joined := strings.Join(res.Paths, "\n")
	for _, want := range []string{"/bin", "/usr/bin/sh", "/usr/bin/nginx"} {
		if !strings.Contains(joined, filepath.Join(dst, want)) {
			t.Fatalf("paths should record %s: %v", want, res.Paths)
		}
	}
}

// A destination that is a mount point — a bind-mounted /etc/hosts, a volume —
// is never touched, and is not recorded as belonging to the release either.
func TestCommitLeavesProtectedAlone(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(dst, "etc", "hosts"), "127.0.0.1 host", 0o644)
	write(t, filepath.Join(dst, "data", "customer.db"), "customer data", 0o644)
	write(t, filepath.Join(staged, "etc", "hosts"), "image hosts", 0o644)
	write(t, filepath.Join(staged, "etc", "app.conf"), "listen 8080", 0o644)
	write(t, filepath.Join(staged, "data", "defaults.json"), "{}", 0o644)

	res, err := Commit(staged, dst, CommitOptions{
		Protected: []string{filepath.Join(dst, "etc", "hosts"), filepath.Join(dst, "data")},
		Log:       t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dst, "etc", "hosts")); got != "127.0.0.1 host" {
		t.Fatalf("a bind-mounted file must keep its content: %q", got)
	}
	if got := read(t, filepath.Join(dst, "etc", "app.conf")); got != "listen 8080" {
		t.Fatalf("its sibling must still be committed: %q", got)
	}
	if exists(filepath.Join(dst, "data", "defaults.json")) {
		t.Fatal("nothing may be written under a volume")
	}
	if got := read(t, filepath.Join(dst, "data", "customer.db")); got != "customer data" {
		t.Fatalf("volume contents changed: %q", got)
	}
	if res.Skipped != 2 {
		t.Fatalf("skipped = %d, want the file and the volume directory", res.Skipped)
	}
	for _, p := range res.Paths {
		if strings.Contains(p, "hosts") || strings.Contains(p, "/data") {
			t.Fatalf("a skipped path must not be recorded as the release's: %s", p)
		}
	}
}

// A symlink planted at /a pointing into the volume must not make /a/file land
// there. It cannot: the staged tree carries /a as a real directory, every
// directory is visited before its children, and a symlink where the release
// has a directory is a type change — the symlink goes and the directory takes
// its place, so /a/file lands in the release's own /a.
func TestCommitDoesNotFollowASymlinkIntoAProtectedDir(t *testing.T) {
	staged, dst := newTree(t)
	if err := os.MkdirAll(filepath.Join(dst, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(dst, "a")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(staged, "a", "file"), "the release's own file", 0o644)

	res, err := Commit(staged, dst, CommitOptions{Protected: []string{filepath.Join(dst, "data")}, Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dst, "data", "file")) {
		t.Fatal("the file reached the volume through the symlink")
	}
	if fi, err := os.Lstat(filepath.Join(dst, "a")); err != nil || !fi.IsDir() {
		t.Fatalf("/a should now be the release's real directory, got %v %v", fi, err)
	}
	if got := read(t, filepath.Join(dst, "a", "file")); got != "the release's own file" {
		t.Fatalf("/a/file = %q", got)
	}
	if res.Replaced != 1 {
		t.Fatalf("the planted symlink should be the one thing replaced: %+v", res)
	}
}

// Type changes both ways: a directory becomes a file and a file becomes a
// directory, as images do between releases.
func TestCommitReplacesAcrossTypes(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(dst, "opt", "app", "config", "x.yaml"), "old", 0o644)   // dir → file
	write(t, filepath.Join(dst, "opt", "app", "plugin"), "old single file", 0o644) // file → dir
	write(t, filepath.Join(staged, "opt", "app", "config"), "config is a file now", 0o644)
	write(t, filepath.Join(staged, "opt", "app", "plugin", "a.so"), "plugin dir now", 0o644)

	res, err := Commit(staged, dst, CommitOptions{Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dst, "opt", "app", "config")); got != "config is a file now" {
		t.Fatalf("dir → file: %q", got)
	}
	if got := read(t, filepath.Join(dst, "opt", "app", "plugin", "a.so")); got != "plugin dir now" {
		t.Fatalf("file → dir: %q", got)
	}
	if res.Replaced < 2 {
		t.Fatalf("both destinations had to be removed first: %+v", res)
	}
}

// Directories cannot be hard-linked, so their metadata is carried over by
// hand: mode (including setgid), and mtime after the children are in place.
func TestCommitCopiesDirectoryMetadata(t *testing.T) {
	staged, dst := newTree(t)
	dir := filepath.Join(staged, "srv", "shared")
	write(t, filepath.Join(dir, "f"), "x", 0o644)
	// os.FileMode keeps setgid in a high bit, not in 0o2000: a numeric
	// 0o2750 would silently be 0o750.
	if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	past := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(dir, past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dst, "srv", "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o750 || fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("mode = %v, want 0750 with setgid", fi.Mode())
	}
	if !fi.ModTime().Equal(past) {
		t.Fatalf("mtime = %v, want %v (children must not clobber it)", fi.ModTime(), past)
	}
}

// Two names for one inode in the staged tree stay two names for one inode
// after the commit: a hard link moves the inode, whichever name goes first.
func TestCommitKeepsHardlinks(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(staged, "usr", "bin", "busybox"), "bb", 0o755)
	if err := os.Link(filepath.Join(staged, "usr", "bin", "busybox"), filepath.Join(staged, "usr", "bin", "ls")); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatal(err)
	}
	var a, b syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dst, "usr", "bin", "busybox"), &a); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(filepath.Join(dst, "usr", "bin", "ls"), &b); err != nil {
		t.Fatal(err)
	}
	if a.Ino != b.Ino || a.Nlink != 2 {
		t.Fatalf("hard link lost: ino %d/%d nlink %d", a.Ino, b.Ino, a.Nlink)
	}
}

// After a commit the staged tree holds no leaves: each one was moved, so the
// caller's cleanup is a walk over empty directories, and disk usage falls as
// the commit proceeds rather than only at the end.
func TestCommitDrainsTheStagedTree(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(staged, "usr", "bin", "app"), "x", 0o755)
	if err := os.Symlink("app", filepath.Join(staged, "usr", "bin", "app-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(staged, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Fatalf("staged leaf left behind: %s", p)
		}
		return nil
	})
}

// protected_hardlinks without CAP_FOWNER refuses the link; a rename moves the
// inode just the same, so the commit still completes.
func TestCommitFallsBackToRenameWhenLinkIsRefused(t *testing.T) {
	old := linkFile
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: errIsPerm} }
	t.Cleanup(func() { linkFile = old })

	staged, dst := newTree(t)
	write(t, filepath.Join(staged, "usr", "bin", "setuid-tool"), "x", 0o4755)
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dst, "usr", "bin", "setuid-tool")); got != "x" {
		t.Fatalf("file not committed via rename: %q", got)
	}
	if exists(filepath.Join(staged, "usr", "bin", "setuid-tool")) {
		t.Fatal("rename must consume the staged copy")
	}
}

// Running twice is harmless: the second commit finds the leaves already
// moved and only re-applies directory metadata.
func TestCommitIsRerunnable(t *testing.T) {
	staged, dst := newTree(t)
	write(t, filepath.Join(staged, "etc", "a"), "a", 0o644)
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(staged, dst, CommitOptions{Log: t.Logf}); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if got := read(t, filepath.Join(dst, "etc", "a")); got != "a" {
		t.Fatalf("content after rerun: %q", got)
	}
}
