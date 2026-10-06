package unpack

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type entry struct {
	name, link, body string
	typ              byte
	mode             int64
}

func mkLayer(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, ModTime: time.Unix(1700000000, 0)}
		if h.Mode == 0 {
			if e.typ == tar.TypeDir {
				h.Mode = 0o755
			} else {
				h.Mode = 0o644
			}
		}
		switch e.typ {
		case tar.TypeReg:
			h.Size = int64(len(e.body))
		case tar.TypeSymlink, tar.TypeLink:
			h.Linkname = e.link
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestWhiteoutRemovesLowerLayerFile(t *testing.T) {
	root := t.TempDir()
	a, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(mkLayer(t,
		entry{name: "etc/", typ: tar.TypeDir},
		entry{name: "etc/keep", typ: tar.TypeReg, body: "k"},
		entry{name: "etc/gone", typ: tar.TypeReg, body: "g"},
	)); err != nil {
		t.Fatal(err)
	}
	st, err := a.Apply(mkLayer(t, entry{name: "etc/.wh.gone", typ: tar.TypeReg}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Whiteouts != 1 || st.Removed != 1 {
		t.Fatalf("stats %+v", st)
	}
	if exists(filepath.Join(root, "etc/gone")) || !exists(filepath.Join(root, "etc/keep")) {
		t.Fatal("whiteout not applied correctly")
	}
}

func TestOpaqueWhiteoutKeepsSameLayerSiblings(t *testing.T) {
	root := t.TempDir()
	a, _ := New(root, Options{})
	a.Apply(mkLayer(t,
		entry{name: "d/", typ: tar.TypeDir},
		entry{name: "d/old1", typ: tar.TypeReg, body: "1"},
		entry{name: "d/old2", typ: tar.TypeReg, body: "2"},
	))
	// Same-layer sibling appears BEFORE the opaque marker: must survive.
	st, err := a.Apply(mkLayer(t,
		entry{name: "d/", typ: tar.TypeDir},
		entry{name: "d/new", typ: tar.TypeReg, body: "n"},
		entry{name: "d/.wh..wh..opq", typ: tar.TypeReg},
	))
	if err != nil {
		t.Fatal(err)
	}
	if st.Opaques != 1 || st.Removed != 2 {
		t.Fatalf("stats %+v", st)
	}
	if exists(filepath.Join(root, "d/old1")) || exists(filepath.Join(root, "d/old2")) {
		t.Fatal("opaque did not remove lower entries")
	}
	if !exists(filepath.Join(root, "d/new")) {
		t.Fatal("opaque removed same-layer sibling")
	}
}

func TestFileReplacesDirAndDirReplacesSymlink(t *testing.T) {
	root := t.TempDir()
	a, _ := New(root, Options{})
	a.Apply(mkLayer(t,
		entry{name: "x/", typ: tar.TypeDir},
		entry{name: "x/child", typ: tar.TypeReg, body: "c"},
		entry{name: "lnk", typ: tar.TypeSymlink, link: "x"},
	))
	if _, err := a.Apply(mkLayer(t,
		entry{name: "x", typ: tar.TypeReg, body: "now a file"},
		entry{name: "lnk/", typ: tar.TypeDir},
	)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(root, "x"))
	if err != nil || fi.IsDir() {
		t.Fatal("x should now be a regular file")
	}
	fi, err = os.Lstat(filepath.Join(root, "lnk"))
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("lnk should now be a real directory")
	}
}

func TestSymlinkEscapeIsContained(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	a, _ := New(root, Options{})
	// Layer tries the classic escape: symlink to outside, then write through it.
	_, err := a.Apply(mkLayer(t,
		entry{name: "evil", typ: tar.TypeSymlink, link: outside},
		entry{name: "evil/pwned", typ: tar.TypeReg, body: "x"},
		entry{name: "../../escape", typ: tar.TypeReg, body: "y"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(outside, "pwned")) {
		t.Fatal("wrote outside root through symlink")
	}
	if exists(filepath.Join(filepath.Dir(root), "escape")) {
		t.Fatal("wrote outside root through ..")
	}
	// The write must have landed inside root instead.
	if !exists(filepath.Join(root, "escape")) {
		t.Fatal("dotdot entry should have been clamped into root")
	}
}

func TestHardlink(t *testing.T) {
	root := t.TempDir()
	a, _ := New(root, Options{})
	st, err := a.Apply(mkLayer(t,
		entry{name: "bin/", typ: tar.TypeDir},
		entry{name: "bin/busybox", typ: tar.TypeReg, body: "BB", mode: 0o755},
		entry{name: "bin/sh", typ: tar.TypeLink, link: "bin/busybox"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if st.Hardlinks != 1 {
		t.Fatalf("stats %+v", st)
	}
	b, err := os.ReadFile(filepath.Join(root, "bin/sh"))
	if err != nil || string(b) != "BB" {
		t.Fatalf("hardlink content: %q %v", b, err)
	}
}

func TestProtectedPathsUntouched(t *testing.T) {
	root := t.TempDir()
	mount := filepath.Join(root, "etc", "hosts")
	os.MkdirAll(filepath.Dir(mount), 0o755)
	os.WriteFile(mount, []byte("customer hosts"), 0o644)
	a, _ := New(root, Options{Protected: []string{mount}})
	st, err := a.Apply(mkLayer(t,
		entry{name: "etc/", typ: tar.TypeDir},
		entry{name: "etc/hosts", typ: tar.TypeReg, body: "image hosts"},
		entry{name: "etc/.wh.hosts", typ: tar.TypeReg},
		entry{name: ".wh.etc", typ: tar.TypeReg},
	))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(mount)
	if string(b) != "customer hosts" {
		t.Fatalf("protected file modified: %q", b)
	}
	if st.Skipped != 1 {
		t.Fatalf("expected 1 skipped write, stats %+v", st)
	}
	if !exists(filepath.Join(root, "etc")) {
		t.Fatal("directory containing a protected path was removed")
	}
}

func TestDecompressSniff(t *testing.T) {
	plain := mkLayer(t, entry{name: "a", typ: tar.TypeReg, body: "a"})
	rc, kind, err := Decompress(bytes.NewReader(plain.Bytes()))
	if err != nil || kind != "tar" {
		t.Fatalf("plain: %v %s", err, kind)
	}
	rc.Close()
}

func TestSetuidSetgidPreserved(t *testing.T) {
	root := t.TempDir()
	a, _ := New(root, Options{Chown: true}) // Chown is a no-op unless root, but the order is what matters
	if _, err := a.Apply(mkLayer(t,
		entry{name: "usr/", typ: tar.TypeDir},
		entry{name: "usr/bin/", typ: tar.TypeDir},
		entry{name: "usr/bin/passwd", typ: tar.TypeReg, body: "x", mode: 0o4755},
		entry{name: "usr/bin/chage", typ: tar.TypeReg, body: "x", mode: 0o2755},
	)); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(root, "usr/bin/passwd"))
	if fi.Mode()&os.ModeSetuid == 0 || fi.Mode().Perm() != 0o755 {
		t.Fatalf("passwd mode %v, want setuid 0755", fi.Mode())
	}
	fi, _ = os.Stat(filepath.Join(root, "usr/bin/chage"))
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("chage mode %v, want setgid", fi.Mode())
	}
}
