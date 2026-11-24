package embedded

import (
	"archive/tar"
	"bytes"
	"testing"
)

type ent struct {
	name, body, link string
	typ              byte
	mode             int64
	uid              int
}

func tarOf(t *testing.T, ents []ent) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: e.mode, Uid: e.uid, Typeflag: e.typ, Linkname: e.link}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return &buf
}

var base = []ent{
	{name: "usr/", typ: tar.TypeDir, mode: 0o755},
	{name: "usr/lib/libssl.so", body: "ssl v1", mode: 0o644},
	{name: "usr/bin/sh", body: "#!sh", mode: 0o755},
	{name: "bin", typ: tar.TypeSymlink, link: "usr/bin", mode: 0o777},
	{name: "app/", typ: tar.TypeDir, mode: 0o755},
	{name: "app/main.js", body: "v1", mode: 0o644},
	{name: "fleetwide-supervisor", body: "SUPERVISOR v1", mode: 0o755},
	{name: "fleetwide/embedded.json", body: "{}", mode: 0o644},
	{name: "var/lib/fleetwide/x", body: "state", mode: 0o644},
}

func build(t *testing.T, ents []ent) *Index {
	t.Helper()
	x, err := Build(tarOf(t, ents))
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// The supervisor, its metadata and its state never appear: they differ between
// builds by construction and would make every release a "base change".
func TestBuildExcludesTheSupervisorsOwnPaths(t *testing.T) {
	x := build(t, base)
	for _, e := range x.Entries {
		if e.Path == "/fleetwide-supervisor" || e.Path == "/fleetwide/embedded.json" || e.Path == "/var/lib/fleetwide/x" {
			t.Fatalf("%s must be excluded", e.Path)
		}
	}
	if len(x.Entries) != 6 {
		t.Fatalf("entries: %d %+v", len(x.Entries), x.Entries)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	x := build(t, base)
	var buf bytes.Buffer
	sha, err := x.Write(&buf)
	if err != nil {
		t.Fatal(err)
	}
	y, sha2, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if sha != sha2 || len(y.Entries) != len(x.Entries) || y.Entries[2] != x.Entries[2] {
		t.Fatalf("round trip: %s %s %+v", sha, sha2, y.Entries)
	}
	if ch := Diff(x, y, nil); len(ch) != 0 {
		t.Fatalf("identical indexes differ: %+v", ch)
	}
}

// Everything under a sync path is the app's business and is never a base
// change; everything else is compared by content, type, mode, owner, link.
func TestDiffTellsBaseChangesFromAppChanges(t *testing.T) {
	sync := []string{"/app"}
	x := build(t, base)
	with := func(mod func([]ent) []ent) *Index { return build(t, mod(append([]ent(nil), base...))) }

	// app change only
	y := with(func(e []ent) []ent { e[5].body = "v2"; return e })
	if ch := Diff(x, y, sync); len(ch) != 0 {
		t.Fatalf("an app-layer change is not a base change: %+v", ch)
	}
	// same size, different content, outside
	y = with(func(e []ent) []ent { e[1].body = "ssl v2"; return e })
	ch := Diff(x, y, sync)
	if len(ch) != 1 || ch[0].Path != "/usr/lib/libssl.so" || ch[0].What != "content" {
		t.Fatalf("content change: %+v", ch)
	}
	// mode change
	y = with(func(e []ent) []ent { e[2].mode = 0o700; return e })
	if ch := Diff(x, y, sync); len(ch) != 1 || ch[0].What != "mode" {
		t.Fatalf("mode change: %+v", ch)
	}
	// owner change
	y = with(func(e []ent) []ent { e[2].uid = 1000; return e })
	if ch := Diff(x, y, sync); len(ch) != 1 || ch[0].What != "owner" {
		t.Fatalf("owner change: %+v", ch)
	}
	// symlink target
	y = with(func(e []ent) []ent { e[3].link = "usr/local/bin"; return e })
	if ch := Diff(x, y, sync); len(ch) != 1 || ch[0].What != "link" {
		t.Fatalf("link change: %+v", ch)
	}
	// added and removed
	y = with(func(e []ent) []ent {
		e = append(e[:1], e[2:]...)
		return append(e, ent{name: "usr/lib/libnew.so", body: "n", mode: 0o644})
	})
	ch = Diff(x, y, sync)
	if len(ch) != 2 || ch[0].Path != "/usr/lib/libnew.so" || ch[0].Kind != "added" || ch[1].Path != "/usr/lib/libssl.so" || ch[1].Kind != "removed" {
		t.Fatalf("added/removed: %+v", ch)
	}
	if s := Summary(ch, 1); s != "2 path(s): /usr/lib/libnew.so (added), … 1 more" {
		t.Fatalf("summary: %q", s)
	}
}

// A hard link carries its target's content; rebuilt layers with identical
// bytes give the same index.
func TestHardlinksAndDeterminism(t *testing.T) {
	ents := append([]ent(nil), base...)
	ents = append(ents, ent{name: "usr/bin/dash", typ: tar.TypeLink, link: "usr/bin/sh", mode: 0o755})
	x := build(t, ents)
	var found bool
	for _, e := range x.Entries {
		if e.Path == "/usr/bin/dash" {
			found = e.Type == "f" && e.Hash != "" && e.Link == ""
		}
	}
	if !found {
		t.Fatalf("hard link not recorded as a file with content: %+v", x.Entries)
	}
	var a, b bytes.Buffer
	sa, _ := x.Write(&a)
	sb, _ := build(t, ents).Write(&b)
	if sa != sb {
		t.Fatal("the same content must index to the same bytes")
	}
}

func TestReadMeta(t *testing.T) {
	x := build(t, base)
	var ib bytes.Buffer
	sha, _ := x.Write(&ib)
	meta := tarOf(t, []ent{
		{name: "fleetwide/embedded.json", body: `{"runtime":"embedded","digest":"sha256:abc","sync_paths":["/app"]}`, mode: 0o644},
		{name: "fleetwide/embedded.index.gz", body: ib.String(), mode: 0o644},
	})
	info, idx, got, err := ReadMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest != "sha256:abc" || len(idx.Entries) != len(x.Entries) || got != sha {
		t.Fatalf("meta: %+v %d %s", info, len(idx.Entries), got)
	}
	if _, _, _, err := ReadMeta(tarOf(t, []ent{{name: "x", body: "y"}})); err == nil {
		t.Fatal("a layer without metadata must be refused")
	}
}
