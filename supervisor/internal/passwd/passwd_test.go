package passwd

import (
	"strings"
	"testing"
)

const pw = "root:x:0:0:root:/root:/bin/bash\nnginx:x:101:101:nginx user:/nonexistent:/bin/false\napp:x:1000:1000::/home/app:/bin/sh\n"
const gr = "root:x:0:\nnginx:x:101:\nstaff:x:50:\n"

func TestLookup(t *testing.T) {
	for _, tc := range []struct {
		spec     string
		uid, gid uint32
		err      bool
	}{
		{"nginx", 101, 101, false},
		{"101", 101, 101, false},   // numeric, in passwd: passwd's gid
		{"65534", 65534, 0, false}, // numeric, absent: gid 0 like runc
		{"app:staff", 1000, 50, false},
		{"app:0", 1000, 0, false},
		{"nobody", 0, 0, true},
		{"app:nogroup", 0, 0, true},
	} {
		uid, gid, err := Lookup(strings.NewReader(pw), strings.NewReader(gr), tc.spec)
		if (err != nil) != tc.err || uid != tc.uid || gid != tc.gid {
			t.Fatalf("%s: got %d:%d err=%v want %d:%d err=%v", tc.spec, uid, gid, err, tc.uid, tc.gid, tc.err)
		}
	}
	if h := Home(strings.NewReader(pw), 1000); h != "/home/app" {
		t.Fatalf("home: %q", h)
	}
}
