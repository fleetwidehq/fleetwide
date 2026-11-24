package fsinfo

import (
	"os"
	"testing"
)

// The numbers have to describe the filesystem the path is on: a bind-mounted
// volume reports a transfer block size far larger than its fragment size.
func TestUsageIsSane(t *testing.T) {
	dir := t.TempDir()
	used, total, ok := Usage(dir)
	if !ok {
		t.Fatalf("Usage(%s) failed on a directory that exists", dir)
	}
	if total == 0 || used > total {
		t.Fatalf("used=%d total=%d: used must fit inside total", used, total)
	}
	// No filesystem this test can run on is a zettabyte; a wrong block size
	// shows up as exactly this kind of implausible total.
	if total > 1<<60 {
		t.Fatalf("total=%d bytes is implausible: wrong block size?", total)
	}
	free, total2, ok := Free(dir)
	if !ok || total2 != total || free > total {
		t.Fatalf("Free and Usage disagree: free=%d total=%d vs total=%d", free, total2, total)
	}
	// used came from an earlier statfs than free, and the filesystem is live
	// (other processes write between the two calls), so allow a little drift.
	if used+free > total+total/100 {
		t.Fatalf("used=%d + free=%d exceeds total=%d", used, free, total)
	}
}

func TestMissingPath(t *testing.T) {
	if _, _, ok := Usage(os.TempDir() + "/fleetwide-no-such-dir-4b1f"); ok {
		t.Fatal("a path that does not exist must not report usage")
	}
}
