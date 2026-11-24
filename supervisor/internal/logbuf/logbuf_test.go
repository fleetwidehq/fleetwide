package logbuf

import (
	"fmt"
	"testing"
)

func TestBuffer(t *testing.T) {
	b := New()
	w := b.Writer("stdout")
	w.Write([]byte("hello "))
	w.Write([]byte("world\npartial"))
	if got := b.Since(0, 0); len(got) != 1 || got[0].Text != "hello world" || got[0].Seq != 1 {
		t.Fatalf("line assembly: %+v", got)
	}
	w.Write([]byte(" done\r\n"))
	if got := b.Since(1, 0); len(got) != 1 || got[0].Text != "partial done" || got[0].Seq != 2 {
		t.Fatalf("second line: %+v", got)
	}
	for i := 0; i < MaxLines+50; i++ {
		b.Add("stderr", fmt.Sprintf("l%d", i))
	}
	all := b.Since(0, 0)
	if len(all) != MaxLines || all[0].Seq != b.Last()-int64(MaxLines)+1 {
		t.Fatalf("ring must keep the newest %d lines: len=%d first=%d last=%d", MaxLines, len(all), all[0].Seq, b.Last())
	}
	if tail := b.Since(0, 3); len(tail) != 3 || tail[2].Seq != b.Last() {
		t.Fatalf("limit keeps the newest: %+v", tail)
	}
	if len(b.Since(b.Last(), 0)) != 0 {
		t.Fatal("since last → empty")
	}
}
