// Package logbuf keeps the application's recent stdout/stderr in memory so
// the supervisor can stream it to the console on demand. Lines are numbered so the
// console can resume from the last sequence it saw. Nothing is written to
// disk and the buffer is bounded (lines and bytes).
package logbuf

import (
	"bytes"
	"io"
	"sync"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

const (
	MaxLines = 2000
	MaxBytes = 1 << 20
	maxLine  = 16 * 1024
)

// Buffer is a bounded ring of log lines.
type Buffer struct {
	mu    sync.Mutex
	lines []v1.LogLine
	bytes int
	seq   int64
}

// New creates an empty buffer.
func New() *Buffer { return &Buffer{} }

// Add appends one line.
func (b *Buffer) Add(stream, text string) {
	if len(text) > maxLine {
		text = text[:maxLine] + "…"
	}
	b.mu.Lock()
	b.seq++
	b.lines = append(b.lines, v1.LogLine{Seq: b.seq, At: time.Now(), Stream: stream, Text: text})
	b.bytes += len(text)
	for len(b.lines) > MaxLines || (b.bytes > MaxBytes && len(b.lines) > 1) {
		b.bytes -= len(b.lines[0].Text)
		b.lines = b.lines[1:]
	}
	b.mu.Unlock()
}

// Since returns lines with Seq > after (oldest first), capped to limit (0 = all).
func (b *Buffer) Since(after int64, limit int) []v1.LogLine {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := 0
	for i < len(b.lines) && b.lines[i].Seq <= after {
		i++
	}
	out := b.lines[i:]
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	cp := make([]v1.LogLine, len(out))
	copy(cp, out)
	return cp
}

// Last is the newest sequence number (0 when empty).
func (b *Buffer) Last() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// Writer returns an io.Writer that splits incoming bytes into lines for the
// given stream. Partial lines are held until a newline arrives.
func (b *Buffer) Writer(stream string) io.Writer { return &lineWriter{b: b, stream: stream} }

type lineWriter struct {
	b      *Buffer
	stream string
	mu     sync.Mutex
	part   bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.part.Write(p)
	for {
		i := bytes.IndexByte(w.part.Bytes(), '\n')
		if i < 0 {
			if w.part.Len() > maxLine {
				w.b.Add(w.stream, w.part.String())
				w.part.Reset()
			}
			return len(p), nil
		}
		line := w.part.Bytes()[:i]
		w.b.Add(w.stream, string(bytes.TrimRight(line, "\r")))
		w.part.Next(i + 1)
	}
}
