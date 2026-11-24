package unpack

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// Decompress sniffs the blob's magic bytes and returns an uncompressed tar
// stream. Supports gzip, zstd and plain tar (the three OCI layer encodings).
func Decompress(r io.Reader) (io.ReadCloser, string, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, "", err
	}
	switch {
	case bytes.HasPrefix(head, gzipMagic):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, "", fmt.Errorf("gzip: %w", err)
		}
		return gz, "gzip", nil
	case bytes.HasPrefix(head, zstdMagic):
		zr, err := zstd.NewReader(br)
		if err != nil {
			return nil, "", fmt.Errorf("zstd: %w", err)
		}
		return zr.IOReadCloser(), "zstd", nil
	default:
		return io.NopCloser(br), "tar", nil
	}
}
