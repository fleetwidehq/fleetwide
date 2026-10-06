//go:build !linux

package unpack

// applyXattrs is a no-op off Linux.
func applyXattrs(string, map[string]string, func(string, ...any), map[string]bool) {}

// CopyXattrs is a no-op off Linux.
func CopyXattrs(string, string, func(string, ...any), map[string]bool) {}
