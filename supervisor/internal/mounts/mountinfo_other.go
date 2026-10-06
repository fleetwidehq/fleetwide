//go:build !linux

package mounts

// Points returns nothing off Linux: the unpacker is only ever pointed at a
// scratch directory there, never at "/".
func Points() ([]string, error) { return nil, nil }
