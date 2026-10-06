//go:build !linux && !darwin && !windows

package cli

// Unsupported platforms conservatively disable automatic colors. An explicit
// --color always still works without requiring a terminal query.
func isTerminalFD(uintptr) bool { return false }
