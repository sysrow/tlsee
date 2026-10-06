package cli

import (
	"os"
	"syscall"
	"testing"
)

func TestPseudoTerminalColor(t *testing.T) {
	// Opening the PTY multiplexer allocates a new pseudo-terminal master.
	// It supports terminal queries without becoming our controlling terminal.
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("pseudo-terminal unavailable: %v", err)
	}
	t.Cleanup(func() { pty.Close() })
	if !isTerminal(pty) {
		t.Fatal("pseudo-terminal not detected as a terminal")
	}
	t.Setenv("NO_COLOR", "")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	if color, err := resolveColor("auto", pty); err != nil || !color {
		t.Errorf("auto color on terminal = %t, %v; want true, nil", color, err)
	}
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct {
		mode string
		want bool
	}{{"auto", false}, {"always", true}, {"never", false}} {
		if color, err := resolveColor(tc.mode, pty); err != nil || color != tc.want {
			t.Errorf("%s color with NO_COLOR = %t, %v; want %t, nil", tc.mode, color, err, tc.want)
		}
	}
}
