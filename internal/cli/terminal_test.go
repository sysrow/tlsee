package cli

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestNonTerminalWriters(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	open := func(path string) *os.File {
		t.Helper()
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	null := open(os.DevNull)
	file := open(t.TempDir() + "/output.txt")
	closed := open(t.TempDir() + "/closed.txt")
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })

	for _, tc := range []struct {
		name string
		w    io.Writer
	}{
		{"buffer", &bytes.Buffer{}},
		{"null device", null},
		{"regular file", file},
		{"pipe reader", reader},
		{"pipe writer", writer},
		{"closed file", closed},
		{"nil file", (*os.File)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isTerminal(tc.w) {
				t.Error("non-terminal writer detected as a terminal")
			}
			if color, err := resolveColor("auto", tc.w); err != nil || color {
				t.Errorf("auto color = %t, %v; want false, nil", color, err)
			}
		})
	}
}
