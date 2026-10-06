package cli

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sysrow/tlsee/tlsscan"
)

// TestParseInterspersed verifies positional targets are extracted no matter
// where the flags sit relative to them, so "scan host --json" and
// "scan --json host" are both accepted, and that multiple targets are collected
// in order. Zero positional targets is not an error here: targets may instead
// come from -f/--file, and the caller enforces "at least one overall".
func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantTargets []string
		wantJSON    bool
		wantErr     bool
	}{
		{name: "target only", args: []string{"example.com"}, wantTargets: []string{"example.com"}},
		{name: "flag before target", args: []string{"--json", "example.com"}, wantTargets: []string{"example.com"}, wantJSON: true},
		{name: "flag after target", args: []string{"example.com", "--json"}, wantTargets: []string{"example.com"}, wantJSON: true},
		{name: "flags on both sides", args: []string{"--json", "example.com", "--color", "never"}, wantTargets: []string{"example.com"}, wantJSON: true},
		{name: "no positional target", args: []string{"--json"}, wantTargets: nil, wantJSON: true},
		{name: "two targets", args: []string{"a", "b"}, wantTargets: []string{"a", "b"}},
		{name: "two targets around flag", args: []string{"a", "--json", "b"}, wantTargets: []string{"a", "b"}, wantJSON: true},
		{name: "bad flag", args: []string{"--nope"}, wantErr: true},
		// Everything after "--" is positional verbatim: the "--json" following
		// "--" is a literal target, not a flag, so json stays false.
		{name: "end-of-flags terminator", args: []string{"a", "--", "b", "--json"}, wantTargets: []string{"a", "b", "--json"}},
		{name: "terminator before all positionals", args: []string{"--", "a", "--json"}, wantTargets: []string{"a", "--json"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("scan", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			asJSON := fs.Bool("json", false, "")
			fs.String("color", "auto", "")

			targets, err := parseInterspersed(fs, tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseInterspersed(%v) = (%v, nil); want error", tc.args, targets)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInterspersed(%v) unexpected error: %v", tc.args, err)
			}
			if !equalStrings(targets, tc.wantTargets) {
				t.Errorf("targets = %v; want %v", targets, tc.wantTargets)
			}
			if *asJSON != tc.wantJSON {
				t.Errorf("json = %v; want %v", *asJSON, tc.wantJSON)
			}
		})
	}
}

// TestParseInterspersedValueBoundaries distinguishes a terminator from a value
// consumed by a non-boolean flag. The standard parser remains responsible for
// validating values and producing help and error diagnostics.
func TestParseInterspersedValueBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantTargets []string
		wantFile    string
		wantJSON    bool
	}{
		{"double dash value", []string{"--file", "--", "host", "--json"}, []string{"host"}, "--", true},
		{"single dash flag", []string{"-file", "--", "host"}, []string{"host"}, "--", false},
		{"short alias", []string{"host", "-f", "--", "--json"}, []string{"host"}, "--", true},
		{"value between targets", []string{"first", "--file", "--", "second", "--json"}, []string{"first", "second"}, "--", true},
		{"value before terminator", []string{"--file", "--", "--", "--json", "--help", "--"}, []string{"--json", "--help", "--"}, "--", false},
		{"inline value", []string{"--file=--", "--", "--json"}, []string{"--json"}, "--", false},
		{"empty inline value", []string{"--file=", "--", "--json"}, []string{"--json"}, "", false},
		{"empty separate value", []string{"--file", "", "--json", "host"}, []string{"host"}, "", true},
		{"help as value", []string{"--file", "--help", "host"}, []string{"host"}, "--help", false},
		{"flag as value", []string{"--file", "--json", "host"}, []string{"host"}, "--json", false},
		{"single dash value", []string{"--file", "-", "host"}, []string{"host"}, "-", false},
		{"boolean before terminator", []string{"--json", "--", "--file", "--help"}, []string{"--file", "--help"}, "", true},
		{"explicit boolean before terminator", []string{"--json=false", "--", "--file"}, []string{"--file"}, "", false},
		{"boolean separate false is positional", []string{"--json", "false", "--file", "--"}, []string{"false"}, "--", true},
		{"terminator at end", []string{"host", "--"}, []string{"host"}, "", false},
		{"single dash positional", []string{"-", "--file", "--"}, []string{"-"}, "--", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("scan", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			file := fs.String("file", "", "")
			fs.StringVar(file, "f", "", "")
			asJSON := fs.Bool("json", false, "")
			targets, err := parseInterspersed(fs, tc.args)
			if err != nil {
				t.Fatalf("parseInterspersed(%q): %v", tc.args, err)
			}
			if !equalStrings(targets, tc.wantTargets) || *file != tc.wantFile || *asJSON != tc.wantJSON {
				t.Errorf("got targets=%q file=%q json=%t; want targets=%q file=%q json=%t", targets, *file, *asJSON, tc.wantTargets, tc.wantFile, tc.wantJSON)
			}
		})
	}
}

func TestParseInterspersedStandardDiagnostics(t *testing.T) {
	for _, args := range [][]string{
		{"--file"},
		{"--json", "--file"},
		{"--count", "--"},
		{"--json=--"},
		{"--unknown", "--"},
		{"---file", "--"},
		{"--file", "--", "--help"},
		{"--file", "--", "--h"},
		{"--file", "--", "-help"},
		{"--file", "--", "-h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			newFlags := func(output io.Writer) *flag.FlagSet {
				fs := flag.NewFlagSet("scan", flag.ContinueOnError)
				fs.SetOutput(output)
				fs.String("file", "", "")
				fs.Bool("json", false, "")
				fs.Int("count", 0, "")
				return fs
			}
			var standardOutput, output bytes.Buffer
			wantErr := newFlags(&standardOutput).Parse(args)
			if wantErr == nil {
				t.Fatal("expected standard parser error or help")
			}
			// A preceding positional must not alter a flag's diagnostics.
			_, err := parseInterspersed(newFlags(&output), append([]string{"host"}, args...))
			if err == nil || err.Error() != wantErr.Error() || errors.Is(err, flag.ErrHelp) != errors.Is(wantErr, flag.ErrHelp) {
				t.Errorf("error = %v; want %v", err, wantErr)
			}
			if output.String() != standardOutput.String() {
				t.Errorf("diagnostics = %q; want %q", output.String(), standardOutput.String())
			}
		})
	}
}

// equalStrings reports whether two string slices have the same elements in the
// same order, treating nil and empty as equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// healthyReport returns a report that passes every health predicate, so each
// test can flip exactly one condition to assert it drives the exit code.
func healthyReport() *tlsscan.Report {
	return &tlsscan.Report{
		ChainTrusted:  true,
		HostnameMatch: true,
		WarnDays:      30,
		Leaf: tlsscan.CertInfo{
			DaysRemaining: 90,
			Expired:       false,
			NotYetValid:   false,
		},
	}
}

func TestExitCodeForReport(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *tlsscan.Report)
		want   int
	}{
		{name: "healthy", mutate: func(*tlsscan.Report) {}, want: exitOK},
		{name: "expired", mutate: func(r *tlsscan.Report) { r.Leaf.Expired = true }, want: exitCertProb},
		{name: "not yet valid", mutate: func(r *tlsscan.Report) { r.Leaf.NotYetValid = true }, want: exitCertProb},
		{name: "untrusted chain", mutate: func(r *tlsscan.Report) { r.ChainTrusted = false }, want: exitCertProb},
		{name: "hostname mismatch", mutate: func(r *tlsscan.Report) { r.HostnameMatch = false }, want: exitCertProb},
		{
			name:   "at warn boundary is unhealthy",
			mutate: func(r *tlsscan.Report) { r.Leaf.DaysRemaining = r.WarnDays },
			want:   exitCertProb,
		},
		{
			name:   "one day past warn boundary is healthy",
			mutate: func(r *tlsscan.Report) { r.Leaf.DaysRemaining = r.WarnDays + 1 },
			want:   exitOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyReport()
			tc.mutate(r)
			if got := exitCodeForReport(r); got != tc.want {
				t.Errorf("exitCodeForReport() = %d; want %d", got, tc.want)
			}
		})
	}
}

func TestResolveColor(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		got, err := resolveColor("always", &bytes.Buffer{})
		if err != nil || !got {
			t.Errorf("resolveColor(always) = (%v, %v); want (true, nil)", got, err)
		}
	})

	t.Run("never", func(t *testing.T) {
		got, err := resolveColor("never", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(never) = (%v, %v); want (false, nil)", got, err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		got, err := resolveColor("sometimes", &bytes.Buffer{})
		if err == nil {
			t.Errorf("resolveColor(sometimes) = (%v, nil); want an error", got)
		}
	})

	t.Run("auto with NO_COLOR set", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		got, err := resolveColor("auto", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(auto, NO_COLOR) = (%v, %v); want (false, nil)", got, err)
		}
	})

	t.Run("auto with non-terminal writer", func(t *testing.T) {
		// With NO_COLOR unset, resolveColor falls through to isTerminal. A
		// *bytes.Buffer is not an *os.File character device, so color is
		// disabled by the terminal-detection path specifically. t.Setenv
		// records the original value and restores it on cleanup; the unset
		// makes this subtest exercise isTerminal rather than the NO_COLOR
		// short-circuit.
		t.Setenv("NO_COLOR", "")
		os.Unsetenv("NO_COLOR")
		got, err := resolveColor("auto", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(auto, buffer) = (%v, %v); want (false, nil)", got, err)
		}
	})
}

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantCode       int
		wantStdoutHas  string
		wantStderrHas  string
		wantStdoutOnly bool // output must be on stdout, stderr empty
	}{
		{
			name:           "version to stdout exit 0",
			args:           []string{"version"},
			wantCode:       exitOK,
			wantStdoutHas:  version,
			wantStdoutOnly: true,
		},
		{
			name:           "help to stdout exit 0",
			args:           []string{"help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "-h to stdout exit 0",
			args:           []string{"-h"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "--help to stdout exit 0",
			args:           []string{"--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "scan --help to stdout exit 0",
			args:           []string{"scan", "--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee scan",
			wantStdoutOnly: true,
		},
		{
			name:           "scan -help spelling also stdout exit 0",
			args:           []string{"scan", "-help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee scan",
			wantStdoutOnly: true,
		},
		{
			name:           "scan --h spelling also stdout exit 0",
			args:           []string{"scan", "--h"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee scan",
			wantStdoutOnly: true,
		},
		{
			name:           "scan help after double dash value",
			args:           []string{"scan", "host", "--file", "--", "--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee scan",
			wantStdoutOnly: true,
		},
		{
			name:           "sweep help after double dash value",
			args:           []string{"sweep", "host", "--ports", "--", "--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee sweep",
			wantStdoutOnly: true,
		},
		{
			name:          "scan validates double dash color value",
			args:          []string{"scan", "host", "--color", "--"},
			wantCode:      exitError,
			wantStderrHas: "invalid --color value",
		},
		{
			name:          "sweep validates double dash color value",
			args:          []string{"sweep", "host", "--color", "--"},
			wantCode:      exitError,
			wantStderrHas: "invalid --color value",
		},
		{
			name:          "scan invalid --starttls rejected up front exit 1",
			args:          []string{"scan", "example.com", "--starttls", "bogus"},
			wantCode:      exitError,
			wantStderrHas: "invalid --starttls",
		},
		{
			name:          "sweep --help to stdout exit 0",
			args:          []string{"sweep", "--help"},
			wantCode:      exitOK,
			wantStdoutHas: "Usage: tlsee sweep",
		},
		{
			name:          "no args to stderr exit 2",
			args:          []string{},
			wantCode:      exitUsage,
			wantStderrHas: "Usage:",
		},
		{
			name:          "unknown command exit 1",
			args:          []string{"frobnicate"},
			wantCode:      exitError,
			wantStderrHas: "unknown command",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run(tc.args, &stdout, &stderr)
			if got != tc.wantCode {
				t.Errorf("Run(%v) = %d; want %d", tc.args, got, tc.wantCode)
			}
			if tc.wantStdoutHas != "" && !strings.Contains(stdout.String(), tc.wantStdoutHas) {
				t.Errorf("stdout missing %q\n---\n%s", tc.wantStdoutHas, stdout.String())
			}
			if tc.wantStderrHas != "" && !strings.Contains(stderr.String(), tc.wantStderrHas) {
				t.Errorf("stderr missing %q\n---\n%s", tc.wantStderrHas, stderr.String())
			}
			if tc.wantStdoutOnly && stderr.Len() != 0 {
				t.Errorf("expected empty stderr, got:\n%s", stderr.String())
			}
		})
	}
}

// requestedOutputWriter fails at a byte boundary, allowing the tests to cover
// both immediately rejected output and partially written help or version text.
type requestedOutputWriter struct {
	remaining int
	err       error
}

func (w *requestedOutputWriter) Write(p []byte) (int, error) {
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return len(p), nil
	}
	n := w.remaining
	w.remaining = 0
	return n, w.err
}

func TestRequestedOutputFailure(t *testing.T) {
	outputErr := errors.New("output unavailable")
	for _, args := range [][]string{
		{"version"}, {"help"}, {"-h"}, {"--help"},
		{"scan", "--help"}, {"scan", "host", "-h"},
		{"sweep", "--help"}, {"sweep", "host", "-help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var successfulOutput, stderr bytes.Buffer
			if code := Run(args, &successfulOutput, &stderr); code != exitOK || stderr.Len() != 0 {
				t.Fatalf("successful output returned %d, stderr %q", code, stderr.String())
			}
			for _, limit := range []int{0, successfulOutput.Len() / 2, successfulOutput.Len() - 1} {
				for _, failure := range []error{outputErr, nil} {
					stderr.Reset()
					stdout := &requestedOutputWriter{remaining: limit, err: failure}
					if code := Run(args, stdout, &stderr); code != exitError {
						t.Errorf("limit %d: exit = %d; want %d", limit, code, exitError)
					}
					wantErr := failure
					if wantErr == nil {
						wantErr = io.ErrShortWrite
					}
					if !strings.Contains(stderr.String(), wantErr.Error()) {
						t.Errorf("limit %d: stderr = %q; want %q", limit, stderr.String(), wantErr)
					}
				}
			}
		})
	}
}

func TestDiagnosticOutputFailurePreservesExit(t *testing.T) {
	failure := outputErrorWriter{errors.New("output unavailable")}
	for _, args := range [][]string{{"help"}, {"version"}, {"scan", "--help"}, {"sweep", "--help"}} {
		var stdout bytes.Buffer
		if code := Run(args, &stdout, failure); code != exitOK {
			t.Errorf("Run(%q) = %d; successful stdout must not depend on unused stderr", args, code)
		}
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{nil, exitUsage},
		{[]string{"unknown"}, exitError},
		{[]string{"scan"}, exitError},
		{[]string{"scan", "--unknown"}, exitError},
		{[]string{"sweep"}, exitError},
		{[]string{"sweep", "--unknown"}, exitError},
		{[]string{"help"}, exitError},
		{[]string{"version"}, exitError},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			if code := Run(tc.args, failure, failure); code != tc.want {
				t.Errorf("exit = %d; want %d", code, tc.want)
			}
		})
	}
}
