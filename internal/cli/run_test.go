package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sysrow/tlsee/internal/report"
	"github.com/sysrow/tlsee/internal/tlsscan"
)

// TestParseHostList verifies blank lines, comment lines, and surrounding
// whitespace are stripped while order is preserved.
func TestParseHostList(t *testing.T) {
	in := `
# a comment
example.com
  spaced.example.com

# another comment
second.example.com
   # indented comment
`
	got, err := parseHostList(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseHostList error: %v", err)
	}
	want := []string{"example.com", "spaced.example.com", "second.example.com"}
	if !equalStrings(got, want) {
		t.Errorf("parseHostList = %v; want %v", got, want)
	}

	empty, err := parseHostList(strings.NewReader("\n# only comments\n\n"))
	if err != nil {
		t.Fatalf("parseHostList error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("parseHostList of comments-only = %v; want empty", empty)
	}
}

// TestParseHostListReadError verifies a read failure surfaces as an error
// instead of silently truncating the target list, which would make a cron
// monitor quietly watch fewer hosts than the file lists.
func TestParseHostListReadError(t *testing.T) {
	readErr := errors.New("disk error")
	if _, err := parseHostList(iotest.ErrReader(readErr)); !errors.Is(err, readErr) {
		t.Errorf("parseHostList with failing reader = %v; want %v", err, readErr)
	}
}

// TestScanTargetsCanceledContextFillsRows verifies that targets never
// dispatched because the context was canceled still produce a row carrying an
// error. A zero-valued row (no report, no error) violates BatchRow's invariant
// and makes batch rendering and exit-code computation dereference a nil
// report.
func TestScanTargetsCanceledContextFillsRows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	targets := make([]string, 40)
	for i := range targets {
		targets[i] = "192.0.2.1:9"
	}
	rows := scanTargets(ctx, targets, tlsscan.Options{Timeout: time.Second}, 30)

	if len(rows) != len(targets) {
		t.Fatalf("len(rows) = %d; want %d", len(rows), len(targets))
	}
	for i, row := range rows {
		if row.Err == "" && row.Report == nil {
			t.Fatalf("rows[%d] has neither report nor error; batch rendering would panic", i)
		}
		if row.Host == "" {
			t.Errorf("rows[%d].Host is empty; want the target preserved", i)
		}
	}
}

// TestWorstExitCode verifies the worst-of computation across batch rows: a
// certificate problem (2) outranks a scan failure (1), which outranks healthy
// (0).
func TestWorstExitCode(t *testing.T) {
	healthy := report.BatchRow{Host: "ok", Report: &tlsscan.Report{
		ChainTrusted: true, HostnameMatch: true, WarnDays: 30,
		Leaf: tlsscan.CertInfo{DaysRemaining: 90},
	}}
	problem := report.BatchRow{Host: "bad", Report: &tlsscan.Report{
		ChainTrusted: false, HostnameMatch: true, WarnDays: 30,
		Leaf: tlsscan.CertInfo{DaysRemaining: 90},
	}}
	failure := report.BatchRow{Host: "down", Err: "connect: timeout"}

	tests := []struct {
		name string
		rows []report.BatchRow
		want int
	}{
		{name: "all healthy", rows: []report.BatchRow{healthy, healthy}, want: exitOK},
		{name: "one failure", rows: []report.BatchRow{healthy, failure}, want: exitError},
		{name: "one problem", rows: []report.BatchRow{healthy, problem}, want: exitCertProb},
		{name: "problem beats failure", rows: []report.BatchRow{failure, problem}, want: exitCertProb},
		{name: "empty", rows: nil, want: exitOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := worstExitCode(tc.rows); got != tc.want {
				t.Errorf("worstExitCode() = %d; want %d", got, tc.want)
			}
		})
	}
}

// tlsTestServerTarget starts an httptest TLS server presenting an untrusted,
// self-signed certificate and returns a "127.0.0.1:port" target plus the
// server's Close cleanup. Scanning it yields an untrusted-chain problem (exit
// code 2), which the batch and quiet tests rely on.
func tlsTestServerTarget(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		srv.Close()
		t.Fatalf("split host port: %v", err)
	}
	return net.JoinHostPort(host, port), srv.Close
}

// closedTarget binds and immediately closes a local listener, returning its
// address so a scan against it fails to connect (exit code 1).
func closedTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestRunScanSingleProblem verifies a single untrusted target prints a report
// and returns the certificate-problem exit code.
func TestRunScanSingleProblem(t *testing.T) {
	target, closeSrv := tlsTestServerTarget(t)
	defer closeSrv()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", target, "--color", "never", "--no-check"}, &stdout, &stderr)
	if code != exitCertProb {
		t.Fatalf("Run scan single = %d; want %d\nstderr: %s", code, exitCertProb, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Status:") {
		t.Errorf("single-host report missing Status line:\n%s", stdout.String())
	}
}

// TestRunScanSingleQuietProblemPrints verifies that with --quiet a single
// unhealthy target still prints its report and returns the problem code.
func TestRunScanSingleQuietProblemPrints(t *testing.T) {
	target, closeSrv := tlsTestServerTarget(t)
	defer closeSrv()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", target, "--color", "never", "--no-check", "-q"}, &stdout, &stderr)
	if code != exitCertProb {
		t.Fatalf("Run scan quiet problem = %d; want %d", code, exitCertProb)
	}
	// In quiet single-host mode a problem falls through to the batch table,
	// which prints the problem row.
	if stdout.Len() == 0 {
		t.Errorf("quiet mode printed nothing for an unhealthy certificate")
	}
}

// TestRunScanBatchWorstOf verifies a multi-target scan prints a summary table
// and returns the worst per-host exit code (a connection failure plus a cert
// problem yields the cert-problem code).
func TestRunScanBatchWorstOf(t *testing.T) {
	target, closeSrv := tlsTestServerTarget(t)
	defer closeSrv()
	closed := closedTarget(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", target, closed, "--color", "never", "--no-check"}, &stdout, &stderr)
	if code != exitCertProb {
		t.Fatalf("batch worst-of = %d; want %d\nstdout:%s", code, exitCertProb, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "STATUS") {
		t.Errorf("batch output missing table header:\n%s", out)
	}
	// Errored host sorts to the top.
	if !strings.Contains(out, "ERROR") {
		t.Errorf("batch table missing the errored host:\n%s", out)
	}
}

// TestRunScanBatchInsecure verifies --insecure in batch mode mirrors single
// mode: certificate problems are suppressed (exit 0), but a connection failure
// is never masked (exit 1), so a cron monitor keeps the down-host signal.
func TestRunScanBatchInsecure(t *testing.T) {
	t.Run("cert problem suppressed", func(t *testing.T) {
		t1, c1 := tlsTestServerTarget(t)
		defer c1()
		t2, c2 := tlsTestServerTarget(t)
		defer c2()

		var stdout, stderr bytes.Buffer
		code := Run([]string{"scan", t1, t2, "--color", "never", "--no-check", "--insecure"}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("insecure batch of cert problems = %d; want %d\nstderr:%s", code, exitOK, stderr.String())
		}
	})

	t.Run("connection failure preserved", func(t *testing.T) {
		target, closeSrv := tlsTestServerTarget(t)
		defer closeSrv()
		closed := closedTarget(t)

		var stdout, stderr bytes.Buffer
		code := Run([]string{"scan", target, closed, "--color", "never", "--no-check", "--insecure"}, &stdout, &stderr)
		if code != exitError {
			t.Fatalf("insecure batch with a down host = %d; want %d\nstdout:%s", code, exitError, stdout.String())
		}
	})
}

// TestRunScanBatchJSON verifies --json in batch mode emits a JSON array.
func TestRunScanBatchJSON(t *testing.T) {
	t1, c1 := tlsTestServerTarget(t)
	defer c1()
	t2, c2 := tlsTestServerTarget(t)
	defer c2()

	var stdout, stderr bytes.Buffer
	Run([]string{"scan", t1, t2, "--json", "--no-check"}, &stdout, &stderr)
	var items []json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &items); err != nil {
		t.Fatalf("batch JSON not an array: %v\n%s", err, stdout.String())
	}
	if len(items) != 2 {
		t.Errorf("batch JSON length = %d; want 2", len(items))
	}
}

// TestRunScanQuietBatchPrintsProblems verifies quiet batch mode prints the
// failing rows (the all-healthy-is-silent direction is covered deterministically
// by the report layer's TestWriteBatchTableQuiet, since tests cannot mint a
// trusted certificate).
func TestRunScanQuietBatchPrintsProblems(t *testing.T) {
	closed1 := closedTarget(t)
	closed2 := closedTarget(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", closed1, closed2, "--color", "never", "-q"}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("quiet batch of failures = %d; want %d", code, exitError)
	}
	if !strings.Contains(stdout.String(), "ERROR") {
		t.Errorf("quiet batch did not print failing rows:\n%s", stdout.String())
	}
}

// TestRunScanFileFlag verifies targets are read from a file via -f and combined
// with positional targets.
func TestRunScanFileFlag(t *testing.T) {
	t1, c1 := tlsTestServerTarget(t)
	defer c1()
	t2, c2 := tlsTestServerTarget(t)
	defer c2()

	dir := t.TempDir()
	hostFile := dir + "/hosts.txt"
	if err := os.WriteFile(hostFile, []byte("# hosts\n"+t2+"\n"), 0o600); err != nil {
		t.Fatalf("write host file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	// One positional plus one from the file -> batch mode (2 targets).
	Run([]string{"scan", t1, "-f", hostFile, "--json", "--no-check"}, &stdout, &stderr)
	var items []json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &items); err != nil {
		t.Fatalf("file+positional JSON not an array: %v\n%s", err, stdout.String())
	}
	if len(items) != 2 {
		t.Errorf("combined target count = %d; want 2", len(items))
	}
}

// TestRunScanNoTargets verifies an empty target set is a usage error.
func TestRunScanNoTargets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", "--json"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("scan with no targets = %d; want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "at least one target") {
		t.Errorf("stderr missing no-targets message:\n%s", stderr.String())
	}
}

// TestRunSweepText verifies the sweep subcommand probes the live TLS port and
// renders the table.
func TestRunSweepText(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"sweep", "127.0.0.1", "--ports", port, "--color", "never"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("sweep exit = %d; want %d\nstderr:%s", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"PORT", "PROTO", "STATUS", port} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep output missing %q:\n%s", want, out)
		}
	}
}

// TestRunSweepJSON verifies the sweep --json path emits a sweep object.
func TestRunSweepJSON(t *testing.T) {
	closed := closedTarget(t)
	host, port, err := net.SplitHostPort(closed)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"sweep", host, "--ports", port, "--json"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("sweep json exit = %d; want %d", code, exitOK)
	}
	var sr tlsscan.SweepResult
	if err := json.Unmarshal(stdout.Bytes(), &sr); err != nil {
		t.Fatalf("sweep JSON did not parse: %v\n%s", err, stdout.String())
	}
	if len(sr.Ports) != 1 || sr.Ports[0].Open {
		t.Errorf("sweep of a closed port = %+v; want one closed port", sr.Ports)
	}
}

// TestRunSweepBadPorts verifies an invalid --ports spec is a usage error.
func TestRunSweepBadPorts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"sweep", "example.com", "--ports", "notaport"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("sweep bad ports = %d; want %d", code, exitError)
	}
}

// TestRunSweepHelp verifies sweep --help prints usage to stdout and exits 0.
func TestRunSweepHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"sweep", "--help"}, &stdout, &stderr)
	if code != exitOK {
		t.Errorf("sweep --help exit = %d; want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: tlsee sweep") {
		t.Errorf("sweep help missing usage:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("sweep help wrote to stderr:\n%s", stderr.String())
	}
}
