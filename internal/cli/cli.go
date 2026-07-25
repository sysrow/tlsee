// Package cli implements the tlsee command-line interface: flag parsing,
// subcommand dispatch, output rendering, and exit-code computation. It is
// the only boundary besides main that is allowed to touch os-level
// terminal details; everything below it takes injected writers.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sysrow/tlsee/internal/report"
	"github.com/sysrow/tlsee/tlsscan"
)

// version is the tool's version, printed by the version subcommand. It defaults
// to "dev" for local builds and is overridden at release time with the git tag
// via -ldflags "-X 'github.com/sysrow/tlsee/internal/cli.version=v1.2.3'".
var version = "dev"

// toolVersion returns the version to report. Release binaries set version via
// ldflags. For a binary produced by "go install module@vX.Y.Z" no ldflags are
// applied, so fall back to the module version embedded in the build info.
func toolVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

// batchConcurrency caps how many hosts are scanned at once in batch mode.
const batchConcurrency = 16

// errNoTargets is returned when neither positional arguments nor a host file
// supply any target to scan.
var errNoTargets = errors.New("at least one target is required")

// Exit codes returned by Run.
const (
	exitOK       = 0 // healthy certificate, or explicitly requested help (or a problem suppressed by --insecure)
	exitError    = 1 // runtime error: bad flags, missing/extra args, unknown command, connection failure
	exitCertProb = 2 // certificate problem, or usage shown for no-args
	// exitUsage (no-args usage) intentionally shares exitCertProb's value;
	// defining it in terms of exitCertProb keeps them from silently diverging.
	exitUsage = exitCertProb
)

// Run parses args, dispatches the subcommand, renders output to stdout,
// reports errors to stderr, and returns the process exit code. os.Exit is
// never called here; that is main's responsibility.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "sweep":
		return runSweep(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "tlsee %s\n", toolVersion())
		return exitOK
	case "help", "-h", "--help":
		// Help was explicitly requested, so it is the requested output:
		// write to stdout and succeed, keeping the tool pipeable.
		writeUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "tlsee: unknown command %q\n\n", args[0])
		writeUsage(stderr)
		return exitError
	}
}

// runScan handles the "scan" subcommand. It accepts one or more positional
// targets plus an optional -f/--file list, scanning a single target as a full
// report and multiple targets (or any --table run) as a concurrent summary
// table. The exit code is the worst per-host code.
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		port      = fs.String("port", "443", "port to connect to when the target omits one")
		timeout   = fs.Duration("timeout", 10*time.Second, "dial and handshake timeout")
		sni       = fs.String("sni", "", "SNI server name override (default: target host)")
		asJSON    = fs.Bool("json", false, "emit JSON instead of text")
		colorMode = fs.String("color", "auto", "color output: auto|always|never")
		warnDays  = fs.Int("warn-days", 30, "warn when a certificate expires within this many days")
		insecure  = fs.Bool("insecure", false, "always exit 0 even when the certificate has problems")
		noCheck   = fs.Bool("no-check", false, "skip SAN liveness checks (resolve + TCP-probe of each certificate name)")
		startTLS  = fs.String("starttls", "", "STARTTLS protocol to negotiate first: smtp|imap|pop3|ftp|postgres|ldap")
		allIPs    = fs.Bool("all-ips", false, "connect to every resolved A/AAAA address and compare certificates")
		table     = fs.Bool("table", false, "always print the summary table, even for a single target")
		quiet     = fs.Bool("quiet", false, "print only problems; print nothing when everything is healthy")
		file      = fs.String("file", "", "read targets from a file (one per line; # comments and blanks ignored)")
	)
	fs.StringVar(file, "f", "", "shorthand for --file")
	fs.BoolVar(quiet, "q", false, "shorthand for --quiet")

	// Render usage ourselves to the correct stream; suppress flag's automatic
	// usage so help and parse errors are handled explicitly below.
	fs.Usage = func() {}

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		// flag's own help handling covers -h, --help, -help and --h alike,
		// returning ErrHelp. Explicit help is the requested output, so print it
		// to stdout and succeed (and "scan host -- --help" treats --help as a
		// literal target rather than a help request).
		if errors.Is(err, flag.ErrHelp) {
			printScanUsage(stdout, fs)
			return exitOK
		}
		// A real flag-parse error was already printed to stderr by flag.
		printScanUsage(stderr, fs)
		return exitError
	}

	targets := positional
	if *file != "" {
		fileTargets, err := readHostFile(*file)
		if err != nil {
			fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
			return exitError
		}
		targets = append(targets, fileTargets...)
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "tlsee scan: "+errNoTargets.Error())
		printScanUsage(stderr, fs)
		return exitError
	}

	if err := validateStartTLS(*startTLS); err != nil {
		fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
		return exitError
	}

	useColor, err := resolveColor(*colorMode, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
		return exitError
	}

	opts := tlsscan.Options{
		Port:       *port,
		Timeout:    *timeout,
		ServerName: *sni,
		ResolveDNS: true,
		CheckSANs:  !*noCheck,
		StartTLS:   *startTLS,
		AllIPs:     *allIPs,
	}

	// Wire the root context to interrupt signals so Ctrl-C (SIGINT) or SIGTERM
	// cancels in-flight dials and handshakes cooperatively instead of
	// hard-killing the process. The context is already threaded down into Scan
	// and every dial/handshake/probe, so cancellation unwinds a run cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A single target with neither --table nor --quiet keeps the original
	// full-report behavior.
	if len(targets) == 1 && !*table && !*quiet {
		return scanSingle(ctx, stdout, stderr, targets[0], opts, *warnDays, *asJSON, useColor, *insecure)
	}

	return scanBatch(ctx, stdout, stderr, targets, opts, *warnDays, *asJSON, useColor, *quiet, *insecure)
}

// scanSingle scans one target and renders the full report. It returns the
// per-report exit code, or exitOK under --insecure.
func scanSingle(ctx context.Context, stdout, stderr io.Writer, target string, opts tlsscan.Options, warnDays int, asJSON, useColor, insecure bool) int {
	rep, err := tlsscan.Scan(ctx, target, opts)
	if err != nil {
		fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
		return exitError
	}

	// The configurable warn-days threshold is carried on the report so
	// rendering and exit-code logic share one source of truth.
	rep.WarnDays = warnDays

	if asJSON {
		if err := report.WriteJSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
			return exitError
		}
	} else {
		report.WriteText(stdout, rep, useColor)
	}

	if insecure {
		return exitOK
	}
	return exitCodeForReport(rep)
}

// scanBatch scans every target concurrently (bounded) and renders a summary
// table or JSON array. The returned exit code is the worst per-host code:
// exitCertProb if any certificate is unhealthy, exitError if any scan failed,
// else exitOK. When quiet is set healthy rows are omitted from output, but the
// exit code still reflects all hosts.
//
// Under --insecure only certificate problems are suppressed, never connection
// failures: this mirrors scanSingle, where a scan that fails to connect returns
// exitError regardless of --insecure. A blanket exitOK here would silently mask
// a down host in batch mode (a cron monitor would lose the down-host signal),
// so any host that failed to scan still yields exitError.
func scanBatch(ctx context.Context, stdout, stderr io.Writer, targets []string, opts tlsscan.Options, warnDays int, asJSON, useColor, quiet, insecure bool) int {
	rows := scanTargets(ctx, targets, opts, warnDays)

	if asJSON {
		if err := report.WriteBatchJSON(stdout, rows, quiet); err != nil {
			fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
			return exitError
		}
	} else {
		report.WriteBatchTable(stdout, rows, useColor, quiet)
	}

	if insecure {
		for _, row := range rows {
			if row.Err != "" {
				return exitError
			}
		}
		return exitOK
	}
	return worstExitCode(rows)
}

// scanTargets scans each target concurrently with a bounded worker pool,
// preserving input order in the returned rows. A scan error is recorded as the
// row's Err; a successful scan carries its report with WarnDays applied.
func scanTargets(ctx context.Context, targets []string, opts tlsscan.Options, warnDays int) []report.BatchRow {
	rows := make([]report.BatchRow, len(targets))
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		// Stop dispatching promptly on cancellation (Ctrl-C/SIGTERM). Targets
		// not yet dispatched are marked failed with the cancellation error: a
		// zero-valued row (no report, no error) would violate BatchRow's
		// invariant and panic the batch rendering and exit-code paths.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			for j := i; j < len(targets); j++ {
				rows[j] = report.BatchRow{Host: targets[j], Err: ctx.Err().Error()}
			}
			wg.Wait()
			return rows
		}
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			rep, err := tlsscan.Scan(ctx, target, opts)
			if err != nil {
				rows[i] = report.BatchRow{Host: target, Err: err.Error()}
				return
			}
			rep.WarnDays = warnDays
			rows[i] = report.BatchRow{Host: target, Report: rep}
		}(i, target)
	}
	wg.Wait()
	return rows
}

// worstExitCode returns the most severe exit code across all batch rows: a
// scan failure contributes exitError and a certificate problem exitCertProb.
// exitCertProb outranks exitError because a present-but-broken certificate is
// the more actionable finding for a monitoring run.
func worstExitCode(rows []report.BatchRow) int {
	worst := exitOK
	for _, row := range rows {
		code := exitOK
		if row.Err != "" {
			code = exitError
		} else {
			code = exitCodeForReport(row.Report)
		}
		if code > worst {
			worst = code
		}
	}
	return worst
}

// parseInterspersed parses fs from args while allowing positional targets to
// appear before, after, or among the flags. The stdlib flag package stops at
// the first non-flag argument, so Parse is re-invoked on the arguments that
// follow each positional until every flag is consumed. It returns all
// positional targets in the order they appeared (possibly none, since targets
// may instead come from a host file).
//
// A "--" end-of-flags terminator is honored once, at the top level: everything
// after the first "--" is treated as positional verbatim and never re-parsed as
// flags. The stdlib flag package only honors "--" within a single Parse call,
// so without this the terminator would lose effect on the loop's later
// iterations. Splitting here keeps standard Unix flag semantics for both the
// scan and sweep subcommands, which share this function.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	rest := args
	var trailing []string
	for i, a := range args {
		if a == "--" {
			rest = args[:i]
			trailing = args[i+1:]
			break
		}
	}

	var targets []string
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		targets = append(targets, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	targets = append(targets, trailing...)
	return targets, nil
}

// readHostFile opens path and parses its target lines. It wraps the errors
// so the caller reports a clear message; parsing itself is delegated to
// parseHostList so it can be tested without disk.
func readHostFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read host file: %w", err)
	}
	defer f.Close()
	targets, err := parseHostList(f)
	if err != nil {
		return nil, fmt.Errorf("read host file %s: %w", path, err)
	}
	return targets, nil
}

// parseHostList reads one target per line from r, trimming surrounding
// whitespace and skipping blank lines and lines whose first non-blank character
// is '#'. It takes an io.Reader so tests can supply an in-memory source. A
// read failure is returned as an error rather than silently truncating the
// list, which would make a monitoring run quietly watch fewer hosts.
func parseHostList(r io.Reader) ([]string, error) {
	var targets []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// runSweep handles the "sweep" subcommand: probe many ports of a single host
// and print a table of which ports speak TLS and the certificate each presents.
func runSweep(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		ports     = fs.String("ports", "", "ports to scan: comma list and/or ranges, e.g. 443,8443,9000-9100 (default: curated list)")
		full      = fs.Bool("full", false, "scan all ports 1-65535 (slow)")
		timeout   = fs.Duration("timeout", 3*time.Second, "per-port probe timeout")
		asJSON    = fs.Bool("json", false, "emit JSON instead of text")
		colorMode = fs.String("color", "auto", "color output: auto|always|never")
	)

	// Render usage ourselves; suppress flag's automatic usage.
	fs.Usage = func() {}

	hosts, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSweepUsage(stdout, fs)
			return exitOK
		}
		printSweepUsage(stderr, fs)
		return exitError
	}
	if len(hosts) != 1 {
		fmt.Fprintln(stderr, "tlsee sweep: exactly one host is required")
		printSweepUsage(stderr, fs)
		return exitError
	}
	host := hosts[0]

	if *ports != "" && *full {
		fmt.Fprintln(stderr, "tlsee sweep: --ports and --full are mutually exclusive")
		return exitError
	}

	useColor, err := resolveColor(*colorMode, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "tlsee sweep: %v\n", err)
		return exitError
	}

	opts := tlsscan.SweepOptions{Timeout: *timeout}
	switch {
	case *full:
		opts.Ports = fullPortRange()
		opts.Concurrency = 256
	case *ports != "":
		list, err := tlsscan.ParsePortSpec(*ports)
		if err != nil {
			fmt.Fprintf(stderr, "tlsee sweep: %v\n", err)
			return exitError
		}
		opts.Ports = list
	}

	// Wire the root context to interrupt signals so an interrupt during a long
	// sweep (up to 65535 ports under --full) cancels in-flight probes
	// cooperatively rather than hard-killing the process mid-handshake.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sr, err := tlsscan.Sweep(ctx, host, opts)
	if err != nil {
		fmt.Fprintf(stderr, "tlsee sweep: %v\n", err)
		return exitError
	}

	if *asJSON {
		if err := report.WriteSweepJSON(stdout, sr); err != nil {
			fmt.Fprintf(stderr, "tlsee sweep: %v\n", err)
			return exitError
		}
	} else {
		report.WriteSweepText(stdout, sr, useColor)
	}
	return exitOK
}

// fullPortRange returns every port 1-65535 for a --full sweep.
func fullPortRange() []int {
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports
}

// exitCodeForReport returns exitCertProb when the certificate is unhealthy
// and exitOK otherwise, using the report's own Healthy predicate so the exit
// code, the --quiet row filter, and the status all agree.
func exitCodeForReport(r *tlsscan.Report) int {
	if r.Healthy() {
		return exitOK
	}
	return exitCertProb
}

// startTLSProtocols is the set of accepted --starttls values; the empty string
// (direct TLS) is also valid and handled by validateStartTLS.
var startTLSProtocols = map[string]bool{
	"smtp": true, "imap": true, "pop3": true, "ftp": true, "postgres": true, "ldap": true,
}

// validateStartTLS rejects an unknown --starttls value up front, before any
// network work, mirroring the up-front --color enum check.
func validateStartTLS(proto string) error {
	if proto == "" || startTLSProtocols[proto] {
		return nil
	}
	return fmt.Errorf("invalid --starttls value %q (want smtp, imap, pop3, ftp, postgres, or ldap)", proto)
}

// resolveColor decides whether ANSI color should be emitted, honoring the
// --color mode, NO_COLOR, and whether stdout is a terminal. Terminal
// detection inspects the passed writer (not the os.Stdout global) so that
// tests using buffers naturally disable color.
func resolveColor(mode string, stdout io.Writer) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			return false, nil
		}
		return isTerminal(stdout), nil
	default:
		return false, fmt.Errorf("invalid --color value %q (want auto, always, or never)", mode)
	}
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// printScanUsage writes the scan subcommand usage and flag list to w.
func printScanUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "Usage: tlsee scan <target>... [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "One or more targets, and/or -f/--file with one target per line.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// printSweepUsage writes the sweep subcommand usage and flag list to w.
func printSweepUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "Usage: tlsee sweep <host> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Probe many ports of one host for TLS and report each certificate.")
	fmt.Fprintln(w, "By default a curated list of well-known TLS and STARTTLS ports is scanned.")
	fmt.Fprintln(w, "--full scans all 65535 ports and is slow.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// writeUsage prints top-level usage and exit-code documentation to w.
func writeUsage(w io.Writer) {
	fmt.Fprint(w, `tlsee - a friendly TLS certificate inspector

Usage:
  tlsee scan <target>... [flags]   Inspect the TLS certificate(s) at one or more targets
  tlsee sweep <host> [flags]       Probe many ports of a host for TLS certificates
  tlsee version                    Print the tlsee version
  tlsee help                       Show this help

Targets may be a hostname, host:port, IP, or URL. Examples:
  tlsee scan example.com
  tlsee scan https://example.com
  tlsee scan localhost:8443
  tlsee scan 127.0.0.1:8443
  tlsee scan [::1]:8443
  tlsee scan -f hosts.txt -q
  tlsee scan a.example.com b.example.com --table
  tlsee scan smtp.example.com --port 587 --starttls smtp
  tlsee sweep example.com
  tlsee sweep example.com --ports 443,8443,9000-9100

Scan flags:
  --port N            port to use when the target omits one (default 443)
  --timeout 10s       dial and handshake timeout (default 10s)
  --sni name          SNI server name override (default: target host)
  --starttls PROTO    negotiate STARTTLS first: smtp|imap|pop3|ftp|postgres|ldap
  --all-ips           connect to every resolved address and compare certificates
  --json              emit JSON instead of text
  --color MODE        auto|always|never (default auto)
  --warn-days N       warn when expiring within N days (default 30)
  --no-check          skip SAN liveness checks (on by default)
  --table             always print the summary table, even for one target
  -q, --quiet         print only problems; print nothing when all healthy
  -f, --file PATH     read targets from a file (one per line; # comments ignored)
  --insecure          always exit 0 even when the certificate has problems

With more than one target, or with --table, tlsee scans every target
concurrently and prints a summary table (HOST, DAYS, STATUS, NOTE), sorted by
urgency. --quiet prints only problem rows (a clean cron check); when used with
a single target it prints nothing for a healthy certificate. The exit code is
the worst per-host code.

Note: --quiet routes even a single target through the batch path, so
"scan host --quiet --json" emits a JSON array (one element for an unhealthy
host, empty/silent when healthy), whereas "scan host --json" without --quiet
emits a single JSON object. Scripts that parse single-host JSON should account
for this shape difference.

Sweep flags:
  --ports SPEC        comma list and/or ranges, e.g. 443,8443,9000-9100
  --full              scan all ports 1-65535 (slow)
  --timeout 3s        per-port probe timeout (default 3s)
  --json              emit JSON instead of text
  --color MODE        auto|always|never (default auto)

By default tlsee also resolves and TCP-probes every DNS name in the
certificate's SAN list and reports dead or stale entries (a name that no
longer resolves, or whose host is unreachable on the port). Dead SANs are
shown but do not change the exit code, which reflects the certificate's own
validity. Use --no-check to skip this.

Exit codes:
  0  healthy: trusted chain, hostname matches, valid, and not expiring soon
     (also when help is explicitly requested)
  1  runtime error: bad flags, missing target, unknown command, or
     connection failure
  2  usage shown for no arguments, or a certificate problem: expired, not
     yet valid, untrusted, hostname mismatch, or expiring within --warn-days
     (a certificate problem is suppressed by --insecure)

In batch mode the exit code is the worst per-host code: 2 if any certificate
has a problem, 1 if any host failed to scan, else 0.
`)
}
