// Package report renders a tlsscan.Report as human-readable text or JSON.
//
// Rendering is kept separate from scanning and never consults the wall
// clock: it relies entirely on the precomputed fields of the report
// (DaysRemaining, Expired, NotYetValid, WarnDays) so output is
// deterministic and testable.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/sysrow/tlsee/tlsscan"
)

// ANSI color codes used only when color output is enabled.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
	// colorMagenta is reserved for one condition: a SAN name that no longer
	// points at the scanned host. Keeping it exclusive is what makes a moved
	// name visually distinct from a healthy one (green) and from a dead or
	// degraded one (red, yellow).
	colorMagenta = "\033[35m"
)

// sweepWarnDays is the days-remaining threshold below which a sweep reports a
// certificate as expiring. The sweep subcommand has no --warn-days flag, so this
// matches the scan default for consistency.
const sweepWarnDays = 30

// status describes the overall health summary of a report.
type status struct {
	text  string
	color string
}

// summarize combines the report's conditions into a single prominent
// status. The most severe problem wins; an otherwise healthy certificate
// that is expiring within WarnDays is reported as expiring soon.
//
// Dead SANs and SAN names that have moved to another host are non-red
// advisories, not certificate problems: they do not change the exit code and a
// certificate carrying only those stays "healthy" for --quiet, so they must
// neither erase the healthy VALID indicator nor turn the headline red. When the
// certificate is otherwise valid the headline reads "VALID | <advisory>" in
// yellow; when there is already a real problem the advisory is appended without
// escalating the color.
func summarize(r *tlsscan.Report) status {
	var problems []string
	worst := colorYellow

	if r.Leaf.Expired {
		problems = append(problems, "EXPIRED")
		worst = colorRed
	}
	if r.Leaf.NotYetValid {
		problems = append(problems, "NOT YET VALID")
		worst = colorRed
	}
	if !r.ChainTrusted {
		problems = append(problems, "UNTRUSTED CHAIN")
		worst = colorRed
	}
	if !r.HostnameMatch {
		problems = append(problems, "HOSTNAME MISMATCH")
		worst = colorRed
	}
	if !r.Leaf.Expired && !r.Leaf.NotYetValid && r.Leaf.DaysRemaining <= r.WarnDays {
		problems = append(problems, expiringStatus(r.Leaf.DaysRemaining))
	}

	advisory := sanAdvisory(r)

	// If nothing above flagged a real certificate problem, the certificate is
	// healthy. The SAN advisory is then appended to the VALID headline as a
	// non-red note rather than replacing it.
	if len(problems) == 0 {
		if advisory != "" {
			return status{text: "VALID | " + advisory, color: colorYellow}
		}
		return status{text: "VALID", color: colorGreen}
	}

	// A real problem exists. Append the SAN advisory for visibility, but do not
	// let it escalate the color beyond what the real problems already set.
	if advisory != "" {
		problems = append(problems, advisory)
	}
	return status{text: strings.Join(problems, " | "), color: worst}
}

// deadSANStatus renders the count of dead/stale SAN names for the headline.
func deadSANStatus(n int) string {
	if n == 1 {
		return "1 DEAD SAN"
	}
	return fmt.Sprintf("%d DEAD SANS", n)
}

// elsewhereSANStatus renders the count of SAN names that no longer point at the
// scanned host, for the headline.
func elsewhereSANStatus(n int) string {
	if n == 1 {
		return "1 SAN ELSEWHERE"
	}
	return fmt.Sprintf("%d SANS ELSEWHERE", n)
}

// sanAdvisory renders the advisory SAN notes for the headline: names that are
// dead and names that have moved to another host. Both are informational and
// must never escalate the headline color, so callers append the result without
// changing the color the real problems already set. It returns "" when there is
// nothing to report.
func sanAdvisory(r *tlsscan.Report) string {
	var parts []string
	if r.DeadSANs > 0 {
		parts = append(parts, deadSANStatus(r.DeadSANs))
	}
	if r.SANsElsewhere > 0 {
		parts = append(parts, elsewhereSANStatus(r.SANsElsewhere))
	}
	return strings.Join(parts, " | ")
}

// sanitize strips control characters from untrusted, certificate- or
// target-derived strings before they are printed to a terminal. Certificate
// subjects, issuers, SAN names, verify errors, and target hosts are all
// attacker-influenced; a malicious server could embed ANSI escape sequences
// (ESC, 0x1b) or other C0/C1 control bytes to forge or corrupt the terminal
// output (clearing the screen, overwriting earlier lines, hiding text).
//
// It iterates runes (not bytes) so legitimate multibyte UTF-8 in a subject or
// SAN is preserved intact, and drops any control rune (C0, DEL, the C1 range,
// and ESC). A horizontal tab is replaced with a space rather than dropped:
// sanitize is applied to tabwriter cell content, where the layout tabs come
// from the render format strings, so a tab inside a value would open a bogus
// column and let a malicious value shift or forge the table. It is applied
// only on the text and table paths; the JSON paths are left untouched because
// encoding/json already escapes control characters.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case !unicode.IsControl(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeJoin sanitizes each element of parts and joins them with sep. It is
// used for lists of untrusted names (SAN DNS names, SAN IP addresses) so a
// control character in any single element cannot survive into the rendered
// line.
func sanitizeJoin(parts []string, sep string) string {
	cleaned := make([]string, len(parts))
	for i, p := range parts {
		cleaned[i] = sanitize(p)
	}
	return strings.Join(cleaned, sep)
}

// paint wraps s in an ANSI color when enabled, otherwise returns it
// unchanged.
func paint(s, color string, enabled bool) string {
	if !enabled || color == "" {
		return s
	}
	return color + s + colorReset
}

// WriteText renders the report as an aligned, scannable text block. ANSI
// color is applied only when color is true.
func WriteText(w io.Writer, r *tlsscan.Report, color bool) {
	st := summarize(r)

	target := r.Target
	if target == "" {
		target = r.Host
	}
	target = sanitize(target)

	fmt.Fprintf(w, "%s %s\n", paint("tlsee", colorBold, color), target)
	fmt.Fprintf(w, "Status: %s\n", paint(st.text, st.color+colorBold, color))
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)

	row := func(label, value string) {
		fmt.Fprintf(tw, "  %s\t%s\n", label, value)
	}

	// SAN DNS names are the primary thing the user wants to see.
	sans := r.Leaf.DNSNames
	if len(sans) == 0 {
		row("SAN DNS", paint("(none)", colorYellow, color))
	} else {
		row("SAN DNS", sanitizeJoin(sans, ", "))
	}
	if len(r.Leaf.IPAddresses) > 0 {
		row("SAN IPs", sanitizeJoin(r.Leaf.IPAddresses, ", "))
	}

	row("Subject", sanitize(r.Leaf.Subject))
	row("Issuer", sanitize(r.Leaf.Issuer))
	row("Serial", r.Leaf.SerialNumber)

	row("Not before", r.Leaf.NotBefore.Format("2006-01-02 15:04:05 MST"))
	expiry := r.Leaf.NotAfter.Format("2006-01-02 15:04:05 MST")
	expiry += fmt.Sprintf("  (%s)", daysPhrase(r.Leaf.DaysRemaining))
	row("Not after", paint(expiry, expiryColor(r), color))

	row("Trusted chain", boolText(r.ChainTrusted, color))
	if r.VerifyError != "" {
		row("Trust error", paint(sanitize(r.VerifyError), colorRed, color))
	}
	row("Hostname match", boolText(r.HostnameMatch, color))

	row("TLS version", r.TLSVersion)
	row("Cipher suite", r.CipherSuite)
	row("Signature", r.Leaf.SignatureAlgorithm)
	row("Public key", r.Leaf.PublicKeyAlgorithm)
	row("SHA-256", r.Leaf.FingerprintSHA256)

	if len(r.ResolvedIPs) > 0 {
		row("Resolved IPs", strings.Join(r.ResolvedIPs, ", "))
	} else {
		row("Resolved IPs", "(none)")
	}

	if len(r.Chain) > 0 {
		row("Chain depth", fmt.Sprintf("%d additional certificate(s)", len(r.Chain)))
	}

	row("Elapsed", fmt.Sprintf("%d ms", r.ElapsedMs))

	tw.Flush()

	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Warnings:")
		for _, warning := range r.Warnings {
			fmt.Fprintf(w, "    %s\n", paint(warning, colorYellow, color))
		}
	}

	if len(r.SANChecks) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  SAN liveness:")
		stw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, c := range r.SANChecks {
			addrs, state, stColor := sanLiveness(c)
			fmt.Fprintf(stw, "    %s\t%s\t%s\n", sanitize(c.Name), addrs, paint(state, stColor, color))
		}
		stw.Flush()
	}

	if len(r.IPCerts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Per-IP certificates:")
		if r.IPCertsDiffer {
			fmt.Fprintf(w, "    %s\n", paint("certificates differ across IPs", colorRed+colorBold, color))
		}
		itw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, ic := range r.IPCerts {
			ipText := sanitize(ic.IP)
			if ic.Error != "" {
				fmt.Fprintf(itw, "    %s\t%s\n", ipText, paint(sanitize(ic.Error), colorRed, color))
				continue
			}
			cn := sanitize(ic.SubjectCN)
			if cn == "" {
				cn = "(no CN)"
			}
			// When the certificates differ across IPs, append a short fingerprint
			// prefix so otherwise-identical rows (same CN, same expiry) are visibly
			// distinct and the reader can see which address serves which cert. The
			// matching case stays narrow with no fingerprint column.
			if r.IPCertsDiffer {
				fmt.Fprintf(itw, "    %s\t%s\t%s\t%s\n", ipText, cn, daysPhrase(ic.DaysRemaining), shortFingerprint(ic.FingerprintSHA256))
				continue
			}
			fmt.Fprintf(itw, "    %s\t%s\t%s\n", ipText, cn, daysPhrase(ic.DaysRemaining))
		}
		itw.Flush()
	}

	if len(r.Chain) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Chain:")
		for i, c := range r.Chain {
			subject := certName(c.SubjectCN, c.Subject)
			issuer := certName(c.IssuerCN, c.Issuer)
			fmt.Fprintf(w, "    [%d]  %s  ->  %s\n", i+1, subject, issuer)
		}
	}
}

// certName returns the common name when present, falling back to the full
// distinguished name. It keeps the text chain narrow (one short line per cert)
// while the full DN remains available in JSON. Both inputs are
// certificate-derived and therefore sanitized before display.
func certName(cn, full string) string {
	if cn != "" {
		return sanitize(cn)
	}
	if full != "" {
		return sanitize(full)
	}
	return "(unknown)"
}

// shortFingerprint returns a brief, human-comparable prefix of a colon-separated
// SHA-256 fingerprint for use as a per-IP discriminator. It keeps the first eight
// hex byte groups (for example "AA:BB:CC:DD:EE:FF:00:11") so differing
// certificates render as visibly distinct rows without printing the full 32-byte
// digest. An empty fingerprint yields "?".
func shortFingerprint(fp string) string {
	if fp == "" {
		return "?"
	}
	const groups = 8
	parts := strings.SplitN(fp, ":", groups+1)
	if len(parts) > groups {
		return strings.Join(parts[:groups], ":") + ":..."
	}
	return fp
}

// WriteJSON renders the report as indented JSON. Color is never applied.
func WriteJSON(w io.Writer, r *tlsscan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// BatchRow pairs a target host with either its scan report or the error that
// scanning it produced. Exactly one of Report and Err is meaningful: when Err is
// non-empty the scan failed and Report is nil. It is the unit of the batch
// summary table and the batch JSON array.
type BatchRow struct {
	Host   string
	Report *tlsscan.Report
	Err    string
}

// batchStatus is the per-row status word, day count, advisory note, and color
// derived from a BatchRow for the summary table.
type batchStatus struct {
	status string
	days   string
	note   string
	color  string
}

// rowStatus reduces a BatchRow to its display fields. Errors sort and render
// first; otherwise the most severe certificate problem wins, mirroring
// summarize but as compact one-word column values.
func rowStatus(row BatchRow) batchStatus {
	if row.Err != "" {
		return batchStatus{status: "ERROR", days: "ERR", note: "-", color: colorRed}
	}
	r := row.Report
	// The note stays a bare dead count in the common case, and only widens to
	// name both figures when some name has moved away from the host.
	note := fmt.Sprintf("%d", r.DeadSANs)
	if r.SANsElsewhere > 0 {
		note = fmt.Sprintf("%d dead, %d elsewhere", r.DeadSANs, r.SANsElsewhere)
	}
	days := fmt.Sprintf("%d", r.Leaf.DaysRemaining)
	switch {
	case r.Leaf.Expired, r.Leaf.NotYetValid:
		return batchStatus{status: "EXPIRED", days: days, note: note, color: colorRed}
	case !r.ChainTrusted:
		return batchStatus{status: "UNTRUSTED", days: days, note: note, color: colorRed}
	case !r.HostnameMatch:
		return batchStatus{status: "MISMATCH", days: days, note: note, color: colorRed}
	case r.Leaf.DaysRemaining <= r.WarnDays:
		return batchStatus{status: "EXPIRING", days: days, note: note, color: colorYellow}
	default:
		return batchStatus{status: "VALID", days: days, note: note, color: colorGreen}
	}
}

// batchSortKey orders rows for the summary table: most urgent first. Errored
// rows sort to the very top; among scanned rows, fewer days remaining sorts
// earlier. Ties break by host name for stable, deterministic output.
func batchSortKey(rows []BatchRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		ei, ej := rows[i].Err != "", rows[j].Err != ""
		if ei != ej {
			return ei // errors first
		}
		if ei && ej {
			return rows[i].Host < rows[j].Host
		}
		di, dj := rows[i].Report.Leaf.DaysRemaining, rows[j].Report.Leaf.DaysRemaining
		if di != dj {
			return di < dj
		}
		return rows[i].Host < rows[j].Host
	})
}

// WriteBatchTable renders one row per host as an aligned summary table sorted by
// urgency (errored hosts first, then fewest days remaining). When quiet is true,
// healthy rows are omitted; if every row is healthy nothing is written. The
// passed slice is sorted in place.
func WriteBatchTable(w io.Writer, rows []BatchRow, color, quiet bool) {
	batchSortKey(rows)

	visible := rows
	if quiet {
		visible = visible[:0:0]
		for _, row := range rows {
			if rowIsHealthy(row) {
				continue
			}
			visible = append(visible, row)
		}
		if len(visible) == 0 {
			return
		}
	}

	// The last column is labeled NOTE rather than DEAD: it honestly covers both
	// the dead-SAN count on a successful row and the free-text scan error on a
	// failed row, instead of putting an error message under a "dead SAN count"
	// header.
	//
	// Column layout is computed on the uncolored cells: tabwriter measures byte
	// width, so a colored STATUS cell would make it count the invisible ANSI
	// escape bytes and push the NOTE header out of alignment. The table is laid
	// out monochrome into a buffer first, then the STATUS word on each data line
	// is wrapped in color afterwards (color codes have zero visible width, so the
	// alignment already computed still holds).
	var plain strings.Builder
	tw := tabwriter.NewWriter(&plain, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tDAYS\tSTATUS\tNOTE")
	statuses := make([]batchStatus, len(visible))
	for i, row := range visible {
		bs := rowStatus(row)
		statuses[i] = bs
		note := bs.note
		if row.Err != "" {
			note = sanitize(row.Err)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", sanitize(row.Host), bs.days, bs.status, note)
	}
	tw.Flush()

	if !color {
		io.WriteString(w, plain.String())
		return
	}

	// Colorize the laid-out table line by line. The header is line 0; each
	// subsequent line maps in order to statuses[i]. Only the first run of the
	// already-padded status word is recolored, so a status token appearing inside
	// a host or note cell is never touched.
	lines := strings.SplitAfter(plain.String(), "\n")
	for i, line := range lines {
		if i == 0 || i-1 >= len(statuses) || line == "" {
			io.WriteString(w, line)
			continue
		}
		bs := statuses[i-1]
		io.WriteString(w, colorizeStatusCell(line, bs.status, bs.color))
	}
}

// colorizeStatusCell wraps the first occurrence of the padded status word in
// line with the given color. The word is matched as a whole, space-delimited
// token (the only place a bare status word stands alone in a laid-out row) so a
// coincidental substring in the host or note column is left untouched. Because
// the surrounding spaces and the word's visible width are unchanged, the column
// alignment computed by tabwriter is preserved.
func colorizeStatusCell(line, word, color string) string {
	if word == "" || color == "" {
		return line
	}
	idx := strings.Index(line, word)
	for idx >= 0 {
		before := idx == 0 || line[idx-1] == ' '
		end := idx + len(word)
		after := end >= len(line) || line[end] == ' ' || line[end] == '\n'
		if before && after {
			return line[:idx] + color + word + colorReset + line[end:]
		}
		next := strings.Index(line[idx+1:], word)
		if next < 0 {
			break
		}
		idx = idx + 1 + next
	}
	return line
}

// rowIsHealthy reports whether a batch row needs no attention: a successful scan
// of a certificate that is trusted, hostname-matching, currently valid, and not
// within its warn window. It mirrors the cli exit-code health predicate so quiet
// mode hides exactly the rows that would not change the exit code. Dead SANs do
// not make a row unhealthy here, matching the exit-code contract.
func rowIsHealthy(row BatchRow) bool {
	if row.Err != "" {
		return false
	}
	return row.Report.Healthy()
}

// WriteBatchJSON renders the batch as a JSON array. Each healthy or unhealthy
// scan is emitted as its full report; each failed scan is emitted as a
// {host, error} object. When quiet is true, healthy rows are omitted and, if
// nothing remains, nothing is written at all (so quiet JSON stays silent for an
// all-healthy run, matching the text path). The passed slice is sorted in place
// to match the table ordering.
func WriteBatchJSON(w io.Writer, rows []BatchRow, quiet bool) error {
	batchSortKey(rows)

	type failure struct {
		Host  string `json:"host"`
		Error string `json:"error"`
	}

	items := make([]any, 0, len(rows))
	for _, row := range rows {
		if quiet && rowIsHealthy(row) {
			continue
		}
		if row.Err != "" {
			items = append(items, failure{Host: row.Host, Error: row.Err})
			continue
		}
		items = append(items, row.Report)
	}

	// In quiet mode, an empty result means every host was healthy: stay silent
	// rather than emitting an empty array, so a clean run produces no output.
	if quiet && len(items) == 0 {
		return nil
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(items); err != nil {
		return fmt.Errorf("encode batch: %w", err)
	}
	return nil
}

// WriteSweepText renders a port sweep as a table sorted by port. Closed ports
// and ports without TLS are reported alongside the certificates found. The CERT
// column shows the leaf subject common name; the STATUS column summarizes
// validity (VALID, EXPIRING Nd, EXPIRED, NOT YET VALID, no TLS, or closed).
func WriteSweepText(w io.Writer, sr *tlsscan.SweepResult, color bool) {
	fmt.Fprintf(w, "%s %s\n\n", paint("tlsee sweep", colorBold, color), sanitize(sr.Host))

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tPROTO\tCERT\tSTATUS")
	for _, p := range sr.Ports {
		status, stColor := sweepStatus(p)
		cert := sanitize(p.SubjectCN)
		if cert == "" {
			cert = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", p.Port, p.Proto, cert, paint(status, stColor, color))
	}
	tw.Flush()
}

// sweepStatus maps a port probe result to its STATUS column word and color.
func sweepStatus(p tlsscan.PortResult) (string, string) {
	switch {
	case !p.Open:
		return "closed", ""
	case !p.TLS:
		return "no TLS", colorYellow
	case p.Expired:
		return "EXPIRED", colorRed
	case p.NotYetValid:
		return "NOT YET VALID", colorRed
	case p.DaysRemaining <= sweepWarnDays:
		return fmt.Sprintf("EXPIRING %dd", p.DaysRemaining), colorYellow
	default:
		return "VALID", colorGreen
	}
}

// WriteSweepJSON renders a sweep result as indented JSON.
func WriteSweepJSON(w io.Writer, sr *tlsscan.SweepResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sr); err != nil {
		return fmt.Errorf("encode sweep: %w", err)
	}
	return nil
}

// sanLiveness renders one SAN check as an address list, a state word, and the
// color for that state. A name is "open" when every resolved address is
// reachable, "partial" when only some are (for example an unreachable IPv6
// address alongside a reachable IPv4 one), "unreachable" when none are, and
// "NO DNS" when it does not resolve at all. Wildcard names are not probed.
//
// A reachable name that resolves away from the scanned host reports its
// ownership instead of open/partial: that a name has moved matters more than
// one of its addresses being down, and the per-address detail is not lost since
// the address column still marks the specific address "(down)".
func sanLiveness(c tlsscan.SANCheck) (addrs, state, color string) {
	if c.Wildcard {
		return "-", "wildcard (not probed)", ""
	}
	if !c.Resolved {
		return "-", "NO DNS (stale?)", colorRed
	}

	parts := make([]string, 0, len(c.Addrs))
	anyUp, allUp := false, true
	for _, a := range c.Addrs {
		ip := sanitize(a.IP)
		if a.Reachable {
			anyUp = true
			parts = append(parts, ip)
		} else {
			allUp = false
			parts = append(parts, ip+" (down)")
		}
	}
	addrs = strings.Join(parts, ", ")

	if !anyUp {
		return addrs, "unreachable", colorRed
	}

	switch c.Ownership {
	case tlsscan.OwnershipOtherCert:
		return addrs, "elsewhere (other cert)", colorMagenta
	case tlsscan.OwnershipUnverified:
		return addrs, "elsewhere (unverified)", colorMagenta
	case tlsscan.OwnershipSameCert:
		return addrs, "open (other IP, same cert)", colorGreen
	}

	if !allUp {
		return addrs, "partial", colorYellow
	}
	return addrs, "open", colorGreen
}

// expiryColor chooses the color for the validity row based on the
// certificate's state.
func expiryColor(r *tlsscan.Report) string {
	switch {
	case r.Leaf.Expired, r.Leaf.NotYetValid:
		return colorRed
	case r.Leaf.DaysRemaining <= r.WarnDays:
		return colorYellow
	default:
		return colorGreen
	}
}

// expiringStatus renders the prominent "expiring soon" headline, mirroring
// the grammar of daysPhrase. Only non-negative day counts reach this branch
// (a negative count is reported as EXPIRED instead).
func expiringStatus(days int) string {
	switch {
	case days <= 0:
		return "EXPIRES TODAY"
	case days == 1:
		return "EXPIRING IN 1 DAY"
	default:
		return fmt.Sprintf("EXPIRING IN %d DAYS", days)
	}
}

// daysPhrase renders the days-remaining count as a readable phrase.
func daysPhrase(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == 0:
		return "expires today"
	case days == 1:
		return "1 day remaining"
	default:
		return fmt.Sprintf("%d days remaining", days)
	}
}

// boolText renders a yes/no value, coloring it green for yes and red for
// no when color is enabled.
func boolText(v bool, color bool) string {
	if v {
		return paint("yes", colorGreen, color)
	}
	return paint("no", colorRed, color)
}
