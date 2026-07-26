package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sysrow/tlsee/tlsscan"
)

// ansiPattern matches ANSI escape sequences (the color codes emitted by paint).
// Tests strip these to reason about the visible width of table columns.
var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripANSI removes ANSI escape sequences from s, leaving only visible text.
func stripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

// hasControlBytes reports whether s contains any C0/C1 control byte or ESC,
// excluding the newline and tab that legitimately structure rendered output.
func hasControlBytes(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

// TestWriteTextChainCNOnly verifies the chain section renders one narrow line
// per certificate using the common name, falling back to the full DN when the
// common name is empty.
func TestWriteTextChainCNOnly(t *testing.T) {
	r := fixedReport()
	r.Chain = []tlsscan.CertInfo{
		// CN present: render the short CN, not the wide DN.
		{
			Subject:   "CN=Intermediate CA,O=Example,L=Somewhere,C=US",
			Issuer:    "CN=Example Root,O=Example,L=Somewhere,C=US",
			SubjectCN: "Intermediate CA",
			IssuerCN:  "Example Root",
		},
		// CN empty: fall back to the full DN.
		{Subject: "OU=Org Unit,O=Example", Issuer: "OU=Root Unit,O=Example"},
	}

	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()

	if !strings.Contains(out, "[1]  Intermediate CA  ->  Example Root") {
		t.Errorf("chain line 1 not rendered CN-only:\n%s", out)
	}
	if !strings.Contains(out, "[2]  OU=Org Unit,O=Example  ->  OU=Root Unit,O=Example") {
		t.Errorf("chain line 2 did not fall back to full DN:\n%s", out)
	}
	// The wide-DN form must not be used when a CN is available.
	if strings.Contains(out, "CN=Intermediate CA,O=Example,L=Somewhere,C=US") {
		t.Errorf("chain still rendered the wide DN despite a CN being present:\n%s", out)
	}
}

// TestWriteTextWarnings verifies the warnings section appears (yellow under
// color) when warnings are present and is omitted when empty.
func TestWriteTextWarnings(t *testing.T) {
	r := fixedReport()
	r.Warnings = []string{"weak TLS version: TLS 1.0", "weak RSA key: 1024 bits"}

	var plain bytes.Buffer
	WriteText(&plain, r, false)
	out := plain.String()
	for _, want := range []string{"Warnings:", "weak TLS version: TLS 1.0", "weak RSA key: 1024 bits"} {
		if !strings.Contains(out, want) {
			t.Errorf("warnings output missing %q\n---\n%s", want, out)
		}
	}

	var colored bytes.Buffer
	WriteText(&colored, r, true)
	if !strings.Contains(colored.String(), colorYellow+"weak TLS version: TLS 1.0"+colorReset) {
		t.Errorf("warning not rendered yellow with color enabled:\n%s", colored.String())
	}

	// No warnings: the section header must not appear.
	clean := fixedReport()
	var noWarn bytes.Buffer
	WriteText(&noWarn, clean, false)
	if strings.Contains(noWarn.String(), "Warnings:") {
		t.Errorf("warnings section rendered with no warnings:\n%s", noWarn.String())
	}
}

// TestWriteTextWarningsNoHeadlineEffect confirms warnings never change the
// status headline: a fully valid certificate with warnings still reads VALID.
func TestWriteTextWarningsNoHeadlineEffect(t *testing.T) {
	r := fixedReport()
	r.Warnings = []string{"weak signature algorithm: SHA1-RSA"}
	var buf bytes.Buffer
	WriteText(&buf, r, false)
	if !strings.Contains(buf.String(), "Status: VALID") {
		t.Errorf("warnings altered the status headline; want VALID:\n%s", buf.String())
	}
}

// TestWriteTextPerIP verifies the per-IP section lists each address with its CN
// or error, and shows the prominent differ note only when fingerprints differ.
func TestWriteTextPerIP(t *testing.T) {
	r := fixedReport()
	r.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "BB", SubjectCN: "example.com", DaysRemaining: 10},
		{IP: "10.0.0.3", Error: "connect 10.0.0.3:443: connection refused"},
	}
	r.IPCertsDiffer = true

	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()
	for _, want := range []string{
		"Per-IP certificates:",
		"10.0.0.1", "90 days remaining",
		"10.0.0.2", "10 days remaining",
		"10.0.0.3", "connection refused",
		"certificates differ across IPs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("per-IP output missing %q\n---\n%s", want, out)
		}
	}

	// When they do not differ, the note is absent but the list remains.
	same := fixedReport()
	same.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
	}
	same.IPCertsDiffer = false
	var buf2 bytes.Buffer
	WriteText(&buf2, same, false)
	if strings.Contains(buf2.String(), "certificates differ across IPs") {
		t.Errorf("differ note shown when certificates match:\n%s", buf2.String())
	}
	if !strings.Contains(buf2.String(), "Per-IP certificates:") {
		t.Errorf("per-IP section missing when fingerprints match:\n%s", buf2.String())
	}
}

// TestWriteTextPerIPDifferShowsDiscriminator verifies that when certificates
// differ across IPs, rows that are otherwise identical (same CN, same expiry)
// still render visibly distinct via a truncated fingerprint, so the differ note
// does not sit above look-alike rows. The matching case adds no fingerprint
// column.
func TestWriteTextPerIPDifferShowsDiscriminator(t *testing.T) {
	differ := fixedReport()
	differ.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "11:22:33:44:55:66:77:88", SubjectCN: "example.com", DaysRemaining: 90},
	}
	differ.IPCertsDiffer = true
	var buf bytes.Buffer
	WriteText(&buf, differ, false)
	out := buf.String()
	for _, want := range []string{"AA:BB:CC:DD", "11:22:33:44"} {
		if !strings.Contains(out, want) {
			t.Errorf("differing per-IP rows missing fingerprint discriminator %q\n---\n%s", want, out)
		}
	}

	// The matching case must not print a fingerprint discriminator.
	same := fixedReport()
	same.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
	}
	same.IPCertsDiffer = false
	var buf2 bytes.Buffer
	WriteText(&buf2, same, false)
	if strings.Contains(buf2.String(), "AA:BB:CC:DD") {
		t.Errorf("matching per-IP rows should not print a fingerprint column:\n%s", buf2.String())
	}
}

// TestShortFingerprint covers the truncation helper: long fingerprints keep the
// first four byte groups with an ellipsis, short or empty inputs degrade safely.
func TestShortFingerprint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AA:BB:CC:DD:EE:FF:00:11:22:33", "AA:BB:CC:DD:EE:FF:00:11:..."},
		{"AA:BB:CC:DD:EE:FF:00:11", "AA:BB:CC:DD:EE:FF:00:11"},
		{"AA:BB:CC:DD", "AA:BB:CC:DD"},
		{"AA:BB", "AA:BB"},
		{"AA", "AA"},
		{"", "?"},
	}
	for _, c := range cases {
		if got := shortFingerprint(c.in); got != c.want {
			t.Errorf("shortFingerprint(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// batchRows builds a deterministic mix of batch outcomes for table tests.
func batchRows() []BatchRow {
	mk := func(days int, trusted, hostnameMatch, expired bool) *tlsscan.Report {
		return &tlsscan.Report{
			ChainTrusted:  trusted,
			HostnameMatch: hostnameMatch,
			WarnDays:      30,
			Leaf: tlsscan.CertInfo{
				DaysRemaining: days,
				Expired:       expired,
			},
		}
	}
	return []BatchRow{
		{Host: "healthy.example.com", Report: mk(90, true, true, false)},
		{Host: "expiring.example.com", Report: mk(10, true, true, false)},
		{Host: "expired.example.com", Report: mk(-3, true, true, true)},
		{Host: "broken.example.com", Err: "connect broken.example.com:443: i/o timeout"},
		{Host: "mismatch.example.com", Report: mk(60, true, false, false)},
	}
}

// TestWriteBatchTableSortAndContent verifies the table is sorted with errors
// first then by ascending days, and that each status word appears.
func TestWriteBatchTableSortAndContent(t *testing.T) {
	var buf bytes.Buffer
	WriteBatchTable(&buf, batchRows(), false, false)
	out := buf.String()

	if !strings.Contains(out, "HOST") || !strings.Contains(out, "STATUS") || !strings.Contains(out, "NOTE") {
		t.Errorf("table header missing columns:\n%s", out)
	}
	for _, want := range []string{"VALID", "EXPIRING", "EXPIRED", "ERROR", "MISMATCH", "i/o timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing status %q\n---\n%s", want, out)
		}
	}

	// Order: error first, then ascending days (-3, 10, 60, 90).
	order := []string{
		"broken.example.com",
		"expired.example.com",
		"expiring.example.com",
		"mismatch.example.com",
		"healthy.example.com",
	}
	lastIdx := -1
	for _, host := range order {
		idx := strings.Index(out, host)
		if idx < 0 {
			t.Fatalf("host %q not in table:\n%s", host, out)
		}
		if idx < lastIdx {
			t.Errorf("host %q out of order in table:\n%s", host, out)
		}
		lastIdx = idx
	}
}

// TestWriteBatchTableQuiet verifies quiet mode prints only problem rows, and
// nothing at all when every row is healthy.
func TestWriteBatchTableQuiet(t *testing.T) {
	var buf bytes.Buffer
	WriteBatchTable(&buf, batchRows(), false, true)
	out := buf.String()
	if strings.Contains(out, "healthy.example.com") {
		t.Errorf("quiet table included a healthy row:\n%s", out)
	}
	for _, want := range []string{"expired.example.com", "broken.example.com", "mismatch.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("quiet table missing problem row %q:\n%s", want, out)
		}
	}

	// All healthy: nothing at all, not even a header.
	allHealthy := []BatchRow{
		{Host: "a.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 90}}},
		{Host: "b.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 80}}},
	}
	var empty bytes.Buffer
	WriteBatchTable(&empty, allHealthy, false, true)
	if empty.Len() != 0 {
		t.Errorf("quiet table for all-healthy hosts wrote output:\n%s", empty.String())
	}
}

// TestWriteBatchJSON verifies the batch array carries full reports for scanned
// hosts and {host,error} objects for failures, and that quiet filters healthy
// entries.
func TestWriteBatchJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteBatchJSON(&buf, batchRows(), false); err != nil {
		t.Fatalf("WriteBatchJSON error: %v", err)
	}

	var items []json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("batch JSON is not an array: %v\n%s", err, buf.String())
	}
	if len(items) != 5 {
		t.Fatalf("batch JSON length = %d; want 5", len(items))
	}

	// The first item (errors sort first) must be a {host,error} object.
	var fail struct {
		Host  string `json:"host"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(items[0], &fail); err != nil || fail.Host != "broken.example.com" || fail.Error == "" {
		t.Errorf("first item not the failure object: %+v err=%v\n%s", fail, err, string(items[0]))
	}

	// Quiet filters healthy hosts out of the array.
	var quietBuf bytes.Buffer
	if err := WriteBatchJSON(&quietBuf, batchRows(), true); err != nil {
		t.Fatalf("WriteBatchJSON quiet error: %v", err)
	}
	if strings.Contains(quietBuf.String(), "healthy.example.com") {
		t.Errorf("quiet batch JSON included a healthy host:\n%s", quietBuf.String())
	}

	// Quiet with every host healthy writes nothing (not an empty array), so a
	// clean cron check produces no output on either the text or JSON path.
	allHealthy := []BatchRow{
		{Host: "a.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 90}}},
	}
	var silent bytes.Buffer
	if err := WriteBatchJSON(&silent, allHealthy, true); err != nil {
		t.Fatalf("WriteBatchJSON all-healthy quiet error: %v", err)
	}
	if silent.Len() != 0 {
		t.Errorf("quiet JSON for all-healthy hosts wrote output:\n%s", silent.String())
	}
}

// sweepFixture returns a deterministic sweep result covering every status word.
func sweepFixture() *tlsscan.SweepResult {
	notAfter := time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC)
	return &tlsscan.SweepResult{
		Host: "example.com",
		Ports: []tlsscan.PortResult{
			{Port: 80, Proto: "tls", Open: false},
			{Port: 443, Proto: "https", Open: true, TLS: true, SubjectCN: "example.com", NotAfter: &notAfter, DaysRemaining: 90},
			{Port: 587, Proto: "smtp", Open: true, TLS: true, SubjectCN: "mail.example.com", DaysRemaining: 10},
			{Port: 993, Proto: "imaps", Open: true, TLS: true, SubjectCN: "old.example.com", DaysRemaining: -2, Expired: true},
			{Port: 22, Proto: "tls", Open: true, TLS: false, Error: "no TLS"},
		},
	}
}

// TestWriteSweepText verifies the sweep table header, per-port rows, and the
// status word for each outcome.
func TestWriteSweepText(t *testing.T) {
	var buf bytes.Buffer
	WriteSweepText(&buf, sweepFixture(), false)
	out := buf.String()

	for _, want := range []string{
		"PORT", "PROTO", "CERT", "STATUS",
		"443", "https", "example.com", "VALID",
		"587", "smtp", "EXPIRING 10d",
		"993", "imaps", "EXPIRED",
		"80", "closed",
		"22", "no TLS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep table missing %q\n---\n%s", want, out)
		}
	}
}

// TestSweepStatus verifies the status mapping in isolation.
func TestSweepStatus(t *testing.T) {
	tests := []struct {
		name string
		in   tlsscan.PortResult
		want string
	}{
		{name: "closed", in: tlsscan.PortResult{Open: false}, want: "closed"},
		{name: "open no tls", in: tlsscan.PortResult{Open: true, TLS: false}, want: "no TLS"},
		{name: "expired", in: tlsscan.PortResult{Open: true, TLS: true, Expired: true, DaysRemaining: -1}, want: "EXPIRED"},
		// A certificate whose NotBefore is in the future has a large positive
		// DaysRemaining, so without an explicit check it would report VALID.
		{name: "not yet valid", in: tlsscan.PortResult{Open: true, TLS: true, NotYetValid: true, DaysRemaining: 300}, want: "NOT YET VALID"},
		{name: "expiring", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: 5}, want: "EXPIRING 5d"},
		{name: "at boundary expiring", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: sweepWarnDays}, want: "EXPIRING 30d"},
		{name: "valid", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: sweepWarnDays + 1}, want: "VALID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := sweepStatus(tc.in)
			if got != tc.want {
				t.Errorf("sweepStatus(%+v) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestWriteSweepJSON verifies the sweep result round-trips through JSON.
func TestWriteSweepJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSweepJSON(&buf, sweepFixture()); err != nil {
		t.Fatalf("WriteSweepJSON error: %v", err)
	}
	var got tlsscan.SweepResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("sweep JSON did not round-trip: %v", err)
	}
	if got.Host != "example.com" || len(got.Ports) != 5 {
		t.Errorf("sweep JSON = %+v; want host example.com with 5 ports", got)
	}
	if !strings.Contains(buf.String(), "\n  \"host\":") {
		t.Errorf("sweep JSON is not 2-space indented:\n%s", buf.String())
	}
}

// TestRowIsHealthyIgnoresDeadSANs confirms quiet's health predicate matches the
// exit-code contract: a dead SAN does not make a row unhealthy.
func TestRowIsHealthyIgnoresDeadSANs(t *testing.T) {
	r := &tlsscan.Report{
		ChainTrusted:  true,
		HostnameMatch: true,
		WarnDays:      30,
		DeadSANs:      2,
		Leaf:          tlsscan.CertInfo{DaysRemaining: 90},
	}
	if !rowIsHealthy(BatchRow{Host: "x", Report: r}) {
		t.Errorf("row with dead SANs but valid cert should be healthy for quiet mode")
	}
}

// TestWriteTextSanitizesControlBytes verifies that control characters embedded
// in attacker-controlled certificate and target fields -- a server can put
// arbitrary bytes in a Subject, Issuer, SAN name, CN, or verify error -- are
// stripped from the rendered text output, so a malicious certificate cannot
// inject ANSI escape sequences (screen clears, cursor moves, color forgery) or
// other terminal control bytes. Rendered with color disabled, the output must
// contain no raw control bytes while still showing the visible text.
func TestWriteTextSanitizesControlBytes(t *testing.T) {
	// ESC[2J clears the screen; CR returns the cursor to overwrite the line;
	// BEL beeps. All three are classic terminal-injection payloads.
	const esc = "\x1b[2J"
	const cr = "\r"
	const bel = "\a"

	r := fixedReport()
	r.Target = "evil" + esc + ".example.com"
	r.Leaf.Subject = "CN=" + esc + "Spoofed"
	r.Leaf.Issuer = "CN=Issuer" + bel
	r.Leaf.DNSNames = []string{"good.example.com", "bad" + cr + ".example.com"}
	r.VerifyError = "x509:" + esc + " forged error"
	r.Chain = []tlsscan.CertInfo{
		{SubjectCN: "Inter" + esc + "mediate", IssuerCN: "Root" + bel},
		{Subject: "OU=" + cr + "Org", Issuer: "OU=Root"},
	}
	r.SANChecks = []tlsscan.SANCheck{
		{Name: "san" + esc + ".example.com", Resolved: true, Reachable: true,
			Addrs: []tlsscan.AddrCheck{{IP: "10.0.0.1" + bel, Reachable: true}}},
	}
	r.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.2", SubjectCN: "ip" + esc + "cert", DaysRemaining: 90},
		{IP: "10.0.0.3", Error: "boom" + cr + "overwrite"},
	}

	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()

	if hasControlBytes(out) {
		t.Errorf("WriteText (color off) emitted raw control bytes from untrusted fields:\n%q", out)
	}

	// The visible text around the stripped control bytes must survive. Only the
	// control byte itself is removed; the printable remainder of an escape
	// sequence (for example the "[2J" after ESC) is left in place, which is
	// harmless once the ESC that would activate it is gone.
	for _, want := range []string{
		"evil[2J.example.com", // ESC stripped, printable "[2J" remains
		"CN=[2JSpoofed",       // ESC removed, surrounding text kept
		"CN=Issuer",           // BEL removed
		"bad.example.com",     // CR removed from SAN name
		"x509:[2J forged error",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sanitized output missing expected visible text %q\n---\n%s", want, out)
		}
	}
}

// TestSanitizeNeutralizesTabs verifies a tab inside an attacker-influenced
// value cannot open a new tabwriter column. The layout tabs are supplied by
// the render format strings, never by cell content, so a tab arriving inside
// a certificate subject, SAN name, or error message is replaced with a space
// to keep it from shifting or forging table columns.
func TestSanitizeNeutralizesTabs(t *testing.T) {
	if got, want := sanitize("CN=a\tVALID"), "CN=a VALID"; got != want {
		t.Errorf("sanitize(%q) = %q; want %q", "CN=a\tVALID", got, want)
	}
	if got, want := sanitize("a\t\tb"), "a  b"; got != want {
		t.Errorf("sanitize(%q) = %q; want %q", "a\t\tb", got, want)
	}
}

// TestBatchAndSweepTablesSanitizeControlBytes confirms the table paths
// (WriteBatchTable, WriteSweepText) also strip control bytes from the
// attacker-influenced host, error, and CN cells, so a malicious target cannot
// forge the terminal through the batch or sweep summary.
func TestBatchAndSweepTablesSanitizeControlBytes(t *testing.T) {
	const esc = "\x1b[2J"
	const bel = "\a"

	rows := []BatchRow{
		{Host: "host" + esc + ".example.com",
			Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 90}}},
		{Host: "broken" + esc + ".example.com", Err: "dial" + bel + " failed"},
	}
	var batch bytes.Buffer
	WriteBatchTable(&batch, rows, false, false)
	if hasControlBytes(batch.String()) {
		t.Errorf("WriteBatchTable emitted raw control bytes from untrusted cells:\n%q", batch.String())
	}

	sr := &tlsscan.SweepResult{
		Host: "sweep" + esc + ".example.com",
		Ports: []tlsscan.PortResult{
			{Port: 443, Proto: "https", Open: true, TLS: true, SubjectCN: "cn" + bel + ".example.com", DaysRemaining: 90},
		},
	}
	var sweep bytes.Buffer
	WriteSweepText(&sweep, sr, false)
	if hasControlBytes(sweep.String()) {
		t.Errorf("WriteSweepText emitted raw control bytes from untrusted cells:\n%q", sweep.String())
	}
}

// TestWriteBatchTableNoteAlignment verifies the NOTE column stays aligned with
// its header even when STATUS cells are colored. tabwriter measures byte width,
// so coloring inside the laid-out cell would otherwise count the invisible ANSI
// escape bytes and push the colored rows' NOTE cell out of line with the header.
// The layout must be computed on the uncolored cells; stripping ANSI from the
// colored output must yield exactly the same column offsets as the monochrome
// output.
func TestWriteBatchTableNoteAlignment(t *testing.T) {
	var mono bytes.Buffer
	WriteBatchTable(&mono, batchRows(), false, false)

	var colored bytes.Buffer
	WriteBatchTable(&colored, batchRows(), true, false)

	// Stripping color from the colored render must reproduce the monochrome
	// render byte-for-byte: if alignment depended on the color codes, the
	// padding would differ and these would not match.
	if got, want := stripANSI(colored.String()), mono.String(); got != want {
		t.Errorf("colored table (ANSI-stripped) does not match monochrome layout:\nstripped:\n%q\nmono:\n%q", got, want)
	}

	// Directly assert the NOTE column starts at the same offset on the header and
	// on every data row, in both renders.
	for _, tc := range []struct {
		name string
		out  string
	}{
		{"monochrome", mono.String()},
		{"colored-stripped", stripANSI(colored.String())},
	} {
		lines := strings.Split(strings.TrimRight(tc.out, "\n"), "\n")
		if len(lines) < 2 {
			t.Fatalf("%s: table too short:\n%s", tc.name, tc.out)
		}
		noteOffset := strings.Index(lines[0], "NOTE")
		if noteOffset < 0 {
			t.Fatalf("%s: NOTE header not found:\n%s", tc.name, tc.out)
		}
		for _, line := range lines[1:] {
			// The NOTE cell content begins exactly at noteOffset; everything to its
			// left (HOST, DAYS, STATUS columns plus padding) is spaces from there
			// back to the previous column. Assert the column boundary is not blank
			// in the header position and that lines are at least that wide.
			if len(line) < noteOffset {
				t.Errorf("%s: data row shorter than NOTE column offset %d:\n%q", tc.name, noteOffset, line)
				continue
			}
			// The character just before the NOTE column must be a space (column
			// separator); the NOTE cell itself must be non-space (real content),
			// proving the columns line up rather than drifting.
			if noteOffset > 0 && line[noteOffset-1] != ' ' {
				t.Errorf("%s: NOTE column not aligned at offset %d (no separator):\n%q", tc.name, noteOffset, line)
			}
			if line[noteOffset] == ' ' {
				t.Errorf("%s: NOTE column at offset %d is blank (misaligned):\n%q", tc.name, noteOffset, line)
			}
		}
	}
}

func TestSANLivenessOwnershipStates(t *testing.T) {
	tests := []struct {
		name      string
		check     tlsscan.SANCheck
		wantState string
		wantColor string
	}{
		{
			name:      "moved name is magenta",
			check:     tlsscan.SANCheck{Name: "moved.test", Resolved: true, Reachable: true, Ownership: tlsscan.OwnershipOtherCert, Addrs: []tlsscan.AddrCheck{{IP: "198.51.100.5", Reachable: true}}},
			wantState: "elsewhere (other cert)",
			wantColor: colorMagenta,
		},
		{
			name:      "unconfirmed name is magenta",
			check:     tlsscan.SANCheck{Name: "maybe.test", Resolved: true, Reachable: true, Ownership: tlsscan.OwnershipUnverified, Addrs: []tlsscan.AddrCheck{{IP: "198.51.100.6", Reachable: true}}},
			wantState: "elsewhere (unverified)",
			wantColor: colorMagenta,
		},
		{
			name:      "another address serving our certificate stays green",
			check:     tlsscan.SANCheck{Name: "cdn.test", Resolved: true, Reachable: true, Ownership: tlsscan.OwnershipSameCert, Addrs: []tlsscan.AddrCheck{{IP: "198.51.100.7", Reachable: true}}},
			wantState: "open (other IP, same cert)",
			wantColor: colorGreen,
		},
		{
			name:      "same host is unchanged",
			check:     tlsscan.SANCheck{Name: "ok.test", Resolved: true, Reachable: true, Ownership: tlsscan.OwnershipSameHost, Addrs: []tlsscan.AddrCheck{{IP: "192.0.2.10", Reachable: true}}},
			wantState: "open",
			wantColor: colorGreen,
		},
		{
			name:      "unclassified partial name is unchanged",
			check:     tlsscan.SANCheck{Name: "half.test", Resolved: true, Reachable: true, Addrs: []tlsscan.AddrCheck{{IP: "192.0.2.10", Reachable: true}, {IP: "192.0.2.11"}}},
			wantState: "partial",
			wantColor: colorYellow,
		},
		{
			name:      "unreachable name stays red and is never classified",
			check:     tlsscan.SANCheck{Name: "down.test", Resolved: true, Addrs: []tlsscan.AddrCheck{{IP: "192.0.2.12"}}},
			wantState: "unreachable",
			wantColor: colorRed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, state, color := sanLiveness(tt.check)
			if state != tt.wantState {
				t.Errorf("state = %q; want %q", state, tt.wantState)
			}
			if color != tt.wantColor {
				t.Errorf("color = %q; want %q", color, tt.wantColor)
			}
		})
	}
}

func TestSANLivenessMagentaSuppressedWithoutColor(t *testing.T) {
	r := fixedReport()
	r.SANChecks = []tlsscan.SANCheck{
		{Name: "moved.test", Resolved: true, Reachable: true, Ownership: tlsscan.OwnershipOtherCert, Addrs: []tlsscan.AddrCheck{{IP: "198.51.100.5", Reachable: true}}},
	}
	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()
	if !strings.Contains(out, "elsewhere (other cert)") {
		t.Error("moved SAN state missing from monochrome output")
	}
	if hasControlBytes(out) {
		t.Error("monochrome output contains ANSI escapes")
	}
}
