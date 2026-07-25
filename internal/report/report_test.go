package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sysrow/tlsee/tlsscan"
)

// fixedReport returns a deterministic report fixture. All time values are
// fixed and all derived fields (DaysRemaining, Expired, NotYetValid) are
// set explicitly so rendering never depends on the wall clock.
func fixedReport() *tlsscan.Report {
	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &tlsscan.Report{
		Target:      "example.com",
		Host:        "example.com",
		Port:        "443",
		ResolvedIPs: []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		TLSVersion:  "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Leaf: tlsscan.CertInfo{
			Subject:            "CN=example.com",
			Issuer:             "CN=Example CA,O=Example",
			SerialNumber:       "12345",
			NotBefore:          notBefore,
			NotAfter:           notAfter,
			DaysRemaining:      90,
			Expired:            false,
			NotYetValid:        false,
			DNSNames:           []string{"example.com", "www.example.com"},
			IPAddresses:        nil,
			IsCA:               false,
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			FingerprintSHA256:  "AA:BB:CC",
		},
		Chain: []tlsscan.CertInfo{
			{Subject: "CN=Example CA,O=Example", Issuer: "CN=Example Root"},
		},
		ChainTrusted:  true,
		HostnameMatch: true,
		ElapsedMs:     42,
		WarnDays:      30,
	}
}

func TestWriteTextValid(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, fixedReport(), false)
	out := buf.String()

	wantContains := []string{
		"example.com",
		"Status: VALID",
		"example.com, www.example.com", // SAN DNS line
		"CN=Example CA,O=Example",      // issuer/subject
		"90 days remaining",
		"TLS 1.3",
		"TLS_AES_128_GCM_SHA256",
		"AA:BB:CC",
		"93.184.216.34",
		"yes", // trusted / hostname match
		"Chain:",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("WriteText output missing %q\n---\n%s", w, out)
		}
	}

	// color=false must not emit ANSI escapes.
	if strings.Contains(out, "\033[") {
		t.Errorf("WriteText emitted ANSI escapes with color disabled:\n%s", out)
	}
}

func TestWriteTextColorEscapes(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, fixedReport(), true)
	if !strings.Contains(buf.String(), "\033[") {
		t.Errorf("WriteText with color=true emitted no ANSI escapes")
	}
}

func TestWriteTextProblemStatuses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *tlsscan.Report)
		want   string
	}{
		{
			name:   "expired",
			mutate: func(r *tlsscan.Report) { r.Leaf.Expired = true; r.Leaf.DaysRemaining = -5 },
			want:   "EXPIRED",
		},
		{
			name:   "not yet valid",
			mutate: func(r *tlsscan.Report) { r.Leaf.NotYetValid = true },
			want:   "NOT YET VALID",
		},
		{
			name:   "untrusted",
			mutate: func(r *tlsscan.Report) { r.ChainTrusted = false; r.VerifyError = "x509: unknown authority" },
			want:   "UNTRUSTED CHAIN",
		},
		{
			name:   "hostname mismatch",
			mutate: func(r *tlsscan.Report) { r.HostnameMatch = false },
			want:   "HOSTNAME MISMATCH",
		},
		{
			name:   "expiring soon",
			mutate: func(r *tlsscan.Report) { r.Leaf.DaysRemaining = 12 },
			want:   "EXPIRING IN 12 DAYS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := fixedReport()
			tc.mutate(r)
			var buf bytes.Buffer
			WriteText(&buf, r, false)
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("status missing %q\n---\n%s", tc.want, buf.String())
			}
		})
	}
}

func TestDaysPhrase(t *testing.T) {
	tests := []struct {
		days int
		want string
	}{
		{days: -5, want: "expired 5 days ago"},
		{days: 0, want: "expires today"},
		{days: 1, want: "1 day remaining"},
		{days: 90, want: "90 days remaining"},
	}
	for _, tc := range tests {
		if got := daysPhrase(tc.days); got != tc.want {
			t.Errorf("daysPhrase(%d) = %q; want %q", tc.days, got, tc.want)
		}
	}
}

func TestExpiringStatus(t *testing.T) {
	tests := []struct {
		days int
		want string
	}{
		{days: 0, want: "EXPIRES TODAY"},
		{days: 1, want: "EXPIRING IN 1 DAY"},
		{days: 2, want: "EXPIRING IN 2 DAYS"},
		{days: 12, want: "EXPIRING IN 12 DAYS"},
	}
	for _, tc := range tests {
		if got := expiringStatus(tc.days); got != tc.want {
			t.Errorf("expiringStatus(%d) = %q; want %q", tc.days, got, tc.want)
		}
	}
}

// TestSummarizeHostnameMismatchColor verifies that a hostname mismatch -- a
// hard failure yielding exit code 2 -- colors the status red, not the yellow
// reserved for the "expiring soon" warning.
func TestSummarizeHostnameMismatchColor(t *testing.T) {
	r := fixedReport()
	r.HostnameMatch = false
	if st := summarize(r); st.color != colorRed {
		t.Errorf("hostname-mismatch status color = %q; want red %q", st.color, colorRed)
	}

	// Combined with expiring-soon, the hard failure must still win (red).
	r = fixedReport()
	r.HostnameMatch = false
	r.Leaf.DaysRemaining = 5
	if st := summarize(r); st.color != colorRed {
		t.Errorf("hostname-mismatch + expiring status color = %q; want red %q", st.color, colorRed)
	}
}

// reportWithSANChecks returns the valid fixture augmented with a mix of SAN
// liveness outcomes: open, partial (IPv6 down), dead (no DNS), and wildcard.
func reportWithSANChecks() *tlsscan.Report {
	r := fixedReport()
	r.SANChecks = []tlsscan.SANCheck{
		{Name: "ok.example.com", Resolved: true, Reachable: true, Addrs: []tlsscan.AddrCheck{{IP: "10.0.0.1", Reachable: true}}},
		{Name: "partial.example.com", Resolved: true, Reachable: true, Addrs: []tlsscan.AddrCheck{
			{IP: "10.0.0.2", Reachable: true},
			{IP: "fe80::1", Reachable: false, Error: "timeout"},
		}},
		{Name: "dead.example.com", Resolved: false},
		{Name: "*.example.com", Wildcard: true},
	}
	r.DeadSANs = 1 // only dead.example.com
	return r
}

func TestWriteTextSANLiveness(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, reportWithSANChecks(), false)
	out := buf.String()

	wantContains := []string{
		"SAN liveness:",
		"ok.example.com", "open",
		"partial.example.com", "partial", "fe80::1 (down)",
		"dead.example.com", "NO DNS (stale?)",
		"wildcard (not probed)",
		"1 DEAD SAN", // status headline
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("WriteText output missing %q\n---\n%s", w, out)
		}
	}
}

// TestWriteTextSANLivenessColor confirms the SAN-liveness section is colored
// when color is enabled (a dead name renders red).
func TestWriteTextSANLivenessColor(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, reportWithSANChecks(), true)
	if !strings.Contains(buf.String(), colorRed+"NO DNS (stale?)"+colorReset) {
		t.Errorf("dead SAN not rendered in red with color enabled\n---\n%s", buf.String())
	}
}

// TestSummarizeDeadSANs verifies a dead SAN on an otherwise-valid certificate
// is a non-red advisory: the headline still reads VALID (so the healthy
// indicator survives and the exit-code/quiet contract is respected) and is not
// colored red, while the dead SAN is still reported. A wildcard-only report
// stays plain VALID.
func TestSummarizeDeadSANs(t *testing.T) {
	r := reportWithSANChecks()
	st := summarize(r)
	if st.color == colorRed {
		t.Errorf("dead-SAN-only status color = %q; want non-red (cert is valid)", st.color)
	}
	if !strings.Contains(st.text, "VALID") {
		t.Errorf("status = %q; want it to retain the VALID indicator", st.text)
	}
	if !strings.Contains(st.text, "1 DEAD SAN") {
		t.Errorf("status = %q; want it to mention the dead SAN", st.text)
	}

	// Wildcard-only (no dead SANs) must not affect a valid status.
	clean := fixedReport()
	clean.SANChecks = []tlsscan.SANCheck{{Name: "*.example.com", Wildcard: true}}
	clean.DeadSANs = 0
	if st := summarize(clean); st.text != "VALID" {
		t.Errorf("wildcard-only status = %q; want VALID", st.text)
	}
}

func TestWriteJSONSANChecks(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, reportWithSANChecks()); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var got tlsscan.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON did not round-trip: %v", err)
	}
	if len(got.SANChecks) != 4 {
		t.Fatalf("SANChecks length = %d; want 4", len(got.SANChecks))
	}
	if got.DeadSANs != 1 {
		t.Errorf("DeadSANs = %d; want 1", got.DeadSANs)
	}
	if !got.SANChecks[3].Wildcard {
		t.Errorf("fourth SAN check should be wildcard: %+v", got.SANChecks[3])
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, fixedReport()); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	// Indented with two spaces.
	if !strings.Contains(buf.String(), "\n  \"target\":") {
		t.Errorf("JSON is not 2-space indented:\n%s", buf.String())
	}

	// Round-trips and preserves key fields, including RFC3339 time.
	var got tlsscan.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON did not round-trip: %v", err)
	}
	if got.Target != "example.com" {
		t.Errorf("Target = %q; want example.com", got.Target)
	}
	if got.Leaf.DaysRemaining != 90 {
		t.Errorf("Leaf.DaysRemaining = %d; want 90", got.Leaf.DaysRemaining)
	}
	if !got.Leaf.NotAfter.Equal(time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Leaf.NotAfter = %v; want 2025-01-01", got.Leaf.NotAfter)
	}
	if !strings.Contains(buf.String(), "2025-01-01T00:00:00Z") {
		t.Errorf("JSON missing RFC3339 NotAfter:\n%s", buf.String())
	}

	// JSON output is never colored.
	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("JSON output contains ANSI escapes:\n%s", buf.String())
	}
}
