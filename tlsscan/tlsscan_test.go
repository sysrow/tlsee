package tlsscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeAddr exercises the deterministic core of the SAN liveness check
// using IP literals only (no DNS): a bound listener is reachable, and a port
// that was bound then closed is refused.
func TestProbeAddr(t *testing.T) {
	ctx := context.Background()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, openPort, _ := net.SplitHostPort(ln.Addr().String())

	if ok, err := probeAddr(ctx, "127.0.0.1", openPort, time.Second); !ok || err != nil {
		t.Errorf("probeAddr(open) = (%v, %v); want (true, nil)", ok, err)
	}

	// Bind a second port, then close it so it is guaranteed not listening.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, closedPort, _ := net.SplitHostPort(ln2.Addr().String())
	ln2.Close()

	if ok, err := probeAddr(ctx, "127.0.0.1", closedPort, time.Second); ok || err == nil {
		t.Errorf("probeAddr(closed) = (%v, %v); want (false, non-nil)", ok, err)
	}
}

// TestCheckSANWildcard verifies a wildcard name is flagged and not probed,
// so it can be excluded from the dead-SAN count.
func TestCheckSANWildcard(t *testing.T) {
	sc := checkSAN(context.Background(), "*.example.com", "443", time.Second)
	if !sc.Wildcard {
		t.Errorf("Wildcard = false; want true for %q", sc.Name)
	}
	if sc.Resolved || sc.Reachable || len(sc.Addrs) != 0 {
		t.Errorf("wildcard probed: %+v; want no resolution or addresses", sc)
	}
}

// TestProbeTimeout checks the per-probe timeout is capped below the handshake
// timeout but honors a smaller scan timeout.
func TestProbeTimeout(t *testing.T) {
	if got := probeTimeout(10 * time.Second); got != maxProbeTimeout {
		t.Errorf("probeTimeout(10s) = %v; want %v", got, maxProbeTimeout)
	}
	if got := probeTimeout(time.Second); got != time.Second {
		t.Errorf("probeTimeout(1s) = %v; want 1s", got)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		defaultPort string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{name: "bare host", target: "example.com", wantHost: "example.com", wantPort: "443"},
		{name: "host and port", target: "example.com:8443", wantHost: "example.com", wantPort: "8443"},
		{name: "https scheme stripped", target: "https://example.com", wantHost: "example.com", wantPort: "443"},
		{name: "tls scheme with port", target: "tls://example.com:9000", wantHost: "example.com", wantPort: "9000"},
		{name: "scheme host port and path", target: "https://example.com:8443/path?q=1", wantHost: "example.com", wantPort: "8443"},
		{name: "host with path no port", target: "example.com/some/path", wantHost: "example.com", wantPort: "443"},
		{name: "default port override applied", target: "example.com", defaultPort: "8443", wantHost: "example.com", wantPort: "8443"},
		{name: "explicit port beats override", target: "example.com:1234", defaultPort: "8443", wantHost: "example.com", wantPort: "1234"},
		{name: "ipv4 with port", target: "127.0.0.1:8443", wantHost: "127.0.0.1", wantPort: "8443"},
		{name: "ipv4 no port", target: "127.0.0.1", wantHost: "127.0.0.1", wantPort: "443"},
		{name: "ipv6 with port", target: "[::1]:8443", wantHost: "::1", wantPort: "8443"},
		{name: "ipv6 no port", target: "[::1]", wantHost: "::1", wantPort: "443"},
		{name: "ipv6 scheme port and path", target: "https://[::1]:8443/health", wantHost: "::1", wantPort: "8443"},
		{name: "bare ipv6 no brackets", target: "::1", wantHost: "::1", wantPort: "443"},
		{name: "bare ipv6 global no brackets", target: "2001:db8::1", wantHost: "2001:db8::1", wantPort: "443"},
		{name: "empty target", target: "", wantErr: true},
		{name: "scheme only", target: "https://", wantErr: true},
		{name: "port out of range", target: "example.com:99999", wantErr: true},
		{name: "port zero", target: "example.com:0", wantErr: true},
		{name: "non numeric port", target: "example.com:https", wantErr: true},
		{name: "invalid default port", target: "example.com", defaultPort: "70000", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseTarget(tc.target, tc.defaultPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTarget(%q, %q) = (%q, %q, nil); want error", tc.target, tc.defaultPort, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTarget(%q, %q) unexpected error: %v", tc.target, tc.defaultPort, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("parseTarget(%q, %q) = (%q, %q); want (%q, %q)",
					tc.target, tc.defaultPort, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	got := formatFingerprint([]byte{0x00, 0x0f, 0xab, 0xff})
	want := "00:0F:AB:FF"
	if got != want {
		t.Errorf("formatFingerprint = %q; want %q", got, want)
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := tlsVersionName(0x0304); got != "TLS 1.3" {
		t.Errorf("tlsVersionName(0x0304) = %q; want %q", got, "TLS 1.3")
	}
	if got := tlsVersionName(0x9999); !strings.HasPrefix(got, "unknown") {
		t.Errorf("tlsVersionName(unknown) = %q; want unknown prefix", got)
	}
}

// TestScanIntegration exercises the full internal/localhost code path
// against a local TLS server. httptest.NewTLSServer presents a self-signed
// certificate with a DNS SAN and IP SANs for loopback, so the leaf must
// parse, carry SAN DNS names, expose a far-future NotAfter, and negotiate a
// TLS version. The chain is not expected to be trusted (self-signed).
func TestScanIntegration(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// srv.URL is an https://127.0.0.1:PORT URL; Scan strips the scheme.
	rep, err := Scan(ctx, srv.URL, Options{Timeout: 5 * time.Second, ResolveDNS: false})
	if err != nil {
		t.Fatalf("Scan(%q) error: %v", srv.URL, err)
	}

	if rep.Host != "127.0.0.1" {
		t.Errorf("Host = %q; want 127.0.0.1", rep.Host)
	}
	if len(rep.Leaf.DNSNames) == 0 {
		t.Errorf("Leaf.DNSNames is empty; expected at least one SAN DNS name")
	}
	if rep.Leaf.NotAfter.IsZero() {
		t.Errorf("Leaf.NotAfter is zero; expected a parsed validity end")
	}
	// httptest.NewTLSServer negotiates a modern TLS version, so assert a
	// recognized name rather than merely non-empty (tlsVersionName always
	// returns a non-empty string, even for unknown versions).
	if rep.TLSVersion != "TLS 1.3" && rep.TLSVersion != "TLS 1.2" {
		t.Errorf("TLSVersion = %q; want TLS 1.3 or TLS 1.2", rep.TLSVersion)
	}
	// A resolved cipher suite name has no 0x prefix; an unknown suite would
	// render as a raw hex value, which would mean the lookup failed.
	if rep.CipherSuite == "" || strings.HasPrefix(rep.CipherSuite, "0x") {
		t.Errorf("CipherSuite = %q; want a named suite (no 0x prefix)", rep.CipherSuite)
	}
	// The test server's certificate is self-signed and far from expiry.
	if rep.Leaf.Expired {
		t.Errorf("Leaf.Expired = true; httptest cert should not be expired")
	}
	// VerifyHostname accepts the loopback IP SAN, so hostname matches.
	if !rep.HostnameMatch {
		t.Errorf("HostnameMatch = false; loopback IP SAN should match 127.0.0.1")
	}
	// Self-signed: not chained to a system root.
	if rep.ChainTrusted {
		t.Errorf("ChainTrusted = true; self-signed cert should not be trusted")
	}
}

func TestScanConnectionRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Port 1 on loopback is reserved and refuses TCP connections.
	rep, err := Scan(ctx, "127.0.0.1:1", Options{Timeout: time.Second, ResolveDNS: false})
	if err == nil {
		t.Fatalf("Scan to refused port returned nil error and report %+v", rep)
	}
	if !strings.Contains(err.Error(), "connect 127.0.0.1:1") {
		t.Errorf("error %q does not wrap the dial address", err.Error())
	}
}
