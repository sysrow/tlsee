package tlsscan

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHygieneWarnings exercises the pure hygiene evaluator across each finding
// in isolation and a clean baseline. It uses real cipher-suite identifiers from
// the stdlib so the InsecureCipherSuites check is meaningful.
func TestHygieneWarnings(t *testing.T) {
	// A known-insecure suite identifier and a known-secure one.
	var insecureID uint16
	if suites := tls.InsecureCipherSuites(); len(suites) > 0 {
		insecureID = suites[0].ID
	} else {
		t.Fatal("expected at least one insecure cipher suite from the stdlib")
	}
	const secureID = tls.TLS_AES_128_GCM_SHA256

	tests := []struct {
		name       string
		version    uint16
		sigAlg     string
		pubKeyAlgo string
		keyBits    int
		cipher     uint16
		wantSubstr string // empty means expect no warnings
	}{
		{
			name:       "clean modern connection",
			version:    tls.VersionTLS13,
			sigAlg:     "SHA256-RSA",
			pubKeyAlgo: "RSA",
			keyBits:    4096,
			cipher:     secureID,
		},
		{
			name:       "weak TLS version",
			version:    tls.VersionTLS10,
			sigAlg:     "SHA256-RSA",
			pubKeyAlgo: "RSA",
			keyBits:    2048,
			cipher:     secureID,
			wantSubstr: "weak TLS version",
		},
		{
			name:       "sha1 signature",
			version:    tls.VersionTLS12,
			sigAlg:     "SHA1-RSA",
			pubKeyAlgo: "RSA",
			keyBits:    2048,
			cipher:     secureID,
			wantSubstr: "weak signature algorithm",
		},
		{
			name:       "md5 signature lowercase input",
			version:    tls.VersionTLS12,
			sigAlg:     "md5WithRSAEncryption",
			pubKeyAlgo: "RSA",
			keyBits:    2048,
			cipher:     secureID,
			wantSubstr: "weak signature algorithm",
		},
		{
			name:       "weak rsa key",
			version:    tls.VersionTLS12,
			sigAlg:     "SHA256-RSA",
			pubKeyAlgo: "RSA",
			keyBits:    1024,
			cipher:     secureID,
			wantSubstr: "weak RSA key",
		},
		{
			name:       "small ecdsa key is not a weak rsa key",
			version:    tls.VersionTLS13,
			sigAlg:     "ECDSA-SHA256",
			pubKeyAlgo: "ECDSA",
			keyBits:    256,
			cipher:     secureID,
		},
		{
			name:       "weak cipher suite",
			version:    tls.VersionTLS12,
			sigAlg:     "SHA256-RSA",
			pubKeyAlgo: "RSA",
			keyBits:    2048,
			cipher:     insecureID,
			wantSubstr: "weak cipher suite",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hygieneWarnings(tc.version, tc.sigAlg, tc.pubKeyAlgo, tc.keyBits, tc.cipher, "TEST_SUITE")
			if tc.wantSubstr == "" {
				if len(got) != 0 {
					t.Fatalf("hygieneWarnings = %v; want none", got)
				}
				return
			}
			found := false
			for _, w := range got {
				if strings.Contains(w, tc.wantSubstr) {
					found = true
				}
			}
			if !found {
				t.Errorf("hygieneWarnings = %v; want a warning containing %q", got, tc.wantSubstr)
			}
		})
	}
}

// TestKeyBits checks the public-key size mapping for each supported algorithm.
// ECDSA and Ed25519 keys are fast to generate; RSA generation is slower, so a
// single small modulus is used to confirm the RSA branch.
func TestKeyBits(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	if got := keyBits(&ecKey.PublicKey); got != 256 {
		t.Errorf("keyBits(P256) = %d; want 256", got)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	if got := keyBits(edPub); got != 256 {
		t.Errorf("keyBits(ed25519) = %d; want 256", got)
	}

	// RSA generation is slower; a 1024-bit modulus is sufficient to verify the
	// modulus bit-length path.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	if got := keyBits(&rsaKey.PublicKey); got != 1024 {
		t.Errorf("keyBits(RSA-1024) = %d; want 1024", got)
	}

	if got := keyBits("not a key"); got != 0 {
		t.Errorf("keyBits(unknown) = %d; want 0", got)
	}
}

// TestParsePortSpec covers single ports, ranges, mixed specs, deduplication,
// sorting, and the rejected forms.
func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "single", spec: "443", want: []int{443}},
		{name: "list", spec: "443,8443,9443", want: []int{443, 8443, 9443}},
		{name: "range", spec: "1000-1003", want: []int{1000, 1001, 1002, 1003}},
		{name: "mixed", spec: "443,9000-9002", want: []int{443, 9000, 9001, 9002}},
		{name: "dedup and sort", spec: "9000,443,443,9000", want: []int{443, 9000}},
		{name: "whitespace tolerated", spec: " 443 , 8443 ", want: []int{443, 8443}},
		{name: "empty", spec: "", wantErr: true},
		{name: "only commas", spec: ",,", wantErr: true},
		{name: "non numeric", spec: "https", wantErr: true},
		{name: "zero out of range", spec: "0", wantErr: true},
		{name: "too large", spec: "70000", wantErr: true},
		{name: "descending range", spec: "9100-9000", wantErr: true},
		{name: "bad range bound", spec: "443-abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePortSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePortSpec(%q) = %v, nil; want error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortSpec(%q) unexpected error: %v", tc.spec, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePortSpec(%q) = %v; want %v", tc.spec, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePortSpec(%q) = %v; want %v", tc.spec, got, tc.want)
				}
			}
		})
	}
}

// TestDisplayProto verifies the PROTO column logic distinguishes curated ports,
// unknown STARTTLS ports, and unknown direct-TLS ports.
func TestDisplayProto(t *testing.T) {
	tests := []struct {
		port  int
		proto string
		want  string
	}{
		{port: 443, proto: "", want: "https"},
		{port: 5432, proto: "postgres", want: "postgresql"},
		{port: 587, proto: "smtp", want: "smtp"},
		{port: 9999, proto: "", want: "tls"},
		{port: 9999, proto: "imap", want: "imap"},
	}
	for _, tc := range tests {
		if got := displayProto(tc.port, tc.proto); got != tc.want {
			t.Errorf("displayProto(%d, %q) = %q; want %q", tc.port, tc.proto, got, tc.want)
		}
	}
}

// TestIPCertsDiffer checks the fingerprint-comparison logic: matching reachable
// certs do not differ, mismatched ones do, and errored entries are ignored.
func TestIPCertsDiffer(t *testing.T) {
	tests := []struct {
		name  string
		certs []IPCert
		want  bool
	}{
		{
			name:  "single reachable",
			certs: []IPCert{{IP: "a", FingerprintSHA256: "AA"}},
			want:  false,
		},
		{
			name:  "two identical",
			certs: []IPCert{{IP: "a", FingerprintSHA256: "AA"}, {IP: "b", FingerprintSHA256: "AA"}},
			want:  false,
		},
		{
			name:  "two different",
			certs: []IPCert{{IP: "a", FingerprintSHA256: "AA"}, {IP: "b", FingerprintSHA256: "BB"}},
			want:  true,
		},
		{
			name:  "errored entry ignored",
			certs: []IPCert{{IP: "a", FingerprintSHA256: "AA"}, {IP: "b", Error: "refused"}},
			want:  false,
		},
		{
			name:  "all errored",
			certs: []IPCert{{IP: "a", Error: "x"}, {IP: "b", Error: "y"}},
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ipCertsDiffer(tc.certs); got != tc.want {
				t.Errorf("ipCertsDiffer = %v; want %v", got, tc.want)
			}
		})
	}
}

// scriptStep is one server-side action in a scripted plaintext dialog: optional
// data to send to the client, then the line(s) the server expects to read back.
type scriptStep struct {
	send   string // bytes the server writes first (may be empty)
	expect string // exact line the server then expects to read (without CRLF; empty skips the read)
}

// runScriptedServer starts a one-connection TCP server that plays the given
// steps against the first client, then returns. The returned address is where
// the client should connect. Test failures from the server side are reported
// via t. The server closes the connection after the script completes.
func runScriptedServer(t *testing.T, steps []scriptStep) (addr string, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(conn)
		for _, step := range steps {
			if step.send != "" {
				if _, err := conn.Write([]byte(step.send)); err != nil {
					return
				}
			}
			if step.expect != "" {
				line, err := br.ReadString('\n')
				if err != nil {
					t.Errorf("scripted server read: %v", err)
					return
				}
				got := strings.TrimRight(line, "\r\n")
				if got != step.expect {
					t.Errorf("scripted server got %q; want %q", got, step.expect)
					return
				}
			}
		}
	}()

	return ln.Addr().String(), finished
}

// dialScript connects to addr and returns the raw conn for the negotiator.
func dialScript(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial scripted server: %v", err)
	}
	return conn
}

// TestStartTLSNegotiateSMTP drives a scripted SMTP STARTTLS dialog, including a
// multiline 250 EHLO reply, and asserts the negotiation succeeds.
func TestStartTLSNegotiateSMTP(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "220 mail.example.com ESMTP ready\r\n", expect: "EHLO tlsee"},
		{send: "250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n", expect: "STARTTLS"},
		{send: "220 ready to start TLS\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()

	if err := startTLSNegotiate(context.Background(), conn, "smtp", 2*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(smtp) error: %v", err)
	}
	<-done
}

// TestStartTLSNegotiateSMTPRefused asserts a non-220 STARTTLS reply yields an
// error rather than proceeding to a doomed handshake.
func TestStartTLSNegotiateSMTPRefused(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "220 mail.example.com ESMTP ready\r\n", expect: "EHLO tlsee"},
		{send: "250 mail.example.com\r\n", expect: "STARTTLS"},
		{send: "454 TLS not available\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()

	if err := startTLSNegotiate(context.Background(), conn, "smtp", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(smtp) = nil; want error for refused STARTTLS")
	}
	<-done
}

// TestStartTLSNegotiateIMAP drives a scripted IMAP STARTTLS dialog with an
// untagged response before the tagged OK.
func TestStartTLSNegotiateIMAP(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n", expect: "a1 STARTTLS"},
		{send: "a1 OK Begin TLS negotiation now\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()

	if err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(imap) error: %v", err)
	}
	<-done
}

// TestStartTLSNegotiatePOP3 drives a scripted POP3 STLS dialog.
func TestStartTLSNegotiatePOP3(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "+OK POP3 ready\r\n", expect: "STLS"},
		{send: "+OK Begin TLS negotiation\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()

	if err := startTLSNegotiate(context.Background(), conn, "pop3", 2*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(pop3) error: %v", err)
	}
	<-done
}

// TestStartTLSNegotiateFTP drives a scripted FTP AUTH TLS dialog.
func TestStartTLSNegotiateFTP(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "220 FTP server ready\r\n", expect: "AUTH TLS"},
		{send: "234 AUTH TLS successful\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()

	if err := startTLSNegotiate(context.Background(), conn, "ftp", 2*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(ftp) error: %v", err)
	}
	<-done
}

// TestStartTLSNegotiatePostgres drives the PostgreSQL SSLRequest exchange. The
// server reads the 8-byte request and replies with the single byte 'S'.
func TestStartTLSNegotiatePostgres(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 8)
		if _, err := conn.Read(buf); err != nil {
			t.Errorf("postgres server read: %v", err)
			return
		}
		if _, err := conn.Write([]byte{'S'}); err != nil {
			t.Errorf("postgres server write: %v", err)
		}
	}()

	conn := dialScript(t, ln.Addr().String())
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "postgres", 2*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(postgres) error: %v", err)
	}
	<-done
}

// TestStartTLSNegotiatePostgresUnsupported asserts a non-'S' reply is an error.
func TestStartTLSNegotiatePostgresUnsupported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{'N'})
	}()

	conn := dialScript(t, ln.Addr().String())
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "postgres", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(postgres) = nil; want error when TLS unsupported")
	}
}

// TestStartTLSNegotiateLDAP drives the LDAP StartTLS exchange against a server
// that sends a complete extendedResponse PDU, as real servers do. The
// negotiator must consume the whole PDU: any unread response bytes would be
// read by the TLS client afterwards and corrupt the handshake. The sentinel
// byte the server writes after the PDU stands in for the first TLS byte and
// must be the very next thing read from the connection.
func TestStartTLSNegotiateLDAP(t *testing.T) {
	// Minimal successful extendedResponse: messageID 1, resultCode success,
	// empty matchedDN and diagnosticMessage.
	shortForm := []byte{
		0x30, 0x0c, // SEQUENCE, length 12
		0x02, 0x01, 0x01, // INTEGER 1 (messageID)
		0x78, 0x07, // [APPLICATION 24] ExtendedResponse, length 7
		0x0a, 0x01, 0x00, // ENUMERATED 0 (success)
		0x04, 0x00, // OCTET STRING "" (matchedDN)
		0x04, 0x00, // OCTET STRING "" (diagnosticMessage)
	}
	// The same PDU with the outer length in long form (0x81 0x0c), which
	// servers emit for larger responses.
	longForm := append([]byte{0x30, 0x81, 0x0c}, shortForm[2:]...)

	tests := []struct {
		name string
		pdu  []byte
	}{
		{name: "short-form length", pdu: shortForm},
		{name: "long-form length", pdu: longForm},
	}
	const sentinel = 0x16 // first byte of a TLS handshake record

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, len(ldapStartTLSRequest))
				if _, err := conn.Read(buf); err != nil {
					t.Errorf("ldap server read: %v", err)
					return
				}
				if buf[0] != 0x30 || buf[1] != 0x1d {
					t.Errorf("ldap request prefix = % X; want 30 1D", buf[:2])
				}
				if _, err := conn.Write(append(tc.pdu, sentinel)); err != nil {
					t.Errorf("ldap server write: %v", err)
				}
			}()

			conn := dialScript(t, ln.Addr().String())
			defer conn.Close()
			if err := startTLSNegotiate(context.Background(), conn, "ldap", 2*time.Second); err != nil {
				t.Fatalf("startTLSNegotiate(ldap) error: %v", err)
			}
			var next [1]byte
			if _, err := io.ReadFull(conn, next[:]); err != nil {
				t.Fatalf("read byte after negotiation: %v", err)
			}
			if next[0] != sentinel {
				t.Errorf("byte after negotiation = 0x%02x; want 0x%02x (leftover PDU bytes would corrupt the TLS handshake)", next[0], sentinel)
			}
			<-done
		})
	}
}

// TestStartTLSNegotiateUnknownProto rejects an unknown protocol token.
func TestStartTLSNegotiateUnknownProto(t *testing.T) {
	// A connection is required only to satisfy the signature; the proto is
	// rejected before any I/O after the deadline is set, but a live conn keeps
	// the deadline call from failing. Use a bound, immediately-served listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Keep the accepted connection open until the test finishes. The unknown
	// proto is rejected before any I/O, so no server-side dialog (and no timed
	// sleep) is needed.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			<-done
		}
	}()
	conn := dialScript(t, ln.Addr().String())
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "carrier-pigeon", time.Second); err == nil {
		t.Fatal("startTLSNegotiate(unknown) = nil; want error")
	}
}

// TestSweepClosedPort verifies a sweep against a closed loopback port records
// the port as not open with no error escaping Sweep itself.
func TestSweepClosedPort(t *testing.T) {
	// Bind then close a port so it is guaranteed refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	port := mustAtoi(t, portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Sweep(ctx, "127.0.0.1", SweepOptions{Ports: []int{port}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Sweep error: %v", err)
	}
	if len(res.Ports) != 1 {
		t.Fatalf("Sweep returned %d ports; want 1", len(res.Ports))
	}
	if res.Ports[0].Open {
		t.Errorf("closed port reported Open = true")
	}
	if res.Ports[0].TLS {
		t.Errorf("closed port reported TLS = true")
	}
}

// TestSweepTLSSuccess exercises the cert-reading success path: a local TLS
// server on a non-curated port is swept via direct TLS, and the result must
// report the port open, TLS negotiated, no error, and a parsed expiry.
func TestSweepTLSSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port := mustAtoi(t, portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Sweep(ctx, "127.0.0.1", SweepOptions{Ports: []int{port}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Sweep error: %v", err)
	}
	if len(res.Ports) != 1 {
		t.Fatalf("Sweep returned %d ports; want 1", len(res.Ports))
	}
	pr := res.Ports[0]
	if !pr.Open {
		t.Errorf("Open = false; want true for live TLS server")
	}
	if !pr.TLS {
		t.Errorf("TLS = false; want true for live TLS server")
	}
	if pr.Error != "" {
		t.Errorf("Error = %q; want empty", pr.Error)
	}
	if pr.NotAfter == nil {
		t.Errorf("NotAfter is nil; want a parsed expiry")
	}
	// A non-curated port attempts direct TLS, so the proto label falls back.
	if pr.Proto != "tls" {
		t.Errorf("Proto = %q; want %q for a non-curated direct-TLS port", pr.Proto, "tls")
	}
}

// TestProbeIPCertSuccess covers the per-IP success path used by --all-ips: a
// direct connection to a live TLS server returns a populated fingerprint and
// expiry with no error.
func TestProbeIPCertSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := probeIPCert(ctx, "127.0.0.1", portStr, "127.0.0.1", "", 5*time.Second)
	if res.Error != "" {
		t.Fatalf("Error = %q; want empty", res.Error)
	}
	if res.FingerprintSHA256 == "" {
		t.Errorf("FingerprintSHA256 is empty; want a populated fingerprint")
	}
	if res.NotAfter == nil {
		t.Errorf("NotAfter is nil; want a parsed expiry")
	}
}

// TestProbeIPCertRefused covers the per-IP failure path: a closed port yields an
// error and an empty fingerprint.
func TestProbeIPCertRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := probeIPCert(ctx, "127.0.0.1", portStr, "127.0.0.1", "", time.Second)
	if res.Error == "" {
		t.Errorf("Error is empty; want a connection error for a closed port")
	}
	if res.FingerprintSHA256 != "" {
		t.Errorf("FingerprintSHA256 = %q; want empty on failure", res.FingerprintSHA256)
	}
}

// TestSweepEmptyHost rejects an empty host.
func TestSweepEmptyHost(t *testing.T) {
	if _, err := Sweep(context.Background(), "", SweepOptions{}); err == nil {
		t.Fatal("Sweep(empty host) = nil error; want error")
	}
}

// TestDefaultSweepPortsSorted confirms the curated default port list is sorted
// and contains representative entries.
func TestDefaultSweepPortsSorted(t *testing.T) {
	ports := DefaultSweepPorts()
	if len(ports) == 0 {
		t.Fatal("DefaultSweepPorts is empty")
	}
	for i := 1; i < len(ports); i++ {
		if ports[i] <= ports[i-1] {
			t.Fatalf("DefaultSweepPorts not strictly ascending at %d: %v", i, ports)
		}
	}
	if _, ok := curatedPorts[443]; !ok {
		t.Error("curated ports missing 443")
	}
	if _, ok := curatedPorts[5432]; !ok {
		t.Error("curated ports missing 5432")
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("non-numeric port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// TestCheckSANsCapAndSeam exercises the SAN-name cap and the injectable
// resolver seam: names beyond maxSANChecks are not probed (and reported as such),
// and swapping lookupIP lets the test resolve without real DNS.
func TestCheckSANsCapAndSeam(t *testing.T) {
	orig := lookupIP
	lookupIP = func(_ context.Context, _, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupIP = orig })

	names := make([]string, maxSANChecks+5)
	for i := range names {
		names[i] = "host.example"
	}
	// Port 1 is closed, so probes resolve (via the seam) but are unreachable;
	// the test only asserts the cap and the seam, not reachability.
	checks, notProbed := checkSANs(context.Background(), names, "1", 200*time.Millisecond)
	if len(checks) != maxSANChecks {
		t.Errorf("probed %d names; want cap of %d", len(checks), maxSANChecks)
	}
	if notProbed != 5 {
		t.Errorf("notProbed = %d; want 5", notProbed)
	}
	if len(checks) == 0 || !checks[0].Resolved {
		t.Errorf("resolver seam not used: first name should resolve via the fake resolver")
	}
}

// testTLSCert borrows the certificate httptest generates so the STARTTLS-then-
// handshake tests need no manual certificate generation.
func testTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	if srv.TLS == nil || len(srv.TLS.Certificates) == 0 {
		t.Fatal("httptest TLS server exposed no certificate")
	}
	return srv.TLS.Certificates[0]
}

// runSMTPStartTLSServer plays the server side of an SMTP STARTTLS dialog and
// then upgrades the same connection to TLS using cert, so a client can be tested
// across the full negotiate-then-handshake path. The plaintext dialog is strictly
// lock-step, so the bufio reader holds no buffered TLS bytes when the raw
// connection is handed to tls.Server.
func runSMTPStartTLSServer(t *testing.T, cert tls.Certificate) (addr string, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		write := func(s string) bool { _, werr := conn.Write([]byte(s)); return werr == nil }
		readLine := func() bool { _, rerr := br.ReadString('\n'); return rerr == nil }

		if !write("220 mail.test ESMTP ready\r\n") || !readLine() { // EHLO
			return
		}
		if !write("250-mail.test\r\n250 STARTTLS\r\n") || !readLine() { // STARTTLS
			return
		}
		if !write("220 go ahead\r\n") {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server TLS handshake after STARTTLS: %v", err)
			return
		}
		_ = tlsConn.Close()
	}()
	return ln.Addr().String(), finished
}

// TestStartTLSThenHandshake exercises the full STARTTLS-then-TLS path used by
// scan and sweep: negotiate the upgrade, then complete the handshake on the same
// connection. It also verifies tlsHandshake clears the deadline left by the
// negotiation (otherwise the handshake would inherit a stale deadline).
func TestStartTLSThenHandshake(t *testing.T) {
	addr, done := runSMTPStartTLSServer(t, testTLSCert(t))
	conn := dialScript(t, addr)
	defer conn.Close()

	ctx := context.Background()
	if err := startTLSNegotiate(ctx, conn, "smtp", 3*time.Second); err != nil {
		t.Fatalf("startTLSNegotiate(smtp): %v", err)
	}
	tlsConn, err := tlsHandshake(ctx, conn, "example.com", 3*time.Second)
	if err != nil {
		t.Fatalf("tlsHandshake after STARTTLS: %v", err)
	}
	defer tlsConn.Close()
	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		t.Fatal("no peer certificates retrieved after STARTTLS handshake")
	}
	<-done
}

// TestProbePortSTARTTLS covers the sweep STARTTLS port path: probePort must
// negotiate the upgrade and then read the leaf certificate.
func TestProbePortSTARTTLS(t *testing.T) {
	addr, done := runSMTPStartTLSServer(t, testTLSCert(t))
	_, portStr, _ := net.SplitHostPort(addr)
	port := mustAtoi(t, portStr)

	res := probePort(context.Background(), "127.0.0.1", port, "smtp", 5*time.Second)
	if !res.Open {
		t.Errorf("Open = false; want true")
	}
	if !res.TLS {
		t.Errorf("TLS = false (err=%q); want true after STARTTLS", res.Error)
	}
	if res.NotAfter == nil {
		t.Errorf("NotAfter is nil; want a parsed expiry")
	}
	<-done
}

// TestStartTLSNegotiateIMAPRefused asserts a tagged non-OK reply is an error.
func TestStartTLSNegotiateIMAPRefused(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "* OK ready\r\n", expect: "a1 STARTTLS"},
		{send: "a1 NO STARTTLS not available\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(imap) = nil; want error for refused STARTTLS")
	}
	<-done
}

// TestStartTLSNegotiatePOP3Refused asserts a -ERR STLS reply is an error.
func TestStartTLSNegotiatePOP3Refused(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "+OK POP3 ready\r\n", expect: "STLS"},
		{send: "-ERR STLS not supported\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "pop3", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(pop3) = nil; want error for refused STLS")
	}
	<-done
}

// TestStartTLSNegotiateFTPRefused asserts a non-234 AUTH TLS reply is an error.
func TestStartTLSNegotiateFTPRefused(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "220 FTP ready\r\n", expect: "AUTH TLS"},
		{send: "500 AUTH not understood\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "ftp", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(ftp) = nil; want error for refused AUTH TLS")
	}
	<-done
}

// TestProbeIPCertsOrchestrator exercises the concurrent per-IP orchestrator and
// its same-fingerprint aggregation: two addresses pointing at one server yield
// two results that agree (differ=false), confirming the wiring beyond the pure
// ipCertsDiffer unit test.
func TestProbeIPCertsOrchestrator(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	certs, differ := probeIPCerts(context.Background(), "127.0.0.1", portStr, "127.0.0.1", "",
		[]string{"127.0.0.1", "127.0.0.1"}, 5*time.Second)
	if len(certs) != 2 {
		t.Fatalf("got %d IPCerts; want 2", len(certs))
	}
	if differ {
		t.Error("differ = true for one identical server; want false")
	}
	for _, c := range certs {
		if c.Error != "" || c.FingerprintSHA256 == "" {
			t.Errorf("unexpected per-IP result: %+v", c)
		}
	}
}

// TestProbeIPCertSTARTTLS proves the per-IP probe used by --all-ips honors a
// STARTTLS mechanism: it negotiates the SMTP upgrade against a scripted server
// and then completes the handshake, returning a populated fingerprint. Without
// the proto wiring this path would attempt a direct TLS handshake against the
// plaintext SMTP greeting and fail.
func TestProbeIPCertSTARTTLS(t *testing.T) {
	addr, done := runSMTPStartTLSServer(t, testTLSCert(t))
	_, portStr, _ := net.SplitHostPort(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := probeIPCert(ctx, "127.0.0.1", portStr, "127.0.0.1", "smtp", 5*time.Second)
	if res.Error != "" {
		t.Fatalf("Error = %q; want empty for a STARTTLS server", res.Error)
	}
	if res.FingerprintSHA256 == "" {
		t.Errorf("FingerprintSHA256 is empty; want a populated fingerprint after STARTTLS")
	}
	<-done
}

// TestStartTLSNegotiateReplyTooLong asserts the reply read is bounded: a server
// that floods bytes without a line terminator cannot make the negotiator buffer
// unbounded memory. The flood exceeds maxReplyBytes, so the LimitReader reaches
// EOF before a newline and the read fails instead of growing without limit.
func TestStartTLSNegotiateReplyTooLong(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		// Send well over maxReplyBytes (64 KiB) with no '\n' so the client can
		// never complete a line. Ignore write errors: once the client gives up
		// and closes, the remaining writes fail, which is expected.
		flood := make([]byte, 128<<10)
		for i := range flood {
			flood[i] = 'A'
		}
		_, _ = conn.Write(flood)
	}()

	conn := dialScript(t, ln.Addr().String())
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "smtp", 3*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(smtp) = nil; want error for an oversized newline-less reply")
	}
	<-done
}

// TestStartTLSNegotiateIMAPPreauth asserts a "* PREAUTH" greeting is accepted
// (RFC 3501 permits it), while a "* BYE" greeting is rejected.
func TestStartTLSNegotiateIMAPPreauth(t *testing.T) {
	t.Run("preauth accepted", func(t *testing.T) {
		addr, done := runScriptedServer(t, []scriptStep{
			{send: "* PREAUTH [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n", expect: "a1 STARTTLS"},
			{send: "a1 OK Begin TLS negotiation now\r\n"},
		})
		conn := dialScript(t, addr)
		defer conn.Close()
		if err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second); err != nil {
			t.Fatalf("startTLSNegotiate(imap) error for PREAUTH greeting: %v", err)
		}
		<-done
	})

	t.Run("bye rejected", func(t *testing.T) {
		addr, done := runScriptedServer(t, []scriptStep{
			{send: "* BYE server shutting down\r\n"},
		})
		conn := dialScript(t, addr)
		defer conn.Close()
		if err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second); err == nil {
			t.Fatal("startTLSNegotiate(imap) = nil; want error for a * BYE greeting")
		}
		<-done
	})
}

// TestStartTLSNegotiateInjection asserts plaintext-injection hardening: when the
// server sends application data immediately after the final STARTTLS reply (in a
// single write, so loopback delivers it in one read and the client buffers it),
// the negotiator rejects it rather than proceeding to a handshake over
// attacker-influenced state.
func TestStartTLSNegotiateInjection(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "* OK ready\r\n", expect: "a1 STARTTLS"},
		// The tagged OK and the injected line arrive in one write.
		{send: "a1 OK begin\r\nINJECTED PLAINTEXT\r\n"},
	})
	conn := dialScript(t, addr)
	defer conn.Close()
	if err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second); err == nil {
		t.Fatal("startTLSNegotiate(imap) = nil; want error for buffered data before TLS")
	}
	<-done
}

// TestCheckSANsCanceledContext verifies that names never dispatched because the
// context was canceled are reported as not probed instead of surfacing as
// zero-valued checks, which would render as (and be counted as) dead SANs.
func TestCheckSANsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("name%d.invalid", i)
	}
	checks, notProbed := checkSANs(ctx, names, "443", time.Second)

	if got := len(checks) + notProbed; got != len(names) {
		t.Errorf("len(checks)+notProbed = %d; want %d (every name accounted for)", got, len(names))
	}
	for i, c := range checks {
		if c.Name == "" {
			t.Fatalf("checks[%d].Name is empty; undispatched zero-valued check leaked into the results", i)
		}
	}
}

// TestProbeIPCertsCanceledContext verifies that addresses never dispatched
// because the context was canceled are dropped from the results instead of
// surfacing as zero-valued entries with no IP, which would render as empty
// per-IP rows.
func TestProbeIPCertsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ips := make([]string, 40)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	certs, differ := probeIPCerts(ctx, "example.invalid", "443", "example.invalid", "", ips, time.Second)

	for i, c := range certs {
		if c.IP == "" {
			t.Fatalf("certs[%d].IP is empty; undispatched zero-valued entry leaked into the results", i)
		}
	}
	if differ {
		t.Error("differ = true; no certificate was retrieved, so none can differ")
	}
}

// TestSweepCanceledContext verifies that ports never dispatched because the
// context was canceled are dropped from the results instead of surfacing as
// zero-valued entries, which would render as a bogus port 0.
func TestSweepCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ports := make([]int, 300)
	for i := range ports {
		ports[i] = 10000 + i
	}
	sr, err := Sweep(ctx, "192.0.2.1", SweepOptions{Ports: ports, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Sweep error: %v", err)
	}
	if len(sr.Ports) > len(ports) {
		t.Errorf("len(sr.Ports) = %d; want at most %d", len(sr.Ports), len(ports))
	}
	for i, p := range sr.Ports {
		if p.Port < 10000 {
			t.Fatalf("sr.Ports[%d].Port = %d; undispatched zero-valued entry leaked into the results", i, p.Port)
		}
	}
}
