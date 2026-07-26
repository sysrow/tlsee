# Stale SAN Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report SAN names on a certificate that no longer resolve to the host being scanned, so an operator can see which names on a certificate are stale before renewing it.

**Architecture:** Two stages inside the existing SAN liveness check. First, compare the name's resolved addresses against the scanned host's own addresses — free, using data the scan already collected. Only when the two sets are disjoint, open one confirming TLS handshake to the name (SNI set to that name) and compare leaf fingerprints, which separates a CDN serving our certificate from a host that has taken the name over. The finding is advisory: it changes output only, never the exit code.

**Tech Stack:** Go 1.25 standard library only. `net/netip` for address comparison, `crypto/x509` for generating a second test certificate, existing `probeIPCert` for the confirming handshake.

## Global Constraints

- **No third-party dependencies.** Standard library only; this is a deliberate project constraint.
- **All code artifacts in English**: identifiers, comments, commit messages, CLI output strings, docs.
- **No emojis anywhere**, including commit messages and output strings.
- **Tests never touch the external network.** Local listeners on `127.0.0.1:0` and the `lookupIP` seam only.
- **Every commit must pass:** `gofmt -l .` (empty), `go vet ./...`, `go test -race -count=1 ./...`.
- **Exit codes are unchanged by this feature.** `0` healthy, `1` runtime error, `2` certificate problem. `Report.Healthy()`, the `--quiet` filter, and `--insecure` all keep their current behavior.
- **Commit author** is `sysrow <rohovskytomas@seznam.cz>`; never add co-author or generated-by trailers.

---

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `tlsscan/tlsscan.go` | Ownership type, pure classification helpers, wiring into `Scan` | Modify |
| `tlsscan/core_test.go` | Tests for the classification helpers and the confirming handshake | Modify |
| `internal/report/report.go` | New palette color, SAN state rendering, headline and batch note | Modify |
| `internal/report/render_test.go` | Render tests for each new state | Modify |
| `internal/report/report_test.go` | Headline tests for the new advisory | Modify |
| `README.md`, `internal/cli/cli.go`, `CLAUDE.md` | User-facing and contributor documentation | Modify |

---

### Task 1: Ownership type and pure classification helpers

**Files:**
- Modify: `tlsscan/tlsscan.go` (add type near `SANCheck` at line 104; add helpers near `checkSAN` at line 457)
- Test: `tlsscan/core_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `SANOwnership` string type with constants `OwnershipUnknown`, `OwnershipSameHost`, `OwnershipSameCert`, `OwnershipOtherCert`, `OwnershipUnverified`; field `SANCheck.Ownership SANOwnership`; field `Report.SANsElsewhere int`; `hostAddrSet(host string, resolved []string) map[netip.Addr]bool`; `classifyAddrs(addrs []AddrCheck, hostAddrs map[netip.Addr]bool) (sameHost bool, probeIP string)`; `countSANFindings(checks []SANCheck) (dead, elsewhere int)`.

- [ ] **Step 1: Write the failing tests**

Add to `tlsscan/core_test.go`. Add `"net/netip"` to that file's import block.

```go
func TestHostAddrSet(t *testing.T) {
	// A hostname target contributes only its resolved addresses; an IP-literal
	// target contributes itself, since no lookup ran for it.
	set := hostAddrSet("example.test", []string{"192.0.2.10", "2001:db8::1"})
	if len(set) != 2 {
		t.Fatalf("len(set) = %d; want 2", len(set))
	}
	if !set[netip.MustParseAddr("192.0.2.10")] {
		t.Error("resolved IPv4 address missing from the set")
	}

	literal := hostAddrSet("192.0.2.20", nil)
	if !literal[netip.MustParseAddr("192.0.2.20")] {
		t.Error("IP-literal target should contribute itself as the host address")
	}

	// A malformed entry is skipped rather than failing the scan.
	if got := len(hostAddrSet("not-an-ip", []string{"garbage"})); got != 0 {
		t.Errorf("len = %d; want 0 for unparseable input", got)
	}
}

func TestClassifyAddrs(t *testing.T) {
	tests := []struct {
		name         string
		addrs        []AddrCheck
		hostAddrs    []string
		wantSameHost bool
		wantProbeIP  string
	}{
		{
			name:         "shared address means the name still points at the host",
			addrs:        []AddrCheck{{IP: "192.0.2.10", Reachable: true}},
			hostAddrs:    []string{"192.0.2.10"},
			wantSameHost: true,
			wantProbeIP:  "",
		},
		{
			name:         "disjoint addresses select the first reachable one to probe",
			addrs:        []AddrCheck{{IP: "198.51.100.5"}, {IP: "198.51.100.6", Reachable: true}},
			hostAddrs:    []string{"192.0.2.10"},
			wantSameHost: false,
			wantProbeIP:  "198.51.100.6",
		},
		{
			name:         "disjoint but nothing reachable yields no probe address",
			addrs:        []AddrCheck{{IP: "198.51.100.5"}},
			hostAddrs:    []string{"192.0.2.10"},
			wantSameHost: false,
			wantProbeIP:  "",
		},
		{
			name:         "two spellings of one IPv6 address are the same address",
			addrs:        []AddrCheck{{IP: "2001:0db8:0000:0000:0000:0000:0000:0001", Reachable: true}},
			hostAddrs:    []string{"2001:db8::1"},
			wantSameHost: true,
			wantProbeIP:  "",
		},
		{
			name:         "unparseable address is skipped",
			addrs:        []AddrCheck{{IP: "garbage", Reachable: true}, {IP: "198.51.100.7", Reachable: true}},
			hostAddrs:    []string{"192.0.2.10"},
			wantSameHost: false,
			wantProbeIP:  "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := hostAddrSet("", tt.hostAddrs)
			sameHost, probeIP := classifyAddrs(tt.addrs, set)
			if sameHost != tt.wantSameHost {
				t.Errorf("sameHost = %v; want %v", sameHost, tt.wantSameHost)
			}
			if probeIP != tt.wantProbeIP {
				t.Errorf("probeIP = %q; want %q", probeIP, tt.wantProbeIP)
			}
		})
	}
}

func TestCountSANFindings(t *testing.T) {
	checks := []SANCheck{
		{Name: "wild", Wildcard: true},
		{Name: "ok", Resolved: true, Reachable: true, Ownership: OwnershipSameHost},
		{Name: "cdn", Resolved: true, Reachable: true, Ownership: OwnershipSameCert},
		{Name: "nodns"},
		{Name: "down", Resolved: true},
		{Name: "moved", Resolved: true, Reachable: true, Ownership: OwnershipOtherCert},
		{Name: "maybe", Resolved: true, Reachable: true, Ownership: OwnershipUnverified},
	}
	dead, elsewhere := countSANFindings(checks)
	if dead != 2 {
		t.Errorf("dead = %d; want 2 (nodns and down; wildcards never count)", dead)
	}
	if elsewhere != 2 {
		t.Errorf("elsewhere = %d; want 2 (moved and maybe; same-cert does not count)", elsewhere)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'TestHostAddrSet|TestClassifyAddrs|TestCountSANFindings' ./tlsscan/`
Expected: FAIL to compile — `undefined: hostAddrSet`, `undefined: classifyAddrs`, `undefined: countSANFindings`, `undefined: OwnershipSameHost`.

- [ ] **Step 3: Add the type and the `SANCheck` field**

In `tlsscan/tlsscan.go`, add `"net/netip"` to the import block. Immediately above the `SANCheck` type (line 104), add:

```go
// SANOwnership classifies whether a SAN name still points at the scanned host.
// It is evaluated only for names that resolve and are reachable; a wildcard,
// an unresolved name, and an unreachable name all keep OwnershipUnknown.
type SANOwnership string

const (
	// OwnershipUnknown means the comparison could not be made, because the
	// scanned host's own addresses are unknown or the name was never probed.
	OwnershipUnknown SANOwnership = ""
	// OwnershipSameHost means the name resolves to at least one address that
	// the scanned host also resolves to.
	OwnershipSameHost SANOwnership = "same-host"
	// OwnershipSameCert means the name resolves elsewhere, but that endpoint
	// presents the same leaf certificate: a CDN or a second front-end.
	OwnershipSameCert SANOwnership = "same-cert"
	// OwnershipOtherCert means the name resolves elsewhere and that endpoint
	// presents a different certificate: the name has moved away, and carrying
	// it on this certificate is stale.
	OwnershipOtherCert SANOwnership = "other-cert"
	// OwnershipUnverified means the name resolves elsewhere but the confirming
	// handshake failed, so which of the two it is remains unclear.
	OwnershipUnverified SANOwnership = "unverified"
)
```

Then add the field to `SANCheck`, after `Reachable`:

```go
	// Ownership records whether this name still points at the scanned host.
	Ownership SANOwnership `json:"ownership,omitempty"`
```

- [ ] **Step 4: Add the `Report` counter**

In `tlsscan/tlsscan.go`, directly after the `DeadSANs` field on `Report`:

```go
	// SANsElsewhere counts names that resolve away from the scanned host and
	// are served by a different certificate (or could not be confirmed). Like
	// DeadSANs it is advisory and never feeds the exit code. It is always
	// serialized so a consumer can tell "checked, none moved" from a scan that
	// did not run the check.
	SANsElsewhere int `json:"sansElsewhere"`
```

- [ ] **Step 5: Implement the three helpers**

Add to `tlsscan/tlsscan.go`, after `checkSAN` (which ends at line 484):

```go
// hostAddrSet builds the set of addresses belonging to the scanned host, used
// to decide whether a SAN name still points at it. resolved holds the addresses
// DNS returned for the host; an IP-literal target contributes itself, since no
// lookup runs for one. Addresses are keyed as netip.Addr rather than strings so
// two spellings of one IPv6 address compare equal, and unmapped so an
// IPv4-in-IPv6 form matches its plain IPv4 counterpart. Unparseable entries are
// skipped: a malformed address should not fail an otherwise good scan.
func hostAddrSet(host string, resolved []string) map[netip.Addr]bool {
	set := make(map[netip.Addr]bool, len(resolved)+1)
	for _, s := range resolved {
		if a, err := netip.ParseAddr(s); err == nil {
			set[a.Unmap()] = true
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		set[a.Unmap()] = true
	}
	return set
}

// classifyAddrs reports whether any of a SAN name's addresses belongs to the
// scanned host, and when none does, which address a confirming handshake should
// use. probeIP is the first reachable address, or "" when none is reachable (in
// which case the name is already reported as unreachable and needs no further
// diagnosis).
func classifyAddrs(addrs []AddrCheck, hostAddrs map[netip.Addr]bool) (sameHost bool, probeIP string) {
	for _, ac := range addrs {
		a, err := netip.ParseAddr(ac.IP)
		if err != nil {
			continue
		}
		if hostAddrs[a.Unmap()] {
			return true, ""
		}
		if ac.Reachable && probeIP == "" {
			probeIP = ac.IP
		}
	}
	return false, probeIP
}

// countSANFindings tallies the two advisory SAN counters from completed checks.
// A dead name is a non-wildcard name that did not resolve or whose every address
// was unreachable. An elsewhere name resolves away from the scanned host and is
// served by a different certificate, or could not be confirmed either way; a
// name confirmed to serve our own certificate from another address does not
// count, since a CDN front-end is not a stale entry.
func countSANFindings(checks []SANCheck) (dead, elsewhere int) {
	for _, c := range checks {
		if c.Wildcard {
			continue
		}
		if !c.Resolved || !c.Reachable {
			dead++
			continue
		}
		if c.Ownership == OwnershipOtherCert || c.Ownership == OwnershipUnverified {
			elsewhere++
		}
	}
	return dead, elsewhere
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -race -run 'TestHostAddrSet|TestClassifyAddrs|TestCountSANFindings' ./tlsscan/ -v`
Expected: PASS, all three tests.

- [ ] **Step 7: Verify nothing else broke**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 ./...`
Expected: no gofmt output, no vet output, all tests PASS. The existing `DeadSANs` counting loop in `Scan` is untouched at this point, so behavior is unchanged.

- [ ] **Step 8: Commit**

```bash
git add tlsscan/tlsscan.go tlsscan/core_test.go
git commit -m "feat(tlsscan): add SAN ownership type and classification helpers

Adds SANOwnership with the states a SAN name can have relative to the scanned
host, plus the pure helpers that compare address sets and tally the advisory
counters. Not wired into Scan yet, so behavior is unchanged."
```

---

### Task 2: Confirming handshake and wiring into Scan

**Files:**
- Modify: `tlsscan/tlsscan.go` (`checkSANs` line 420, `checkSAN` line 457, `Scan` lines 344-351)
- Test: `tlsscan/core_test.go`

**Interfaces:**
- Consumes: `SANOwnership` constants, `hostAddrSet`, `classifyAddrs`, `countSANFindings` from Task 1; existing `probeIPCert(ctx context.Context, ip, port, sni, proto string, timeout time.Duration) IPCert` at `tlsscan/tlsscan.go:561`.
- Produces: `sanContext` struct; `classifyOwnership(ctx context.Context, addrs []AddrCheck, name, port string, timeout time.Duration, sctx sanContext) SANOwnership`; changed signatures `checkSANs(ctx, names, port, timeout, sctx)` and `checkSAN(ctx, name, port, timeout, sctx)`.

- [ ] **Step 1: Write the failing tests**

Add to `tlsscan/core_test.go`. Add these imports to that file if absent: `"crypto/ecdsa"`, `"crypto/elliptic"`, `"crypto/rand"`, `"crypto/x509"`, `"crypto/x509/pkix"`, `"math/big"`.

These tests call `classifyOwnership` directly rather than going through `Scan`, because SAN liveness probes always use the scanned port — calling the helper lets each case point at a listener on its own port without loopback aliases.

```go
// newSelfSignedCert generates a throwaway self-signed certificate so a test can
// stand up a TLS server whose leaf differs from the one httptest shares across
// all of its servers.
func newSelfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// runLeafServer starts a TLS listener that completes handshakes and closes,
// which is all a fingerprint probe needs. It returns the port it listens on.
func runLeafServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				_ = tc.Handshake()
			}()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	return port
}

// leafFingerprint returns the SHA-256 fingerprint of a tls.Certificate's leaf,
// in the same colon-separated form the scanner records on a report.
func leafFingerprint(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certInfo(parsed, time.Now()).FingerprintSHA256
}

func TestClassifyOwnershipSameHostSkipsHandshake(t *testing.T) {
	// Port 1 is closed, so any confirming handshake would fail and yield
	// OwnershipUnverified. Getting OwnershipSameHost back proves the free path
	// short-circuited and no handshake was attempted.
	addrs := []AddrCheck{{IP: "192.0.2.10", Reachable: true}}
	sctx := sanContext{
		hostAddrs:   hostAddrSet("", []string{"192.0.2.10"}),
		fingerprint: "AA:BB",
	}
	got := classifyOwnership(context.Background(), addrs, "name.test", "1", time.Second, sctx)
	if got != OwnershipSameHost {
		t.Errorf("Ownership = %q; want %q", got, OwnershipSameHost)
	}
}

func TestClassifyOwnershipUnknownWithoutHostAddrs(t *testing.T) {
	addrs := []AddrCheck{{IP: "192.0.2.10", Reachable: true}}
	got := classifyOwnership(context.Background(), addrs, "name.test", "1", time.Second, sanContext{})
	if got != OwnershipUnknown {
		t.Errorf("Ownership = %q; want %q when the host's own addresses are unknown", got, OwnershipUnknown)
	}
}

func TestClassifyOwnershipOtherCert(t *testing.T) {
	other := newSelfSignedCert(t, "other.test")
	port := runLeafServer(t, other)

	// The name resolves to a reachable address that is not ours, and the
	// endpoint there serves a certificate we do not recognize.
	addrs := []AddrCheck{{IP: "127.0.0.1", Reachable: true}}
	sctx := sanContext{
		hostAddrs:   hostAddrSet("", []string{"192.0.2.10"}),
		fingerprint: leafFingerprint(t, newSelfSignedCert(t, "ours.test")),
	}
	got := classifyOwnership(context.Background(), addrs, "moved.test", port, 2*time.Second, sctx)
	if got != OwnershipOtherCert {
		t.Errorf("Ownership = %q; want %q", got, OwnershipOtherCert)
	}
}

func TestClassifyOwnershipSameCert(t *testing.T) {
	shared := newSelfSignedCert(t, "shared.test")
	port := runLeafServer(t, shared)

	// A different address, but it serves our own certificate: a CDN or a second
	// front-end, not a stale name.
	addrs := []AddrCheck{{IP: "127.0.0.1", Reachable: true}}
	sctx := sanContext{
		hostAddrs:   hostAddrSet("", []string{"192.0.2.10"}),
		fingerprint: leafFingerprint(t, shared),
	}
	got := classifyOwnership(context.Background(), addrs, "cdn.test", port, 2*time.Second, sctx)
	if got != OwnershipSameCert {
		t.Errorf("Ownership = %q; want %q", got, OwnershipSameCert)
	}
}

func TestClassifyOwnershipUnverifiedWhenHandshakeFails(t *testing.T) {
	// A listener that accepts and immediately closes never completes a TLS
	// handshake, so the confirming probe fails and the verdict stays open.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	addrs := []AddrCheck{{IP: "127.0.0.1", Reachable: true}}
	sctx := sanContext{
		hostAddrs:   hostAddrSet("", []string{"192.0.2.10"}),
		fingerprint: "AA:BB",
	}
	got := classifyOwnership(context.Background(), addrs, "maybe.test", port, 2*time.Second, sctx)
	if got != OwnershipUnverified {
		t.Errorf("Ownership = %q; want %q", got, OwnershipUnverified)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run TestClassifyOwnership ./tlsscan/`
Expected: FAIL to compile — `undefined: sanContext`, `undefined: classifyOwnership`.

- [ ] **Step 3: Add `sanContext` and `classifyOwnership`**

In `tlsscan/tlsscan.go`, add after the helpers from Task 1:

```go
// sanContext carries what a SAN liveness check needs to know about the scan it
// belongs to, so a name can be classified as still pointing at the scanned host
// or as having moved elsewhere. It is passed as one value rather than three
// loose parameters because every field is needed together or not at all.
type sanContext struct {
	// hostAddrs is the scanned host's own address set. An empty set disables
	// ownership classification: there is nothing to compare against.
	hostAddrs map[netip.Addr]bool
	// fingerprint is the scanned host's leaf SHA-256, compared against whatever
	// a moved name is served by.
	fingerprint string
	// startTLS is the mechanism the confirming handshake must negotiate first,
	// mirroring the main scan so --starttls targets classify correctly.
	startTLS string
}

// classifyOwnership decides whether a reachable SAN name still points at the
// scanned host. When the name's addresses are disjoint from the host's, one TLS
// handshake to a reachable address settles whether it is a second front-end for
// the same certificate or a host that has taken the name over. SNI is set to the
// SAN name, not the scanned host, because the question is what that name is
// served by.
func classifyOwnership(ctx context.Context, addrs []AddrCheck, name, port string, timeout time.Duration, sctx sanContext) SANOwnership {
	if len(sctx.hostAddrs) == 0 {
		return OwnershipUnknown
	}
	sameHost, probeIP := classifyAddrs(addrs, sctx.hostAddrs)
	if sameHost {
		return OwnershipSameHost
	}
	if probeIP == "" {
		return OwnershipUnknown
	}

	res := probeIPCert(ctx, probeIP, port, name, sctx.startTLS, timeout)
	switch {
	case res.Error != "" || res.FingerprintSHA256 == "":
		return OwnershipUnverified
	case res.FingerprintSHA256 == sctx.fingerprint:
		return OwnershipSameCert
	default:
		return OwnershipOtherCert
	}
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test -race -run TestClassifyOwnership ./tlsscan/ -v`
Expected: PASS, all five tests. The rest of the suite still compiles because `checkSAN` has not changed yet.

- [ ] **Step 5: Commit the classification core**

```bash
git add tlsscan/tlsscan.go tlsscan/core_test.go
git commit -m "feat(tlsscan): confirm a moved SAN name with a leaf fingerprint

Adds classifyOwnership, which compares a SAN name's addresses against the
scanned host's and, only when they are disjoint, opens one handshake to compare
leaf fingerprints. Not yet called from checkSAN."
```

- [ ] **Step 6: Thread `sanContext` through `checkSANs` and `checkSAN`**

In `tlsscan/tlsscan.go`, change the two signatures and the call between them.

`checkSANs` (line 420) — signature and the goroutine body:

```go
func checkSANs(ctx context.Context, names []string, port string, timeout time.Duration, sctx sanContext) (checks []SANCheck, notProbed int) {
```

and inside its goroutine, replace the `checkSAN` call with:

```go
			checks[i] = checkSAN(ctx, name, port, timeout, sctx)
```

`checkSAN` (line 457) — signature, and the classification at the end. Replace the closing `return sc` with the ownership step:

```go
func checkSAN(ctx context.Context, name, port string, timeout time.Duration, sctx sanContext) SANCheck {
```

```go
	// Ownership is only meaningful for a name that resolves and answers: an
	// unresolved or unreachable name is already reported as dead and needs no
	// further diagnosis.
	if sc.Resolved && sc.Reachable {
		sc.Ownership = classifyOwnership(ctx, sc.Addrs, name, port, timeout, sctx)
	}
	return sc
}
```

- [ ] **Step 7: Wire it into `Scan`**

In `tlsscan/tlsscan.go`, replace the SAN block at lines 344-351 with:

```go
	if opts.CheckSANs && len(report.Leaf.DNSNames) > 0 {
		sctx := sanContext{
			hostAddrs:   hostAddrSet(host, report.ResolvedIPs),
			fingerprint: report.Leaf.FingerprintSHA256,
			startTLS:    opts.StartTLS,
		}
		report.SANChecks, report.SANsNotProbed = checkSANs(ctx, report.Leaf.DNSNames, port, probeTimeout(timeout), sctx)
		report.DeadSANs, report.SANsElsewhere = countSANFindings(report.SANChecks)
	}
```

- [ ] **Step 8: Fix the remaining `checkSANs` callers in tests**

Run: `go build ./... && go vet ./...`
Expected: compile errors in `tlsscan/core_test.go` at the existing `checkSANs` calls in `TestCheckSANsCapAndSeam` and `TestCheckSANsCanceledContext`.

Add `sanContext{}` as the final argument to both:

```go
	checks, notProbed := checkSANs(context.Background(), names, "1", 200*time.Millisecond, sanContext{})
```

```go
	checks, notProbed := checkSANs(ctx, names, "443", time.Second, sanContext{})
```

An empty `sanContext` means no host addresses are known, so those tests keep classification switched off and continue to assert only what they asserted before.

- [ ] **Step 9: Run the full suite**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 ./...`
Expected: no gofmt output, no vet output, all tests PASS.

- [ ] **Step 10: Commit**

```bash
git add tlsscan/tlsscan.go tlsscan/core_test.go
git commit -m "feat(tlsscan): classify SAN names that no longer point at the host

Threads the scan's own addresses, leaf fingerprint, and STARTTLS mechanism into
the SAN liveness check, so each reachable name is classified as same-host,
same-cert, other-cert, or unverified. Advisory only: exit codes are unchanged."
```

---

### Task 3: Render the new states

**Files:**
- Modify: `internal/report/report.go` (palette at line 22, `sanLiveness` at line 584)
- Test: `internal/report/render_test.go`

**Interfaces:**
- Consumes: `tlsscan.SANOwnership` constants and `tlsscan.SANCheck.Ownership` from Tasks 1-2.
- Produces: `colorMagenta` constant; `sanLiveness` returning the new state strings.

- [ ] **Step 1: Write the failing test**

Add to `internal/report/render_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestSANLiveness' ./internal/report/`
Expected: FAIL to compile — `undefined: colorMagenta`.

- [ ] **Step 3: Add the palette entry**

In `internal/report/report.go`, in the color block at lines 22-28, add after `colorYellow`:

```go
	// colorMagenta is reserved for one condition: a SAN name that no longer
	// points at the scanned host. Keeping it exclusive is what makes a moved
	// name visually distinct from a healthy one (green) and from a dead or
	// degraded one (red, yellow).
	colorMagenta = "\033[35m"
```

- [ ] **Step 4: Rewrite `sanLiveness`**

Replace the whole function at `internal/report/report.go:584` with:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -race -run 'TestSANLiveness' ./internal/report/ -v`
Expected: PASS, both tests.

Note while you are in this file: in the SAN liveness block of `WriteText`
(line 229-238) the state cell is colored *before* it reaches the tabwriter,
which is safe only because it is the last column — tabwriter measures byte
width, so an ANSI-colored cell with anything after it would misalign. Do not add
a column after the state cell. If one is ever needed, adopt the batch-table
pattern instead: lay the table out monochrome into a buffer, then colorize.

- [ ] **Step 6: Run the full suite**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 ./...`
Expected: no output from gofmt or vet, all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/report/report.go internal/report/render_test.go
git commit -m "feat(report): render moved SAN names in magenta

Adds a magenta palette entry reserved for SAN names that no longer point at the
scanned host, and reports ownership in place of open/partial for those names."
```

---

### Task 4: Headline advisory and batch note

**Files:**
- Modify: `internal/report/report.go` (`summarize` line 51, `deadSANStatus` line 94, `rowStatus` line 344, `WriteBatchTable` line 424)
- Test: `internal/report/report_test.go`, `internal/report/render_test.go`

**Interfaces:**
- Consumes: `tlsscan.Report.SANsElsewhere` from Task 1.
- Produces: `elsewhereSANStatus(n int) string`; `sanAdvisory(r *tlsscan.Report) string`; `batchStatus.note` field replacing `batchStatus.dead`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/report/report_test.go`:

```go
func TestSummarizeElsewhereAdvisory(t *testing.T) {
	tests := []struct {
		name      string
		dead      int
		elsewhere int
		wantText  string
		wantColor string
	}{
		{name: "clean", dead: 0, elsewhere: 0, wantText: "VALID", wantColor: colorGreen},
		{name: "moved only", dead: 0, elsewhere: 3, wantText: "VALID | 3 SANS ELSEWHERE", wantColor: colorYellow},
		{name: "one moved", dead: 0, elsewhere: 1, wantText: "VALID | 1 SAN ELSEWHERE", wantColor: colorYellow},
		{name: "dead and moved", dead: 1, elsewhere: 2, wantText: "VALID | 1 DEAD SAN | 2 SANS ELSEWHERE", wantColor: colorYellow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixedReport()
			r.DeadSANs = tt.dead
			r.SANsElsewhere = tt.elsewhere
			st := summarize(r)
			if st.text != tt.wantText {
				t.Errorf("text = %q; want %q", st.text, tt.wantText)
			}
			if st.color != tt.wantColor {
				t.Errorf("color = %q; want %q", st.color, tt.wantColor)
			}
		})
	}
}

func TestSummarizeMovedSANNeverTurnsHeadlineRed(t *testing.T) {
	// A moved SAN is advisory: it must never escalate the headline to red, the
	// color reserved for actual certificate problems.
	r := fixedReport()
	r.SANsElsewhere = 5
	if st := summarize(r); st.color == colorRed {
		t.Error("a moved SAN turned the headline red")
	}
	if st := summarize(r); st.color == colorMagenta {
		t.Error("headline uses magenta; magenta is reserved for the SAN liveness rows")
	}
}

func TestSummarizeRealProblemOutranksMovedSAN(t *testing.T) {
	r := fixedReport()
	r.ChainTrusted = false
	r.SANsElsewhere = 2
	st := summarize(r)
	if st.color != colorRed {
		t.Errorf("color = %q; want red when the chain is untrusted", st.color)
	}
	if !strings.Contains(st.text, "UNTRUSTED CHAIN") {
		t.Errorf("text = %q; want it to report the untrusted chain", st.text)
	}
	if !strings.Contains(st.text, "2 SANS ELSEWHERE") {
		t.Errorf("text = %q; want the moved-SAN advisory appended", st.text)
	}
}
```

Add to `internal/report/render_test.go`:

```go
func TestBatchNoteReportsMovedSANs(t *testing.T) {
	rows := batchRows()
	for i := range rows {
		if rows[i].Report != nil {
			rows[i].Report.SANsElsewhere = 2
			break
		}
	}
	var buf bytes.Buffer
	WriteBatchTable(&buf, rows, false, false)
	if !strings.Contains(buf.String(), "2 elsewhere") {
		t.Errorf("batch table missing the moved-SAN note; got:\n%s", buf.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'TestSummarize|TestBatchNote' ./internal/report/`
Expected: FAIL — the headline lacks the elsewhere advisory and the batch note lacks `2 elsewhere`.

- [ ] **Step 3: Add the advisory helpers**

In `internal/report/report.go`, after `deadSANStatus` (line 94-99), add:

```go
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
```

- [ ] **Step 4: Use them in `summarize`**

In `internal/report/report.go`, replace the two advisory blocks at the end of `summarize` (lines 76-90) with:

```go
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
```

Also update the doc comment above `summarize` (lines 42-50): replace the sentence beginning "Dead SANs are a non-red advisory" so it reads:

```go
// Dead SANs and SAN names that have moved to another host are non-red
// advisories, not certificate problems: they do not change the exit code and a
// certificate carrying only those stays "healthy" for --quiet, so they must
// neither erase the healthy VALID indicator nor turn the headline red. When the
// certificate is otherwise valid the headline reads "VALID | <advisory>" in
// yellow; when there is already a real problem the advisory is appended without
// escalating the color.
```

- [ ] **Step 5: Rename `batchStatus.dead` to `note` and include moved names**

In `internal/report/report.go`, change the `batchStatus` struct (lines 334-339):

```go
// batchStatus is the per-row status word, day count, advisory note, and color
// derived from a BatchRow for the summary table.
type batchStatus struct {
	status string
	days   string
	note   string
	color  string
}
```

In `rowStatus` (line 344), replace the `dead` local and every `dead: dead` with `note: note`, computing it as:

```go
	r := row.Report
	note := fmt.Sprintf("%d", r.DeadSANs)
	if r.SANsElsewhere > 0 {
		note = fmt.Sprintf("%d dead, %d elsewhere", r.DeadSANs, r.SANsElsewhere)
	}
	days := fmt.Sprintf("%d", r.Leaf.DaysRemaining)
```

The error branch at line 346 becomes:

```go
	if row.Err != "" {
		return batchStatus{status: "ERROR", days: "ERR", note: "-", color: colorRed}
	}
```

In `WriteBatchTable` (line 424), change:

```go
		note := bs.note
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -race -run 'TestSummarize|TestBatchNote' ./internal/report/ -v`
Expected: PASS, all four tests.

- [ ] **Step 7: Run the full suite**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 ./...`
Expected: no output from gofmt or vet, all tests PASS. If an existing batch render test asserted the exact `NOTE` cell, it still passes: a report with no moved SANs renders the bare count exactly as before.

- [ ] **Step 8: Commit**

```bash
git add internal/report/report.go internal/report/report_test.go internal/report/render_test.go
git commit -m "feat(report): report moved SAN names in the headline and batch note

The status headline gains an N SANS ELSEWHERE advisory alongside the dead-SAN
one, and the batch NOTE column reports the count when non-zero. Both stay
advisory: neither escalates the headline color nor the exit code."
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md` (SAN liveness table, lines 167-183)
- Modify: `internal/cli/cli.go` (`writeUsage` SAN paragraph, lines 613-617)
- Modify: `CLAUDE.md` (load-bearing invariants)

**Interfaces:**
- Consumes: the state names and behavior established in Tasks 1-4.
- Produces: no code.

- [ ] **Step 1: Update the README state table**

In `README.md`, replace the SAN liveness state table with:

```markdown
| State                        | Meaning                                                        |
| ---------------------------- | ------------------------------------------------------------- |
| `open`                       | Resolves to the scanned host and every address accepts a connection on the port. |
| `partial`                    | Resolves to the scanned host and some addresses are reachable (e.g. IPv4 up, IPv6 down). |
| `open (other IP, same cert)` | Resolves to a different address, but that endpoint serves the same certificate (a CDN or second front-end). |
| `elsewhere (other cert)`     | Resolves to a different address serving a different certificate: the name has moved away and is stale on this certificate. |
| `elsewhere (unverified)`     | Resolves to a different address, but the confirming handshake failed, so it is unclear which. |
| `unreachable`                | Resolves but no address accepts a connection.                 |
| `NO DNS (stale?)`            | Does not resolve at all -- likely a stale name on the cert.   |
| `wildcard (not probed)`      | A `*.` name, which cannot be resolved directly.               |
```

- [ ] **Step 2: Add a README paragraph on moved names**

In `README.md`, immediately after that table, before the existing "Names that are `unreachable`..." paragraph, insert:

```markdown
Each name is also checked against the scanned host itself. When a name resolves
to addresses the host does not have, `tlsee` opens one further handshake to that
address (presenting the name as SNI) and compares the certificate: the same leaf
means a second front-end, a different leaf means the name has moved to another
host and is stale on this certificate. Names that have moved are counted in the
status headline as `N SANS ELSEWHERE` and shown in magenta. Like dead SANs they
are advisory and do **not** change the exit code. The comparison costs no extra
connection for names that still point at the scanned host.
```

- [ ] **Step 3: Update `writeUsage`**

In `internal/cli/cli.go`, replace the SAN paragraph in the `writeUsage` raw string (lines 613-617) with:

```
By default tlsee also resolves and TCP-probes every DNS name in the
certificate's SAN list and reports dead or stale entries (a name that no
longer resolves, or whose host is unreachable on the port). A name that
resolves away from the scanned host is confirmed with one further handshake
and reported as "elsewhere" when another certificate is served there. Dead and
moved SANs are shown but do not change the exit code, which reflects the
certificate's own validity. Use --no-check to skip this.
```

- [ ] **Step 4: Update the `--no-check` flag description**

In `internal/cli/cli.go` at line 108, the flag's help text still describes only
the liveness half of the check. Replace it with:

```go
		noCheck   = fs.Bool("no-check", false, "skip SAN checks (resolve, TCP-probe, and confirm each certificate name still points at the host)")
```

- [ ] **Step 5: Update the CLAUDE.md invariants**

In `CLAUDE.md`, replace the "Dead SANs and hygiene warnings are advisory only" bullet with:

```markdown
- **Dead SANs, moved SANs, and hygiene warnings are advisory only**: they appear
  in output but must never change the exit code or turn the headline red.
  `sanAdvisory` in `internal/report` is where the SAN notes are composed for the
  headline; it appends without touching the color the real problems set.
- **Magenta is reserved for one condition**: a SAN name that no longer points at
  the scanned host. Keeping it exclusive is what makes a moved name distinct
  from a healthy one (green) and a dead one (red). Do not reuse it elsewhere.
- **SAN ownership classification is free unless something looks wrong**: address
  sets are compared from data the scan already has, and a confirming handshake
  runs only for a name whose addresses are disjoint from the host's. Keep that
  ordering — reversing it puts a handshake on every name of every certificate.
```

- [ ] **Step 6: Verify docs match behavior**

Run: `mkdir -p ~/scratch/go && go build -o ~/scratch/go/tlsee . && ~/scratch/go/tlsee help`
Expected: the help text shows the updated SAN paragraph. Read it and confirm it matches what Task 3 actually renders.

- [ ] **Step 7: Run the full suite one last time**

Run: `gofmt -l . && go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@latest ./... && go test -race -count=1 ./...`
Expected: no output from gofmt, vet, or staticcheck; all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add README.md internal/cli/cli.go CLAUDE.md
git commit -m "docs: document SAN names that no longer point at the scanned host

Adds the new SAN liveness states to the README table and help text, and records
the magenta-is-reserved and free-unless-suspicious invariants in CLAUDE.md."
```

---

## Verification

After Task 5, confirm the feature end to end against a host whose certificate
carries a name that has moved away:

```bash
go build -o tlsee . && ./tlsee scan <host-with-a-moved-san>
```

Expected: the moved name renders as `elsewhere (other cert)` in magenta, the
headline reads `... | N SANS ELSEWHERE`, and `echo $?` prints the same exit code
as before the change (`0` for an otherwise healthy certificate).

Also confirm the JSON shape:

```bash
./tlsee scan <host> --json | grep -E '"ownership"|"sansElsewhere"'
```

Expected: `"ownership": "other-cert"` on the moved name and a `"sansElsewhere"`
count on the report.
