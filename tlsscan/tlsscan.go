// Package tlsscan connects to a TLS endpoint, retrieves the presented
// certificate chain, and reports detailed information about it.
//
// Verification is intentionally skipped during the handshake so that any
// certificate can be inspected, including expired, self-signed, or
// wrong-host certificates. Trust and hostname matching are evaluated
// separately and reported as independent facts.
//
// This package is the importable half of tlsee. Scan is its entry point: give
// it a target and Options, and it returns one Report describing what the
// endpoint presented. Callers that only want to know what a local service is
// serving should set ResolveDNS and CheckSANs to false, which skips the
// lookups that only make sense from outside the host.
package tlsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Options controls how a scan is performed.
type Options struct {
	// Port overrides the port to connect to when the target does not
	// include one. Defaults to "443".
	Port string
	// Timeout bounds the dial and handshake. Defaults to 10s.
	Timeout time.Duration
	// ServerName overrides the SNI sent during the handshake. When empty,
	// the host parsed from the target is used.
	ServerName string
	// ResolveDNS controls whether the host's A/AAAA records are looked up.
	// It is ignored for IP literals.
	ResolveDNS bool
	// CheckSANs controls whether each DNS name in the certificate's SAN list
	// is resolved (A/AAAA) and TCP-probed on the scanned port to detect dead
	// or stale entries. Wildcard SAN names are reported but not probed.
	CheckSANs bool
	// StartTLS selects a plaintext-to-TLS upgrade protocol to negotiate before
	// the handshake. The empty string (the default) means direct TLS. Valid
	// values are: smtp, imap, pop3, ftp, postgres, ldap.
	StartTLS string
	// AllIPs controls whether, after the primary scan, every resolved A/AAAA
	// address of the host is connected to individually (SNI set to the host)
	// to retrieve its leaf certificate. This catches load-balancer backends
	// serving a stale or mismatched certificate. It is ignored for IP literals.
	AllIPs bool
}

// CertInfo describes a single parsed certificate.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SubjectCN          string    `json:"subjectCommonName"`
	IssuerCN           string    `json:"issuerCommonName"`
	KeyBits            int       `json:"keyBits"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DaysRemaining      int       `json:"daysRemaining"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"notYetValid"`
	DNSNames           []string  `json:"dnsNames"`
	IPAddresses        []string  `json:"ipAddresses"`
	IsCA               bool      `json:"isCA"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	FingerprintSHA256  string    `json:"fingerprintSHA256"`
}

// AddrCheck is the liveness result for a single resolved address.
type AddrCheck struct {
	IP        string `json:"ip"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// IPCert is the leaf certificate retrieved from a single resolved address of
// the host when AllIPs is set. It captures just enough to detect that backends
// behind one name disagree (for example a load-balancer member serving a stale
// certificate). Error is set instead of the certificate fields when the address
// could not be reached or its handshake failed.
type IPCert struct {
	IP                string     `json:"ip"`
	FingerprintSHA256 string     `json:"fingerprintSHA256,omitempty"`
	SubjectCN         string     `json:"subjectCommonName,omitempty"`
	NotAfter          *time.Time `json:"notAfter,omitempty"`
	DaysRemaining     int        `json:"daysRemaining,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// SANOwnership classifies whether a SAN name still points at the scanned host.
// It is evaluated only for names that resolve and are reachable; a wildcard, an
// unresolved name, and an unreachable name all keep OwnershipUnknown.
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

// SANCheck is the liveness result for one DNS name from a certificate's SAN
// list: whether it resolves, and whether any resolved address accepts a TCP
// connection on the scanned port. Wildcard names are flagged and not probed.
type SANCheck struct {
	Name      string `json:"name"`
	Wildcard  bool   `json:"wildcard"`
	Resolved  bool   `json:"resolved"`
	Reachable bool   `json:"reachable"`
	// Ownership records whether this name still points at the scanned host.
	Ownership SANOwnership `json:"ownership,omitempty"`
	Addrs     []AddrCheck  `json:"addrs,omitempty"`
}

// Report is the full result of scanning a target.
type Report struct {
	Target        string     `json:"target"`
	Host          string     `json:"host"`
	Port          string     `json:"port"`
	ResolvedIPs   []string   `json:"resolvedIPs"`
	TLSVersion    string     `json:"tlsVersion"`
	CipherSuite   string     `json:"cipherSuite"`
	Leaf          CertInfo   `json:"leaf"`
	Chain         []CertInfo `json:"chain"`
	ChainTrusted  bool       `json:"chainTrusted"`
	HostnameMatch bool       `json:"hostnameMatch"`
	VerifyError   string     `json:"verifyError,omitempty"`
	ElapsedMs     int64      `json:"elapsedMs"`
	// WarnDays is the threshold below which an unexpired certificate is
	// considered "expiring soon". It is carried on the report so that
	// rendering and exit-code logic share a single source of truth without
	// depending on the wall clock.
	WarnDays int `json:"warnDays"`
	// SANChecks holds the per-name liveness results when CheckSANs is set.
	SANChecks []SANCheck `json:"sanChecks,omitempty"`
	// DeadSANs counts non-wildcard SAN names that did not resolve or whose
	// every resolved address was unreachable.
	DeadSANs int `json:"deadSANs"`
	// SANsElsewhere counts names that resolve away from the scanned host and
	// are served by a different certificate (or could not be confirmed). Like
	// DeadSANs it is advisory and never feeds the exit code. It is always
	// serialized so a consumer can tell "checked, none moved" from a scan that
	// did not run the check.
	SANsElsewhere int `json:"sansElsewhere"`
	// SANsNotProbed is the number of SAN names skipped by the liveness check,
	// either because the certificate exceeded maxSANChecks names or because
	// the scan was canceled before they were probed.
	SANsNotProbed int `json:"sansNotProbed,omitempty"`
	// Warnings holds informational hygiene findings (weak TLS version, weak
	// signature algorithm, weak RSA key, or a weak negotiated cipher suite).
	// Warnings never change the exit code or the status headline.
	Warnings []string `json:"warnings,omitempty"`
	// IPCerts holds the per-address leaf certificates retrieved when AllIPs is
	// set. It is empty for IP literals and single-address hosts.
	IPCerts []IPCert `json:"ipCerts,omitempty"`
	// IPCertsDiffer is true when the reachable addresses in IPCerts do not all
	// present the same leaf fingerprint. It is always serialized (no omitempty)
	// so a JSON consumer can distinguish "checked, all agree" (false) from a
	// scan that did not run the per-IP comparison (IPCerts absent).
	IPCertsDiffer bool `json:"ipCertsDiffer"`
}

// Healthy reports whether the certificate needs no attention: it chains to a
// trusted root, matches the hostname, is currently valid, and is not within the
// warn window. It is the single source of truth for the process exit code and
// the --quiet row filter, so the cli and report packages do not each re-derive
// it.
func (r *Report) Healthy() bool {
	return r.ChainTrusted &&
		r.HostnameMatch &&
		!r.Leaf.Expired &&
		!r.Leaf.NotYetValid &&
		r.Leaf.DaysRemaining > r.WarnDays
}

// lookupIP resolves a host's A/AAAA addresses. It is a package var so tests can
// substitute a deterministic resolver instead of hitting real DNS.
var lookupIP = net.DefaultResolver.LookupIP

// SweepOptions controls a multi-port sweep of a single host.
type SweepOptions struct {
	// Ports is the explicit list of ports to probe. When empty, the curated
	// default port table is used.
	Ports []int
	// Timeout bounds each per-port probe (TCP connect plus any STARTTLS and
	// handshake). Defaults to defaultSweepTimeout so closed ports fail fast.
	Timeout time.Duration
	// Concurrency caps how many ports are probed at once. Defaults to
	// defaultSweepConcurrency.
	Concurrency int
}

// PortResult is the outcome of probing a single port during a sweep.
type PortResult struct {
	Port          int        `json:"port"`
	Proto         string     `json:"proto"`
	Open          bool       `json:"open"`
	TLS           bool       `json:"tls"`
	SubjectCN     string     `json:"subjectCommonName,omitempty"`
	NotAfter      *time.Time `json:"notAfter,omitempty"`
	DaysRemaining int        `json:"daysRemaining,omitempty"`
	Expired       bool       `json:"expired,omitempty"`
	NotYetValid   bool       `json:"notYetValid,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// SweepResult is the full outcome of sweeping one host's ports.
type SweepResult struct {
	Host  string       `json:"host"`
	Ports []PortResult `json:"ports"`
}

const (
	defaultPort     = "443"
	defaultTimeout  = 10 * time.Second
	defaultWarnDays = 30
	// maxProbeTimeout bounds each SAN liveness probe independently of the
	// handshake timeout, so a single dead or firewalled name cannot stall a
	// scan for the full dial timeout.
	maxProbeTimeout = 3 * time.Second
	// sanProbeConcurrency caps how many SAN names are probed at once.
	sanProbeConcurrency = 8
	// maxSANChecks caps how many SAN names are probed for liveness, so a
	// certificate carrying thousands of SAN entries cannot turn one scan into
	// thousands of DNS lookups and outbound connections.
	maxSANChecks = 100
	// ipCertConcurrency caps how many per-IP certificate probes run at once.
	ipCertConcurrency = 8
	// defaultSweepTimeout bounds each per-port probe in a sweep, kept short so
	// closed ports fail fast.
	defaultSweepTimeout = 3 * time.Second
	// defaultSweepConcurrency caps concurrent port probes for a curated sweep.
	defaultSweepConcurrency = 64
	// minRSABits is the smallest RSA modulus size not flagged as weak.
	minRSABits = 2048
)

// Scan connects to target over TLS, retrieves the certificate chain, and
// returns a populated Report. Connection-level failures return a wrapped
// error and a nil report; certificate problems are reported within the
// Report rather than as errors.
func Scan(ctx context.Context, target string, opts Options) (*Report, error) {
	host, port, err := parseTarget(target, opts.Port)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	warnDays := defaultWarnDays

	// Bound the entire scan (connect + STARTTLS + handshake + DNS + SAN/AllIPs
	// probes) by a single timeout budget, mirroring how the sweep engine wraps
	// one per-port context. The per-call timeout argument is kept as the dialer
	// and handshake deadline; threading scanCtx as the base makes the nested
	// per-phase contexts take the min of the two, so the whole scan cannot exceed
	// --timeout no matter how many phases run.
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sni := opts.ServerName
	if sni == "" {
		sni = host
	}

	addr := net.JoinHostPort(host, port)

	start := time.Now()
	conn, err := dialPlaintext(scanCtx, addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if opts.StartTLS != "" {
		if err := startTLSNegotiate(scanCtx, conn, opts.StartTLS, timeout); err != nil {
			return nil, fmt.Errorf("starttls %s on %s: %w", opts.StartTLS, addr, err)
		}
	}

	tlsConn, err := tlsHandshake(scanCtx, conn, sni, timeout)
	if err != nil {
		return nil, fmt.Errorf("handshake %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()
	elapsed := time.Since(start).Milliseconds()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("connect %s: server presented no certificates", addr)
	}

	now := time.Now()
	leaf := state.PeerCertificates[0]

	report := &Report{
		Target:      target,
		Host:        host,
		Port:        port,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Leaf:        certInfo(leaf, now),
		ElapsedMs:   elapsed,
		WarnDays:    warnDays,
	}

	for _, c := range state.PeerCertificates[1:] {
		report.Chain = append(report.Chain, certInfo(c, now))
	}

	// Trust: verify to a system root without any hostname constraint.
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	if _, verifyErr := leaf.Verify(x509.VerifyOptions{
		Intermediates: pool,
		Roots:         nil,
	}); verifyErr != nil {
		report.ChainTrusted = false
		report.VerifyError = verifyErr.Error()
	} else {
		report.ChainTrusted = true
	}

	// Hostname matching is independent of trust. VerifyHostname also
	// handles IP SANs, so the parsed host is passed directly.
	report.HostnameMatch = leaf.VerifyHostname(host) == nil

	// DNS resolution is best-effort and skipped for IP literals. It is
	// bounded by its own timeout-derived context so a slow resolver cannot
	// make the scan exceed --timeout.
	// Post-handshake enrichment (DNS resolution, SAN liveness, per-IP probing)
	// runs on the original ctx, NOT scanCtx. scanCtx's single --timeout budget
	// is depleted by the connect and handshake; reusing it here would give the
	// enrichment little or no time and, worse, make checkSANs/probeIPCerts trip
	// their cancellation path and report un-probed names as dead. These steps
	// carry their own per-probe timeouts and still honor ctx cancellation.
	if opts.ResolveDNS && net.ParseIP(host) == nil {
		lookupCtx, lookupCancel := context.WithTimeout(ctx, timeout)
		defer lookupCancel()
		if ips, lookupErr := net.DefaultResolver.LookupHost(lookupCtx, host); lookupErr == nil {
			report.ResolvedIPs = ips
		}
	}

	// SAN liveness: resolve and TCP-probe each certificate name to surface
	// dead or stale entries (names left on the cert that no longer resolve or
	// whose host is down). Probes run concurrently with their own short
	// timeout so this never dominates scan latency.
	if opts.CheckSANs && len(report.Leaf.DNSNames) > 0 {
		report.SANChecks, report.SANsNotProbed = checkSANs(ctx, report.Leaf.DNSNames, port, probeTimeout(timeout))
		for _, c := range report.SANChecks {
			if !c.Wildcard && (!c.Resolved || !c.Reachable) {
				report.DeadSANs++
			}
		}
	}

	// Hygiene warnings are derived from already-known facts about the leaf and
	// the negotiated connection. They are informational only and never change
	// the exit code or status headline.
	report.Warnings = hygieneWarnings(
		state.Version,
		report.Leaf.SignatureAlgorithm,
		report.Leaf.PublicKeyAlgorithm,
		report.Leaf.KeyBits,
		state.CipherSuite,
		report.CipherSuite,
	)

	// Per-IP certificates: connect to every resolved address (SNI=host) to
	// detect backends serving a stale or mismatched certificate. Skipped for IP
	// literals; only meaningful when more than one address resolves.
	if opts.AllIPs && net.ParseIP(host) == nil {
		report.IPCerts, report.IPCertsDiffer = probeIPCerts(ctx, host, port, sni, opts.StartTLS, report.ResolvedIPs, probeTimeout(timeout))
	}

	return report, nil
}

// hygieneWarnings evaluates informational hardening findings from already-known
// connection facts. It is a pure function of its inputs so it can be tested
// without a network. version and cipher are the negotiated TLS protocol version
// and cipher-suite identifier; cipherName is the human-readable suite name used
// in the message; sigAlg and pubKeyAlgo are the leaf's algorithm strings; and
// keyBits is the leaf public-key size (0 when unknown). Warnings never affect
// the exit code.
func hygieneWarnings(version uint16, sigAlg, pubKeyAlgo string, keyBits int, cipher uint16, cipherName string) []string {
	var warnings []string

	if version < tls.VersionTLS12 {
		warnings = append(warnings, "weak TLS version: "+tlsVersionName(version))
	}

	upperSig := strings.ToUpper(sigAlg)
	if strings.Contains(upperSig, "SHA1") || strings.Contains(upperSig, "MD5") {
		warnings = append(warnings, "weak signature algorithm: "+sigAlg)
	}

	if pubKeyAlgo == "RSA" && keyBits > 0 && keyBits < minRSABits {
		warnings = append(warnings, fmt.Sprintf("weak RSA key: %d bits", keyBits))
	}

	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == cipher {
			warnings = append(warnings, "weak cipher suite: "+cipherName)
			break
		}
	}

	return warnings
}

// probeTimeout derives the per-probe timeout from the scan timeout, capped so
// a single dead name cannot block a scan for the whole dial timeout.
func probeTimeout(timeout time.Duration) time.Duration {
	if timeout < maxProbeTimeout {
		return timeout
	}
	return maxProbeTimeout
}

// checkSANs probes every name concurrently, preserving input order. Each
// goroutine writes its own slot, so no synchronization beyond the WaitGroup
// is needed.
func checkSANs(ctx context.Context, names []string, port string, timeout time.Duration) (checks []SANCheck, notProbed int) {
	if len(names) > maxSANChecks {
		notProbed = len(names) - maxSANChecks
		names = names[:maxSANChecks]
	}
	checks = make([]SANCheck, len(names))
	sem := make(chan struct{}, sanProbeConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		// Acquire a slot, but stop dispatching promptly on cancellation
		// (Ctrl-C/SIGTERM) instead of launching every remaining probe. Names
		// never dispatched are counted as not probed rather than left as
		// zero-valued checks, which would render as (and count as) dead SANs.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Truncate only after the in-flight probes finish: the spawned
			// goroutines read the checks slice header through their closure, so
			// reassigning it before Wait would race with them.
			notProbed += len(names) - i
			wg.Wait()
			return checks[:i], notProbed
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			checks[i] = checkSAN(ctx, name, port, timeout)
		}(i, name)
	}
	wg.Wait()
	return checks, notProbed
}

// checkSAN resolves a single SAN name and TCP-probes each resolved address.
// Wildcard names (for example "*.example.com") cannot be resolved as-is, so
// they are reported but not probed.
func checkSAN(ctx context.Context, name, port string, timeout time.Duration) SANCheck {
	sc := SANCheck{Name: name}
	if strings.HasPrefix(name, "*.") {
		sc.Wildcard = true
		return sc
	}

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := lookupIP(lookupCtx, "ip", name)
	if err != nil || len(ips) == 0 {
		return sc // Resolved stays false.
	}
	sc.Resolved = true

	for _, ip := range ips {
		ok, probeErr := probeAddr(ctx, ip.String(), port, timeout)
		ac := AddrCheck{IP: ip.String(), Reachable: ok}
		if !ok && probeErr != nil {
			ac.Error = probeErr.Error()
		}
		if ok {
			sc.Reachable = true
		}
		sc.Addrs = append(sc.Addrs, ac)
	}
	return sc
}

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

// probeAddr reports whether a TCP connection to ip:port can be established
// within timeout. It is the deterministic core of the liveness check and
// takes an IP literal so it performs no name resolution itself.
func probeAddr(ctx context.Context, ip, port string, timeout time.Duration) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

// probeIPCerts resolves every A/AAAA address of host and connects to each one
// (with SNI set to sni) to retrieve its leaf certificate. proto is the STARTTLS
// mechanism to negotiate before the handshake ("" for direct TLS), so --all-ips
// works for STARTTLS services. It returns the per-address results and whether
// the reachable addresses disagree on the leaf fingerprint. Resolution failures
// or a single resolved address yield an empty result, since there is nothing to
// compare.
func probeIPCerts(ctx context.Context, host, port, sni, proto string, resolved []string, timeout time.Duration) ([]IPCert, bool) {
	// Reuse the addresses the scan already resolved; only fall back to a lookup
	// when the caller has none (for example when DNS resolution was disabled for
	// the main scan).
	ips := resolved
	if len(ips) == 0 {
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		looked, err := net.DefaultResolver.LookupHost(lookupCtx, host)
		if err != nil {
			return nil, false
		}
		ips = looked
	}
	if len(ips) < 2 {
		return nil, false
	}

	results := make([]IPCert, len(ips))
	sem := make(chan struct{}, ipCertConcurrency)
	var wg sync.WaitGroup
	for i, ip := range ips {
		// Stop dispatching promptly on cancellation. Addresses never dispatched
		// are dropped from the results: a zero-valued entry carries no address
		// or error and would render as an empty per-IP row.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Truncate only after the in-flight probes finish: the spawned
			// goroutines read the results slice header through their closure, so
			// reassigning it before Wait would race with them.
			wg.Wait()
			results = results[:i]
			return results, ipCertsDiffer(results)
		}
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probeIPCert(ctx, ip, port, sni, proto, timeout)
		}(i, ip)
	}
	wg.Wait()

	differ := ipCertsDiffer(results)
	return results, differ
}

// probeIPCert connects to a single resolved address, presenting sni, and
// retrieves its leaf certificate. proto is the STARTTLS mechanism negotiated
// before the handshake ("" for direct TLS), mirroring Scan's main path so
// --all-ips works for STARTTLS services. Any failure is captured in
// IPCert.Error.
func probeIPCert(ctx context.Context, ip, port, sni, proto string, timeout time.Duration) IPCert {
	res := IPCert{IP: ip}
	addr := net.JoinHostPort(ip, port)

	conn, err := dialPlaintext(ctx, addr, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	if proto != "" {
		if err := startTLSNegotiate(ctx, conn, proto, timeout); err != nil {
			res.Error = err.Error()
			return res
		}
	}

	tlsConn, err := tlsHandshake(ctx, conn, sni, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Error = "server presented no certificates"
		return res
	}

	now := time.Now()
	info := certInfo(state.PeerCertificates[0], now)
	res.FingerprintSHA256 = info.FingerprintSHA256
	res.SubjectCN = info.SubjectCN
	notAfter := info.NotAfter
	res.NotAfter = &notAfter
	res.DaysRemaining = info.DaysRemaining
	return res
}

// ipCertsDiffer reports whether the reachable addresses (those without an
// error) present more than one distinct leaf fingerprint. Unreachable addresses
// are ignored, so a single transient failure does not flag a difference.
func ipCertsDiffer(certs []IPCert) bool {
	var first string
	seen := false
	for _, c := range certs {
		if c.Error != "" || c.FingerprintSHA256 == "" {
			continue
		}
		if !seen {
			first = c.FingerprintSHA256
			seen = true
			continue
		}
		if c.FingerprintSHA256 != first {
			return true
		}
	}
	return false
}

// parseTarget splits a target into host and port. It strips a leading
// scheme and any trailing path or query, then splits the host and port.
// When no port is present, defaultPortOverride (or 443) is used. IPv6
// literals such as "[::1]:8443" and "[::1]" are handled.
func parseTarget(target, defaultPortOverride string) (host, port string, err error) {
	port = defaultPort
	if defaultPortOverride != "" {
		if _, perr := parsePort(defaultPortOverride); perr != nil {
			return "", "", fmt.Errorf("parse target: invalid default port: %w", perr)
		}
		port = defaultPortOverride
	}

	remainder := strings.TrimSpace(target)
	if remainder == "" {
		return "", "", fmt.Errorf("parse target: empty target")
	}

	// Strip a leading scheme such as "https://" or "tls://".
	if i := strings.Index(remainder, "://"); i >= 0 {
		remainder = remainder[i+len("://"):]
	}

	// Strip any trailing path or query. For an IPv6 literal the host is
	// inside brackets, so only look past the closing bracket.
	cut := remainder
	if strings.HasPrefix(remainder, "[") {
		if end := strings.IndexByte(remainder, ']'); end >= 0 {
			cut = remainder[end:]
			if slash := strings.IndexAny(cut, "/?"); slash >= 0 {
				remainder = remainder[:end] + cut[:slash]
			}
		}
	} else if slash := strings.IndexAny(remainder, "/?"); slash >= 0 {
		remainder = remainder[:slash]
	}

	if remainder == "" {
		return "", "", fmt.Errorf("parse target %q: no host", target)
	}

	h, p, splitErr := net.SplitHostPort(remainder)
	if splitErr != nil {
		// No port present: treat the remainder as a bare host. This covers a
		// hostname or IPv4 ("missing port in address") and a bare IPv6 literal
		// like "::1" or "2001:db8::1", for which SplitHostPort instead reports
		// "too many colons in address".
		bare := strings.TrimSuffix(strings.TrimPrefix(remainder, "["), "]")
		if net.ParseIP(bare) != nil || strings.Contains(splitErr.Error(), "missing port in address") {
			return bare, port, nil
		}
		return "", "", fmt.Errorf("parse target %q: %w", target, splitErr)
	}

	if p != "" {
		if _, perr := parsePort(p); perr != nil {
			return "", "", fmt.Errorf("parse target %q: %w", target, perr)
		}
		port = p
	}
	return h, port, nil
}

// certInfo builds a CertInfo from a parsed certificate, evaluating
// validity relative to now.
func certInfo(c *x509.Certificate, now time.Time) CertInfo {
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}

	sum := sha256.Sum256(c.Raw)

	return CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SubjectCN:          c.Subject.CommonName,
		IssuerCN:           c.Issuer.CommonName,
		KeyBits:            keyBits(c.PublicKey),
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		DaysRemaining:      int(c.NotAfter.Sub(now).Hours() / 24),
		Expired:            now.After(c.NotAfter),
		NotYetValid:        now.Before(c.NotBefore),
		DNSNames:           c.DNSNames,
		IPAddresses:        ips,
		IsCA:               c.IsCA,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  formatFingerprint(sum[:]),
	}
}

// keyBits returns the size of a public key in bits: the modulus length for RSA,
// the curve size for ECDSA, 256 for Ed25519, and 0 for any unrecognized key.
func keyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// formatFingerprint renders a digest as colon-separated uppercase hex.
func formatFingerprint(sum []byte) string {
	const hexDigits = "0123456789ABCDEF"
	b := make([]byte, 0, len(sum)*3)
	for i, v := range sum {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hexDigits[v>>4], hexDigits[v&0x0f])
	}
	return string(b)
}

// tlsVersionName maps a TLS version constant to a friendly string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
