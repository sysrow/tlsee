package tlsscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// portProto pairs the human-readable display protocol for a port with the
// STARTTLS mechanism needed to upgrade it. A mechanism of "" means direct TLS;
// otherwise it is one of the startTLSNegotiate protocol tokens (smtp, imap,
// pop3, ftp, postgres, ldap). The display name and the mechanism are distinct:
// port 5432 displays "postgresql" but its mechanism is "postgres".
type portProto struct {
	// Display is shown in the sweep table's PROTO column.
	Display string
	// StartTLS is the mechanism passed to startTLSNegotiate, or "" for direct
	// TLS.
	StartTLS string
}

// curatedPorts maps well-known TLS and STARTTLS ports to their protocols. It is
// the default sweep target list and also supplies the protocol for any port in
// the map when a custom or full sweep is requested.
var curatedPorts = map[int]portProto{
	// Direct TLS (HTTPS and HTTPS-like).
	443:   {Display: "https"},
	8443:  {Display: "https"},
	4443:  {Display: "https"},
	9443:  {Display: "https"},
	10250: {Display: "https"},
	// Direct TLS (implicit-TLS variants of plaintext protocols).
	993:  {Display: "imaps"},
	995:  {Display: "pop3s"},
	465:  {Display: "smtps"},
	636:  {Display: "ldaps"},
	990:  {Display: "ftps"},
	853:  {Display: "dns-tls"},
	5671: {Display: "amqps"},
	6697: {Display: "ircs"},
	8883: {Display: "mqtts"},
	// STARTTLS upgrades.
	587:  {Display: "smtp", StartTLS: "smtp"},
	25:   {Display: "smtp", StartTLS: "smtp"},
	143:  {Display: "imap", StartTLS: "imap"},
	110:  {Display: "pop3", StartTLS: "pop3"},
	389:  {Display: "ldap", StartTLS: "ldap"},
	21:   {Display: "ftp", StartTLS: "ftp"},
	5432: {Display: "postgresql", StartTLS: "postgres"},
}

// DefaultSweepPorts returns the curated default list of ports to sweep, sorted
// ascending.
func DefaultSweepPorts() []int {
	ports := make([]int, 0, len(curatedPorts))
	for p := range curatedPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// Sweep probes each requested port of host concurrently and returns one result
// per fully probed port, sorted ascending by port. Per-port failures are
// captured in the PortResult rather than returned as an error; an error is
// returned only for an invalid host or an empty port list. When ctx is
// canceled mid-sweep the ports probed so far are returned and the rest are
// counted in PortsNotProbed, so the caller can tell a partial sweep from a
// complete one.
func Sweep(ctx context.Context, host string, opts SweepOptions) (*SweepResult, error) {
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("sweep: empty host")
	}

	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultSweepPorts()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultSweepTimeout
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultSweepConcurrency
	}

	results := make([]PortResult, len(ports))
	interrupted := make([]bool, len(ports))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	dispatched := len(ports)
dispatch:
	for i, port := range ports {
		// Stop dispatching promptly on cancellation (Ctrl-C/SIGTERM) rather than
		// launching a probe for every remaining port (important for --full).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			dispatched = i
			break dispatch
		}
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			proto := curatedPorts[port].StartTLS
			results[i], interrupted[i] = probePort(ctx, host, port, proto, timeout)
		}(i, port)
	}
	wg.Wait()

	// Keep only the ports that reached a verdict. A port never dispatched would
	// surface as a zero-valued entry (a bogus port 0), and a probe cut short by
	// cancellation would masquerade as a closed or non-TLS port; both are
	// counted as not probed instead so a partial sweep is visible as such. The
	// filter runs only after Wait, since in-flight goroutines still write
	// through the results slice.
	probed := results[:0]
	for i := 0; i < dispatched; i++ {
		if interrupted[i] {
			continue
		}
		probed = append(probed, results[i])
	}

	sort.Slice(probed, func(a, b int) bool { return probed[a].Port < probed[b].Port })
	return &SweepResult{Host: host, Ports: probed, PortsNotProbed: len(ports) - len(probed)}, nil
}

// probePort probes a single port of host using the same dial, STARTTLS, and
// leaf-read path as Scan. proto is the STARTTLS mechanism ("" for direct TLS).
// It reports whether the port is open, whether TLS was negotiated, and the leaf
// certificate summary. Failures are recorded in PortResult.Error; a port that
// is open but never completes a TLS handshake is reported with TLS=false and
// Error "no TLS".
//
// The second result is true when ctx was canceled before the probe reached a
// verdict. A canceled dial or handshake fails exactly like a refused or
// non-TLS port would, so the PortResult then describes the cancellation, not
// the port, and the caller must not report it. A per-port timeout is a
// verdict (the port did not answer in time), not an interruption.
func probePort(ctx context.Context, host string, port int, proto string, timeout time.Duration) (PortResult, bool) {
	res := PortResult{Port: port, Proto: displayProto(port, proto)}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Bound the entire per-port probe (connect + STARTTLS + handshake) by a
	// single timeout budget, so a port cannot consume a multiple of the
	// configured timeout across its phases.
	portCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialPlaintext(portCtx, addr, timeout)
	if err != nil {
		// Closed or unreachable: Open stays false. The error is informational.
		return res, ctx.Err() != nil
	}
	defer conn.Close()
	res.Open = true

	if proto != "" {
		if err := startTLSNegotiate(portCtx, conn, proto, timeout); err != nil {
			res.Error = "no TLS"
			return res, ctx.Err() != nil
		}
	}

	tlsConn, err := tlsHandshake(portCtx, conn, host, timeout)
	if err != nil {
		res.Error = "no TLS"
		return res, ctx.Err() != nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Error = "no TLS"
		return res, false
	}

	res.TLS = true
	now := time.Now()
	info := certInfo(state.PeerCertificates[0], now)
	res.SubjectCN = info.SubjectCN
	notAfter := info.NotAfter
	res.NotAfter = &notAfter
	res.DaysRemaining = info.DaysRemaining
	res.Expired = info.Expired
	res.NotYetValid = info.NotYetValid
	return res, false
}

// displayProto returns the PROTO column value for a port. Ports in the curated
// map use their display name; an unknown port attempting a STARTTLS mechanism
// shows that mechanism, and an unknown port attempting direct TLS shows "tls".
func displayProto(port int, proto string) string {
	if pp, ok := curatedPorts[port]; ok {
		return pp.Display
	}
	if proto != "" {
		return proto
	}
	return "tls"
}

// ParsePortSpec parses a port specification into a deduplicated, ascending list
// of ports. The spec is a comma-separated list of single ports and inclusive
// ranges, for example "443,8443,9000-9100". Whitespace around items is ignored.
// It rejects empty specs, non-numeric items, ports outside 1-65535, and ranges
// whose start exceeds their end.
func ParsePortSpec(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("parse ports: empty spec")
	}

	set := make(map[int]struct{})
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(item, "-"); ok {
			start, err := parsePort(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("parse ports: %w", err)
			}
			end, err := parsePort(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("parse ports: %w", err)
			}
			if start > end {
				return nil, fmt.Errorf("parse ports: range %d-%d is descending", start, end)
			}
			for p := start; p <= end; p++ {
				set[p] = struct{}{}
			}
			continue
		}
		p, err := parsePort(item)
		if err != nil {
			return nil, fmt.Errorf("parse ports: %w", err)
		}
		set[p] = struct{}{}
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("parse ports: no ports in spec")
	}

	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// parsePort parses a single decimal port and validates the 1-65535 range.
func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return n, nil
}
