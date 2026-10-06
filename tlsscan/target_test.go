package tlsscan

import (
	"context"
	"strings"
	"testing"
)

func TestParseTargetURLAuthority(t *testing.T) {
	for _, tc := range []struct {
		name        string
		target      string
		defaultPort string
		wantHost    string
		wantPort    string
	}{
		{name: "URL fragment", target: "https://example.com#section", wantHost: "example.com", wantPort: "443"},
		{name: "bare fragment", target: "example.com#section", wantHost: "example.com", wantPort: "443"},
		{name: "URL port and fragment", target: "https://example.com:8443#section", wantHost: "example.com", wantPort: "8443"},
		{name: "bare port and fragment", target: "example.com:8443#section", wantHost: "example.com", wantPort: "8443"},
		{name: "URL username", target: "https://user@example.com", wantHost: "example.com", wantPort: "443"},
		{name: "URL credentials", target: "https://user:password@example.com:8443/path?q=1#section", wantHost: "example.com", wantPort: "8443"},
		{name: "escaped URL credentials", target: "https://user%40name:p%3Ass@example.com", wantHost: "example.com", wantPort: "443"},
		{name: "URL in bare path", target: "example.com/path/https://other.example", wantHost: "example.com", wantPort: "443"},
		{name: "URL in bare query", target: "example.com?next=https://other.example", wantHost: "example.com", wantPort: "443"},
		{name: "URL in bare fragment", target: "example.com#https://other.example", wantHost: "example.com", wantPort: "443"},
		{name: "URL in URL query", target: "https://example.com?next=https://other.example", wantHost: "example.com", wantPort: "443"},
		{name: "URL IPv6 fragment", target: "https://[::1]#section", wantHost: "::1", wantPort: "443"},
		{name: "bare IPv6 fragment", target: "[::1]:8443#section", wantHost: "::1", wantPort: "8443"},
		{name: "IPv6 URL zone", target: "https://[fe80::1%25eth0]:8443/path", wantHost: "fe80::1%eth0", wantPort: "8443"},
		{name: "IPv6 URL zone default port", target: "tls://[fe80::1%25eth0]", defaultPort: "8443", wantHost: "fe80::1%eth0", wantPort: "8443"},
		{name: "bare IPv6 zone", target: "fe80::1%eth0", wantHost: "fe80::1%eth0", wantPort: "443"},
		{name: "bracketed IPv6 zone", target: "[fe80::1%eth0]:8443", wantHost: "fe80::1%eth0", wantPort: "8443"},
		{name: "bracketed IPv6 zone with hash", target: "[fe80::1%eth#0]:8443#section", wantHost: "fe80::1%eth#0", wantPort: "8443"},
		{name: "override remains default", target: "https://example.com/path", defaultPort: "8443", wantHost: "example.com", wantPort: "8443"},
		{name: "explicit port beats default", target: "https://example.com:9443/path", defaultPort: "8443", wantHost: "example.com", wantPort: "9443"},
		{name: "empty explicit port uses default", target: "https://example.com:/path", defaultPort: "8443", wantHost: "example.com", wantPort: "8443"},
		{name: "scheme does not select service port", target: "http://example.com", wantHost: "example.com", wantPort: "443"},
		{name: "signed bare port preserved", target: "example.com:+443", wantHost: "example.com", wantPort: "+443"},
		{name: "leading zero port preserved", target: "https://example.com:00443", wantHost: "example.com", wantPort: "00443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseTarget(tc.target, tc.defaultPort)
			if err != nil || host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("parseTarget(%q, %q) = (%q, %q, %v); want (%q, %q)", tc.target, tc.defaultPort, host, port, err, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestScanRejectsMalformedURLBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, target := range []string{
		"https://user@", "https://[::1", "https://example.com:abc",
		"https://[not-an-ip]", "https://[fe80::1%eth0]", "https:///path",
		"https://example.com:65536", "https://example.com:0", "#section",
	} {
		t.Run(target, func(t *testing.T) {
			report, err := Scan(ctx, target, Options{})
			if report != nil || err == nil || !strings.HasPrefix(err.Error(), "parse target") {
				t.Fatalf("Scan = (%+v, %v); want parse error before canceled dial", report, err)
			}
		})
	}
}
