package tlsscan

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestHostIdentityMatchesIPCertificatesWithZones(t *testing.T) {
	certificate := &x509.Certificate{
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("fe80::1"), net.ParseIP("127.0.0.1")},
	}
	for _, tc := range []struct {
		host      string
		wantIP    bool
		wantMatch bool
	}{
		{host: "fe80::1%eth0", wantIP: true, wantMatch: true},
		{host: "fe80:0:0:0:0:0:0:1%2", wantIP: true, wantMatch: true},
		{host: "fe80::1", wantIP: true, wantMatch: true},
		{host: "fe80::2%eth0", wantIP: true},
		{host: "127.0.0.1", wantIP: true, wantMatch: true},
		{host: "example.com", wantMatch: true},
		{host: "other.example"},
		{host: "example.com%eth0"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			identity, isIP := hostIdentity(tc.host)
			if isIP != tc.wantIP {
				t.Errorf("hostIdentity(%q) IP = %v; want %v", tc.host, isIP, tc.wantIP)
			}
			if matches := certificate.VerifyHostname(identity) == nil; matches != tc.wantMatch {
				t.Errorf("certificate match for %q (identity %q) = %v; want %v", tc.host, identity, matches, tc.wantMatch)
			}
		})
	}
}
