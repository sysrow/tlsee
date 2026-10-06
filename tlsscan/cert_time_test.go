package tlsscan

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestCertInfoWholeDaysRemaining(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 500_000_000, time.UTC)
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    int
	}{
		{name: "equal", expires: now, want: 0},
		{name: "less than future day", expires: now.Add(24*time.Hour - time.Nanosecond), want: 0},
		{name: "exact future day", expires: now.Add(24 * time.Hour), want: 1},
		{name: "more than future day", expires: now.Add(24*time.Hour + time.Nanosecond), want: 1},
		{name: "less than expired day", expires: now.Add(-24*time.Hour + time.Nanosecond), want: 0},
		{name: "exact expired day", expires: now.Add(-24 * time.Hour), want: -1},
		{name: "more than expired day", expires: now.Add(-24*time.Hour - time.Nanosecond), want: -1},
		{name: "future beyond duration range", expires: time.Date(2400, 1, 1, 12, 0, 0, 500_000_000, time.UTC), want: 136600},
		{name: "maximum certificate year", expires: time.Date(9999, 1, 1, 12, 0, 0, 500_000_000, time.UTC), want: 2912078},
		{name: "past beyond duration range", expires: time.Date(1600, 1, 1, 12, 0, 0, 500_000_000, time.UTC), want: -155594},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificate := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     tc.expires,
			}
			info := certInfo(certificate, now)
			if info.DaysRemaining != tc.want {
				t.Errorf("DaysRemaining = %d; want %d", info.DaysRemaining, tc.want)
			}
			if info.NotAfter != tc.expires || info.Expired != now.After(tc.expires) || info.NotYetValid {
				t.Errorf("validity metadata changed: %+v", info)
			}
		})
	}
}
