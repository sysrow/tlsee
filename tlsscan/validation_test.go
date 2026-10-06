package tlsscan

import (
	"context"
	"strings"
	"testing"
)

func TestParseTargetRejectsMissingHost(t *testing.T) {
	for _, target := range []string{
		":443", ":", "[]:443", "[]", "[ ]:443",
		"https://:443/path", "tls://[]:443?query", "https://[]/path",
	} {
		t.Run(target, func(t *testing.T) {
			host, port, err := parseTarget(target, "")
			if err == nil {
				t.Fatalf("parseTarget(%q) = (%q, %q, %v); want missing-host error", target, host, port, err)
			}
		})
	}
}

func TestScanValidatesHostBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := Scan(ctx, ":443", Options{})
	if report != nil || err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("Scan = (%+v, %v); want missing-host error before canceled dial", report, err)
	}
}

func TestSweepValidatesPortsBeforeProbing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, ports := range [][]int{
		{0}, {-1}, {65536}, {443, 0}, {1, 65535, -1},
	} {
		result, err := Sweep(ctx, "127.0.0.1", SweepOptions{Ports: ports})
		if result != nil || err == nil || !strings.Contains(err.Error(), "out of range (1-65535)") {
			t.Errorf("Sweep(ports=%v) = (%+v, %v); want port validation error", ports, result, err)
		}
	}
}

func TestSweepAcceptsValidPortsAndDefaults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name  string
		ports []int
		count int
	}{
		{name: "boundaries", ports: []int{1, 65535}, count: 2},
		{name: "duplicates preserved", ports: []int{443, 443}, count: 2},
		{name: "nil defaults", count: len(DefaultSweepPorts())},
		{name: "empty defaults", ports: []int{}, count: len(DefaultSweepPorts())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Sweep(ctx, "127.0.0.1", SweepOptions{Ports: tc.ports})
			if err != nil {
				t.Fatalf("Sweep = %v; want accepted ports", err)
			}
			if len(result.Ports) != 0 || result.PortsNotProbed != tc.count {
				t.Fatalf("Sweep = %+v; want %d unprobed ports", result, tc.count)
			}
		})
	}
}
