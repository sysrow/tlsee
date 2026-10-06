package tlsscan

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestCheckSANsPreCanceledSkipsEveryName(t *testing.T) {
	original := lookupIP
	lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		t.Error("canceled check attempted DNS resolution")
		return nil, nil
	}
	t.Cleanup(func() { lookupIP = original })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	names := []string{"first.invalid", "*.second.invalid", "third.invalid"}
	checks, notProbed := checkSANs(ctx, names, "443", time.Second, sanContext{})
	if len(checks) != 0 || notProbed != len(names) {
		t.Fatalf("checkSANs = (%+v, %d); want no checks and %d not probed", checks, notProbed, len(names))
	}
}

func TestCheckSANsCancellationPreservesCompletedChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, sanProbeConcurrency)
	original := lookupIP
	lookupIP = func(ctx context.Context, _, name string) ([]net.IP, error) {
		if name == "missing.invalid" {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		select {
		case started <- struct{}{}:
		case <-ctx.Done():
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { lookupIP = original })
	names := []string{"pending.invalid", "*.first.invalid", "missing.invalid", "*.second.invalid"}
	for len(names) < maxSANChecks+5 {
		names = append(names, fmt.Sprintf("pending%d.invalid", len(names)))
	}
	done := make(chan struct{})
	var checks []SANCheck
	var notProbed int
	go func() {
		checks, notProbed = checkSANs(ctx, names, "443", 5*time.Second, sanContext{})
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for range sanProbeConcurrency {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("SAN workers did not fill the pool")
		}
	}
	cancel()
	<-done
	want := []SANCheck{
		{Name: names[1], Wildcard: true},
		{Name: names[2]},
		{Name: names[3], Wildcard: true},
	}
	if !reflect.DeepEqual(checks, want) || notProbed != len(names)-len(want) {
		t.Fatalf("checkSANs = (%+v, %d); want (%+v, %d)", checks, notProbed, want, len(names)-len(want))
	}
	if dead, elsewhere := countSANFindings(checks); dead != 1 || elsewhere != 0 {
		t.Errorf("findings = (%d, %d); want only the completed DNS failure", dead, elsewhere)
	}
}

func TestCheckSANsCancellationAfterLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := lookupIP
	lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		cancel()
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupIP = original })
	checks, notProbed := checkSANs(ctx, []string{"pending.invalid"}, "443", time.Second, sanContext{})
	if len(checks) != 0 || notProbed != 1 {
		t.Fatalf("checkSANs = (%+v, %d); want no checks and one not probed", checks, notProbed)
	}
}

func TestCheckSANsLookupTimeoutIsDead(t *testing.T) {
	original := lookupIP
	lookupIP = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { lookupIP = original })
	checks, notProbed := checkSANs(context.Background(), []string{"timeout.invalid"}, "443", time.Millisecond, sanContext{})
	if len(checks) != 1 || notProbed != 0 {
		t.Fatalf("checkSANs = (%+v, %d); want one completed check", checks, notProbed)
	}
	if dead, elsewhere := countSANFindings(checks); dead != 1 || elsewhere != 0 {
		t.Errorf("findings = (%d, %d); want one dead SAN", dead, elsewhere)
	}
}

func TestCheckSANsOwnershipInterruption(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		t.Run(fmt.Sprintf("canceled=%t", canceled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			confirming := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			go func() {
				for i := 0; i < 2; i++ {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					if i == 1 {
						close(confirming)
						<-release
					}
					conn.Close()
				}
			}()
			original := lookupIP
			lookupIP = func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			t.Cleanup(func() { lookupIP = original })
			timeout := 50 * time.Millisecond
			if canceled {
				timeout = 5 * time.Second
			}
			sctx := sanContext{hostAddrs: hostAddrSet("", []string{"192.0.2.1"}), fingerprint: "original"}
			done := make(chan struct{})
			var checks []SANCheck
			var notProbed int
			go func() {
				checks, notProbed = checkSANs(ctx, []string{"elsewhere.invalid"}, port, timeout, sctx)
				close(done)
			}()
			defer func() {
				cancel()
				<-done
			}()
			select {
			case <-confirming:
			case <-time.After(5 * time.Second):
				t.Fatal("ownership confirmation did not start")
			}
			if canceled {
				cancel()
			}
			<-done
			if canceled {
				if len(checks) != 0 || notProbed != 1 {
					t.Fatalf("checkSANs = (%+v, %d); want no checks and one not probed", checks, notProbed)
				}
			} else if len(checks) != 1 || notProbed != 0 || checks[0].Ownership != OwnershipUnverified {
				t.Fatalf("checkSANs = (%+v, %d); want a completed unverified ownership check", checks, notProbed)
			}
		})
	}
}
