package tlsscan

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestScanReleasesConnectionBeforeEnrichment(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cert := testTLSCert(t)
	closed := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := server.Handshake(); err != nil {
			closed <- err
			return
		}
		var data [1]byte
		_, err = server.Read(data[:])
		closed <- err
	}()
	defer func() {
		listener.Close()
		<-serverDone
	}()

	original := lookupIP
	lookupIP = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		select {
		case err := <-closed:
			if err != io.EOF {
				t.Errorf("primary connection did not close cleanly: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("primary connection remains open during SAN enrichment")
		case <-ctx.Done():
			t.Errorf("SAN enrichment canceled before observing close: %v", ctx.Err())
		}
		return nil, nil
	}
	t.Cleanup(func() { lookupIP = original })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Scan(ctx, listener.Addr().String(), Options{CheckSANs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SANChecks) == 0 {
		t.Fatal("SAN enrichment did not run")
	}
}
