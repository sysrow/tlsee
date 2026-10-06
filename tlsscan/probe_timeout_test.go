package tlsscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeIPCertSharesTimeoutAcrossSTARTTLSAndHandshake(t *testing.T) {
	cert := testTLSCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	const timeout = 2 * time.Second
	const phaseDelay = 3 * timeout / 5
	handshakeStarted := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(4 * timeout)); err != nil {
			serverDone <- err
			return
		}
		var request [8]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			serverDone <- fmt.Errorf("read SSLRequest: %w", err)
			return
		}
		// Each phase individually fits the configured timeout. Together they
		// exceed it, so refreshing the TLS phase's budget incorrectly succeeds.
		time.Sleep(phaseDelay)
		if _, err := conn.Write([]byte{'S'}); err != nil {
			serverDone <- fmt.Errorf("write SSLRequest reply: %w", err)
			return
		}
		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				close(handshakeStarted)
				time.Sleep(phaseDelay)
				return nil, nil
			},
		})
		// A handshake error is expected after the client's aggregate timeout.
		_ = server.Handshake()
		serverDone <- nil
	}()

	result := probeIPCert(context.Background(), "127.0.0.1", port, "localhost", "postgres", timeout)
	if err := <-serverDone; err != nil {
		t.Fatalf("local STARTTLS server: %v", err)
	}
	select {
	case <-handshakeStarted:
	default:
		t.Fatal("probe timed out before reaching the TLS handshake")
	}
	if result.Error == "" || !strings.Contains(result.Error, "deadline exceeded") {
		t.Fatalf("probe error = %q; want aggregate timeout", result.Error)
	}
	if result.FingerprintSHA256 != "" {
		t.Fatalf("fingerprint = %q; want no certificate after timeout", result.FingerprintSHA256)
	}
}
