package tlsscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// observedConn signals when negotiation starts its first blocking operation.
type observedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func (c *observedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestStartTLSCancellationInterruptsIO(t *testing.T) {
	for _, proto := range []string{"smtp", "imap", "pop3", "ftp", "postgres", "ldap"} {
		t.Run(proto, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			conn := &observedConn{Conn: client, started: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- startTLSNegotiate(ctx, conn, proto, 10*time.Second)
			}()
			<-conn.started
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("negotiation error = %v; want context.Canceled", err)
				}
			case <-time.After(time.Second):
				client.Close()
				<-done
				t.Fatal("negotiation did not stop promptly after cancellation")
			}
		})
	}
}

func TestStartTLSAlreadyCanceled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := startTLSNegotiate(ctx, client, "smtp", time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("negotiation error = %v; want context.Canceled", err)
	}
}
