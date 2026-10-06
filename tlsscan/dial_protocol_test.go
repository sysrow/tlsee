package tlsscan

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStartTLSFTPMultilineBanner(t *testing.T) {
	addr, done := runScriptedServer(t, []scriptStep{
		{send: "220-Welcome to the FTP service\r\nPlease observe the usage policy.\r\n\r\n220 Service ready\r\n", expect: "AUTH TLS"},
		{send: "234-Starting TLS\r\nNegotiation follows this reply.\r\n234 Proceed\r\n"},
	})
	conn := dialScript(t, addr)
	err := startTLSNegotiate(context.Background(), conn, "ftp", 2*time.Second)
	conn.Close()
	<-done
	if err != nil {
		t.Fatalf("FTP multiline negotiation: %v", err)
	}
}

func TestStartTLSIMAPCaseInsensitiveStatus(t *testing.T) {
	for _, greeting := range []string{"* OK ready", "* ok ready", "* Ok ready", "* preauth ready"} {
		t.Run(greeting, func(t *testing.T) {
			addr, done := runScriptedServer(t, []scriptStep{
				{send: greeting + "\r\n", expect: "a1 STARTTLS"},
				{send: "* ok preparing TLS\r\na1 oK Proceed\r\n"},
			})
			conn := dialScript(t, addr)
			err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second)
			conn.Close()
			<-done
			if err != nil {
				t.Fatalf("IMAP mixed-case negotiation: %v", err)
			}
		})
	}
}

func TestStartTLSIMAPRejectsStatusPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []scriptStep
	}{
		{"greeting", []scriptStep{{send: "* OKAY ready\r\n"}}},
		{"tagged reply", []scriptStep{
			{send: "* OK ready\r\n", expect: "a1 STARTTLS"},
			{send: "a1 OKAY proceed\r\n"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, done := runScriptedServer(t, tc.steps)
			conn := dialScript(t, addr)
			err := startTLSNegotiate(context.Background(), conn, "imap", 2*time.Second)
			conn.Close()
			<-done
			if err == nil || !strings.Contains(err.Error(), "OKAY") {
				t.Fatalf("invalid IMAP status = %v; want status rejection", err)
			}
		})
	}
}

func TestStartTLSLDAPRefusal(t *testing.T) {
	// A protocolError is the ordinary response when StartTLS is unsupported.
	// The server keeps the LDAP session open, so the negotiator must report the
	// refusal itself instead of attempting a TLS handshake on that session.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		request := make([]byte, len(ldapStartTLSRequest))
		if _, err := io.ReadFull(server, request); err != nil {
			done <- err
			return
		}
		_, err := server.Write([]byte{
			0x30, 0x0c,
			0x02, 0x01, 0x01,
			0x78, 0x07,
			0x0a, 0x01, 0x02,
			0x04, 0x00,
			0x04, 0x00,
		})
		done <- err
	}()
	err := startTLSNegotiate(context.Background(), client, "ldap", 2*time.Second)
	client.Close()
	if serverErr := <-done; serverErr != nil {
		t.Fatalf("LDAP server: %v", serverErr)
	}
	if err == nil || !strings.Contains(err.Error(), "result code 2") {
		t.Fatalf("LDAP refusal = %v; want result code 2", err)
	}
}

func TestLDAPStartTLSResponseFields(t *testing.T) {
	// All lengths use BER long form, including nested fields. LDAP accepts
	// these encodings even though DER would require the shorter length form.
	longFields := []byte{
		0x02, 0x81, 0x01, 0x01,
		0x78, 0x81, 0x0a,
		0x0a, 0x81, 0x01, 0x00,
		0x04, 0x81, 0x00,
		0x04, 0x81, 0x00,
	}
	for _, tc := range []struct {
		name    string
		body    []byte
		wantErr string
	}{
		{
			name: "nested long-form lengths",
			body: longFields,
		},
		{
			name: "optional response name and controls",
			body: []byte{
				0x02, 0x01, 0x01,
				0x78, 0x23,
				0x0a, 0x01, 0x00,
				0x04, 0x00,
				0x04, 0x04, 'd', 'o', 'n', 'e',
				0x8a, 0x16,
				'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
				'1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
				0xa0, 0x00,
			},
		},
		{
			name: "unavailable result",
			body: []byte{
				0x02, 0x01, 0x01,
				0x78, 0x07,
				0x0a, 0x01, 0x34,
				0x04, 0x00,
				0x04, 0x00,
			},
			wantErr: "result code 52",
		},
		{
			name: "unsolicited response",
			body: []byte{
				0x02, 0x01, 0x00,
				0x78, 0x07,
				0x0a, 0x01, 0x00,
				0x04, 0x00,
				0x04, 0x00,
			},
			wantErr: "unexpected message ID",
		},
		{
			name: "different operation",
			body: []byte{
				0x02, 0x01, 0x01,
				0x61, 0x07, // BindResponse, not ExtendedResponse
				0x0a, 0x01, 0x00,
				0x04, 0x00,
				0x04, 0x00,
			},
			wantErr: "unexpected BER tag",
		},
		{
			name: "incomplete result",
			body: []byte{
				0x02, 0x01, 0x01,
				0x78, 0x05,
				0x0a, 0x01, 0x00,
				0x04, 0x00,
			},
			wantErr: "EOF",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLDAPStartTLSResponse(tc.body)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("response error = %v; want %q", err, tc.wantErr)
			}
		})
	}
}
