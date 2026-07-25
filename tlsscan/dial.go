package tlsscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// maxReplyBytes caps the total plaintext bytes read during a STARTTLS
// negotiation. Protocol greetings and replies are tiny, so this bound only ever
// trips a misbehaving or malicious server that withholds a line terminator.
const maxReplyBytes = 64 << 10 // 64 KiB

// dialPlaintext opens a plain TCP connection to addr, bounded by timeout. The
// connect error is wrapped here so the wrap is shared by every caller (Scan,
// per-IP probing, and the sweep engine) and matches the message tests assert.
func dialPlaintext(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	return conn, nil
}

// tlsHandshake wraps an already-connected plaintext conn in a TLS client and
// performs the handshake, bounded by timeout. Verification is intentionally
// skipped so any certificate can be retrieved. The SNI is passed separately
// from the dial address so a caller may connect to an IP while presenting the
// host name (used by per-IP probing). Any deadline left on conn by an earlier
// STARTTLS exchange is cleared before the handshake.
func tlsHandshake(ctx context.Context, conn net.Conn, sni string, timeout time.Duration) (*tls.Conn, error) {
	// Clear any stale deadline from a prior plaintext exchange so the handshake
	// runs under its own bound.
	_ = conn.SetDeadline(time.Time{})

	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		// Permit legacy TLS versions and cipher suites so the inspector can
		// both retrieve certificates from old servers and observe (and warn
		// about) weak negotiation. Without this, Go's client defaults (minimum
		// TLS 1.2, secure suites only) make the weak-TLS-version and weak-cipher
		// hygiene warnings unreachable: the handshake would never negotiate the
		// weak parameters the warnings look for.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: weakFriendlyCipherSuites,
	})
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// weakFriendlyCipherSuites lists every cipher suite Go supports, secure and
// insecure, so the handshake can negotiate (and the inspector can therefore
// observe and warn about) weak ciphers offered by legacy servers. The list only
// affects TLS 1.2 and below; TLS 1.3 cipher suites are not configurable.
var weakFriendlyCipherSuites = allCipherSuiteIDs()

func allCipherSuiteIDs() []uint16 {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	ids := make([]uint16, 0, len(suites))
	for _, s := range suites {
		ids = append(ids, s.ID)
	}
	return ids
}

// startTLSNegotiate performs the plaintext-to-TLS upgrade handshake for proto on
// conn before the TLS handshake. It uses connection deadlines (derived from
// timeout) for every read and write so a silent server cannot stall a scan. It
// returns a clear error when the server does not offer STARTTLS for proto.
func startTLSNegotiate(ctx context.Context, conn net.Conn, proto string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	// Bound the plaintext reply stream so a malicious server cannot accumulate a
	// huge newline-less line in the bufio buffer. Protocol greetings and replies
	// are tiny, so a generous cap is safe and a server exceeding it fails fast
	// (the LimitReader returns EOF, which surfaces as a read error).
	br := bufio.NewReader(io.LimitReader(conn, maxReplyBytes))

	var negErr error
	switch strings.ToLower(proto) {
	case "smtp":
		negErr = startTLSSMTP(conn, br)
	case "imap":
		negErr = startTLSIMAP(conn, br)
	case "pop3":
		negErr = startTLSPOP3(conn, br)
	case "ftp":
		negErr = startTLSFTP(conn, br)
	case "postgres":
		// Binary protocols read the conn directly and never buffer through br,
		// so the leftover-data assertion below does not apply to them.
		return startTLSPostgres(conn)
	case "ldap":
		return startTLSLDAP(conn)
	default:
		return fmt.Errorf("unknown starttls protocol %q", proto)
	}
	if negErr != nil {
		return negErr
	}

	// Plaintext-injection hardening: after a successful line-based negotiation,
	// the bufio reader must hold no leftover bytes. Buffered data here means the
	// server sent application data before the TLS handshake (a known STARTTLS
	// injection vector). Reject it rather than silently discarding it. The TLS
	// handshake reads the raw conn, so br is intentionally not threaded forward.
	if br.Buffered() != 0 {
		return fmt.Errorf("server sent unexpected data before TLS")
	}
	return nil
}

// readReplyLine reads one CRLF-terminated line and returns it without the
// trailing CR/LF.
func readReplyLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readNumericReply reads a possibly multiline SMTP/FTP reply. Continuation
// lines have a hyphen as the fourth byte ("250-..."); the final line has a
// space ("250 ..."). It returns the three-digit status code of the final line.
func readNumericReply(br *bufio.Reader) (string, error) {
	for {
		line, err := readReplyLine(br)
		if err != nil {
			return "", err
		}
		if len(line) < 4 {
			// A short line cannot be a continuation; treat it as final.
			return strings.TrimSpace(line), nil
		}
		if line[3] == '-' {
			continue // continuation line
		}
		return line[:3], nil
	}
}

// startTLSSMTP negotiates STARTTLS on an SMTP connection (ports 25 and 587).
func startTLSSMTP(conn net.Conn, br *bufio.Reader) error {
	if code, err := readNumericReply(br); err != nil {
		return fmt.Errorf("read smtp greeting: %w", err)
	} else if code != "220" {
		return fmt.Errorf("smtp greeting not ready: %s", code)
	}
	if _, err := io.WriteString(conn, "EHLO tlsee\r\n"); err != nil {
		return fmt.Errorf("send EHLO: %w", err)
	}
	if code, err := readNumericReply(br); err != nil {
		return fmt.Errorf("read EHLO reply: %w", err)
	} else if code != "250" {
		return fmt.Errorf("EHLO rejected: %s", code)
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("send STARTTLS: %w", err)
	}
	if code, err := readNumericReply(br); err != nil {
		return fmt.Errorf("read STARTTLS reply: %w", err)
	} else if code != "220" {
		return fmt.Errorf("server does not offer STARTTLS: %s", code)
	}
	return nil
}

// startTLSIMAP negotiates STARTTLS on an IMAP connection.
func startTLSIMAP(conn net.Conn, br *bufio.Reader) error {
	greeting, err := readReplyLine(br)
	if err != nil {
		return fmt.Errorf("read imap greeting: %w", err)
	}
	// A usable greeting is "* OK" (connection ready) or "* PREAUTH" (already
	// authenticated, e.g. by a local transport). "* BYE" and anything else mean
	// the server is rejecting the session, so do not proceed.
	if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* PREAUTH") {
		return fmt.Errorf("imap greeting not OK: %q", greeting)
	}
	if _, err := io.WriteString(conn, "a1 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("send STARTTLS: %w", err)
	}
	// Skip any untagged responses until the tagged a1 reply.
	for {
		line, err := readReplyLine(br)
		if err != nil {
			return fmt.Errorf("read STARTTLS reply: %w", err)
		}
		if strings.HasPrefix(line, "a1 ") {
			if !strings.HasPrefix(line, "a1 OK") {
				return fmt.Errorf("server does not offer STARTTLS: %q", line)
			}
			return nil
		}
	}
}

// startTLSPOP3 negotiates STLS on a POP3 connection.
func startTLSPOP3(conn net.Conn, br *bufio.Reader) error {
	greeting, err := readReplyLine(br)
	if err != nil {
		return fmt.Errorf("read pop3 greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("pop3 greeting not OK: %q", greeting)
	}
	if _, err := io.WriteString(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("send STLS: %w", err)
	}
	reply, err := readReplyLine(br)
	if err != nil {
		return fmt.Errorf("read STLS reply: %w", err)
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fmt.Errorf("server does not offer STLS: %q", reply)
	}
	return nil
}

// startTLSFTP negotiates AUTH TLS on an FTP connection.
func startTLSFTP(conn net.Conn, br *bufio.Reader) error {
	if code, err := readNumericReply(br); err != nil {
		return fmt.Errorf("read ftp greeting: %w", err)
	} else if code != "220" {
		return fmt.Errorf("ftp greeting not ready: %s", code)
	}
	if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("send AUTH TLS: %w", err)
	}
	if code, err := readNumericReply(br); err != nil {
		return fmt.Errorf("read AUTH TLS reply: %w", err)
	} else if code != "234" {
		return fmt.Errorf("server does not offer AUTH TLS: %s", code)
	}
	return nil
}

// startTLSPostgres sends the PostgreSQL SSLRequest message and requires the
// single-byte 'S' response indicating TLS is supported. The request is a 4-byte
// big-endian length (8) followed by the 4-byte SSL request code 80877103.
func startTLSPostgres(conn net.Conn) error {
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	if _, err := conn.Write(req[:]); err != nil {
		return fmt.Errorf("send postgres SSLRequest: %w", err)
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("read postgres SSLRequest reply: %w", err)
	}
	if resp[0] != 'S' {
		return fmt.Errorf("server does not support TLS (replied %q)", resp[0])
	}
	return nil
}

// ldapStartTLSRequest is the fixed BER encoding of an LDAP StartTLS extended
// request (message id 1, OID 1.3.6.1.4.1.1466.20037):
//
//	30 1d            SEQUENCE, length 29 (LDAPMessage)
//	  02 01 01       INTEGER 1 (messageID)
//	  77 18          [APPLICATION 23] length 24 (extendedReq)
//	    80 16        [CONTEXT 0] length 22 (requestName)
//	      "1.3.6.1.4.1.1466.20037"
var ldapStartTLSRequest = []byte{
	0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16,
	'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
	'1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
}

// startTLSLDAP sends the LDAP StartTLS extended request and consumes the
// server's complete extendedResponse PDU. The response is parsed best-effort:
// only the outer SEQUENCE header is decoded, and a well-formed PDU is treated
// as success, letting the TLS handshake surface a clear error if the server
// actually refused. Consuming the whole PDU matters: any unread response bytes
// would be read by the TLS client afterwards and corrupt the handshake.
func startTLSLDAP(conn net.Conn) error {
	if _, err := conn.Write(ldapStartTLSRequest); err != nil {
		return fmt.Errorf("send ldap StartTLS: %w", err)
	}
	n, err := readBERHeader(conn)
	if err != nil {
		return fmt.Errorf("read ldap StartTLS reply: %w", err)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
		return fmt.Errorf("read ldap StartTLS reply: %w", err)
	}
	return nil
}

// readBERHeader reads a BER SEQUENCE tag and definite-form length from conn
// and returns the content length that follows. Indefinite lengths are rejected
// (LDAP requires the definite form), as is any length above maxReplyBytes, so
// a malicious server cannot make the negotiator read an arbitrarily large
// reply.
func readBERHeader(conn net.Conn) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x30 {
		return 0, fmt.Errorf("not an LDAP message (tag 0x%02x)", hdr[0])
	}
	if hdr[1] < 0x80 {
		return int(hdr[1]), nil
	}
	numBytes := int(hdr[1] & 0x7f)
	if numBytes == 0 {
		return 0, fmt.Errorf("indefinite BER length not allowed")
	}
	if numBytes > 4 {
		return 0, fmt.Errorf("BER length of %d bytes too large", numBytes)
	}
	buf := make([]byte, numBytes)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	var n uint64
	for _, b := range buf {
		n = n<<8 | uint64(b)
	}
	if n > maxReplyBytes {
		return 0, fmt.Errorf("BER length %d exceeds %d-byte limit", n, maxReplyBytes)
	}
	return int(n), nil
}
