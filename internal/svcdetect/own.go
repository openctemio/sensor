package svcdetect

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Our own credential-free probes, for protocols whose nerva plugin is
// excluded (ssh, ldap, postgresql) or sends HTTP (http):
//   - ssh: reads the server's identification line, sends ours, reads the
//     server's KEXINIT and closes. No key exchange is completed, no service
//     or user authentication is requested.
//   - http/https: one "GET / HTTP/1.1" with Host and the job's
//     identification; only the status line is read. The protocol is all it
//     reports (product details are the HTTP probe tool's).
//   - ldap/ldaps: one base-scope search of the root DSE (objectClass
//     present), without a bind: the anonymous root DSE read every LDAPv3
//     server answers before authentication.
//   - postgresql: the 8-byte SSLRequest; the server answers S or N. No
//     startup message (that names a user and is a login).

// ownIdent is the SSH identification the tool sends (RFC 4253 §4.2).
const ownIdent = "SSH-2.0-OpenCTEM_svcdetect_1.0\r\n"

// Priorities of the own probes among the plugins (lower runs earlier).
const (
	priorityHTTP = 1
	prioritySSH  = 2
	priorityLDAP = 300
	priorityPG   = 400
)

func ownProbes(identity *tool.Identity, version string) []*probe {
	ua := "openctem-svcdetect/" + version
	var headers []string
	if identity != nil {
		headers = identity.HeaderLines()
		if identity.UserAgent != "" {
			ua = ""
		}
	}
	httpRun := func(useTLS bool) func(net.Conn, time.Duration, *target) (*result, error) {
		return func(c net.Conn, timeout time.Duration, t *target) (*result, error) {
			return probeHTTP(c, timeout, t, ua, headers, useTLS)
		}
	}
	return []*probe{
		{name: "ssh", talksFirst: true, priority: prioritySSH, portHint: portIn(22, 2222), run: probeSSH},
		{name: "http", priority: priorityHTTP, portHint: portIn(80, 591, 8000, 8008, 8080, 8081, 8088, 8888), run: httpRun(false), fallback: true},
		{name: "https", tls: true, priority: priorityHTTP, portHint: portIn(443, 4443, 8443, 9443), run: httpRun(true), fallback: true},
		{name: "ldap", priority: priorityLDAP, portHint: portIn(389, 3268), run: probeLDAP("ldap")},
		{name: "ldaps", tls: true, priority: priorityLDAP, portHint: portIn(636, 3269), run: probeLDAP("ldaps")},
		{name: "postgresql", priority: priorityPG, portHint: portIn(5432, 5433), run: probePostgres, hintOnly: true},
	}
}

func portIn(ports ...uint16) func(uint16) bool {
	return func(p uint16) bool {
		for _, q := range ports {
			if p == q {
				return true
			}
		}
		return false
	}
}

// probeSSH: identification line and KEXINIT.
func probeSSH(c net.Conn, timeout time.Duration, _ *target) (*result, error) {
	br := bufio.NewReaderSize(c, 4096)
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	// RFC 4253 §4.2: the server may send other lines before its
	// identification; at most a few, each at most 255 bytes.
	var ident string
	for range 8 {
		line, err := readLimitedLine(br, 255)
		if err != nil {
			return nil, nil
		}
		if strings.HasPrefix(line, "SSH-") {
			ident = line
			break
		}
	}
	if !strings.HasPrefix(ident, "SSH-2.0-") && !strings.HasPrefix(ident, "SSH-1.99-") {
		if strings.HasPrefix(ident, "SSH-") {
			return &result{protocol: "ssh", banner: cleanText(ident, MaxBanner)}, nil
		}
		return nil, nil
	}
	r := &result{protocol: "ssh", banner: cleanText(ident, MaxBanner)}
	r.product, r.version = sshSoftware(ident)
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(c, ownIdent); err != nil {
		return r, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	if kex, err := readKexInit(br); err == nil {
		r.details = kex
	}
	return r, nil
}

// readLimitedLine reads one line of at most limit bytes (CR LF or LF
// ended), without the line end.
func readLimitedLine(br *bufio.Reader, limit int) (string, error) {
	var b []byte
	for {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		if len(b) >= limit {
			return "", errors.New("line too long")
		}
		b = append(b, c)
	}
}

// sshSoftware reads product and version from an identification
// ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" is OpenSSH 9.6p1).
func sshSoftware(ident string) (product, version string) {
	rest := ident[strings.Index(ident[4:], "-")+5:]
	sw, _, _ := strings.Cut(rest, " ")
	product, version, _ = strings.Cut(sw, "_")
	return cleanText(product, maxProduct), cleanText(version, maxVersion)
}

// readKexInit reads the server's unencrypted SSH_MSG_KEXINIT and returns
// its algorithm lists as details.
func readKexInit(br *bufio.Reader) (map[string]string, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	pad := int(hdr[4])
	if n < 1+16+4 || n > 35000 || pad >= int(n) {
		return nil, errors.New("not a KEXINIT packet")
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	payload := body[:len(body)-pad]
	if len(payload) < 17 || payload[0] != 20 {
		return nil, errors.New("not a KEXINIT packet")
	}
	p := payload[17:]
	names := []string{"kex_algorithms", "host_key_algorithms", "ciphers_client_to_server", "ciphers_server_to_client",
		"macs_client_to_server", "macs_server_to_client", "compression_client_to_server", "compression_server_to_client"}
	out := map[string]string{}
	for _, name := range names {
		if len(p) < 4 {
			return nil, errors.New("truncated KEXINIT")
		}
		l := binary.BigEndian.Uint32(p[:4])
		if uint64(l) > uint64(len(p)-4) {
			return nil, errors.New("truncated KEXINIT")
		}
		v := string(p[4 : 4+l])
		p = p[4+l:]
		switch name {
		case "ciphers_client_to_server", "macs_client_to_server", "compression_client_to_server":
			continue // the server-to-client lists say the same of the server
		}
		if s := cleanText(v, MaxDetailValue); s != "" {
			out[name] = s
		}
	}
	return out, nil
}

// probeHTTP sends one GET / and reads the status line.
func probeHTTP(c net.Conn, timeout time.Duration, t *target, ua string, headers []string, useTLS bool) (*result, error) {
	var req strings.Builder
	req.WriteString("GET / HTTP/1.1\r\nHost: ")
	req.WriteString(t.hostHeader(useTLS))
	req.WriteString("\r\n")
	if ua != "" {
		req.WriteString("User-Agent: " + ua + "\r\n")
	}
	for _, h := range headers {
		// The identification is validated by the tool host (printable
		// ASCII, no CR or LF); checked again here.
		if strings.ContainsAny(h, "\r\n") {
			continue
		}
		req.WriteString(h + "\r\n")
	}
	req.WriteString("Accept: */*\r\nConnection: close\r\n\r\n")
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(c, req.String()); err != nil {
		return nil, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	line, err := readLimitedLine(bufio.NewReaderSize(c, 1024), 512)
	if err != nil {
		return nil, nil
	}
	if !httpStatusLine(line) {
		return nil, nil
	}
	name := "http"
	if useTLS {
		name = "https"
	}
	return &result{protocol: name, banner: cleanText(line, MaxBanner)}, nil
}

// httpStatusLine reports an HTTP/1.x status line ("HTTP/1.1 200 OK").
func httpStatusLine(line string) bool {
	if !strings.HasPrefix(line, "HTTP/1.0 ") && !strings.HasPrefix(line, "HTTP/1.1 ") {
		return false
	}
	code := line[9:]
	if len(code) < 3 {
		return false
	}
	n, err := strconv.Atoi(code[:3])
	return err == nil && n >= 100 && n <= 599 && (len(code) == 3 || code[3] == ' ')
}

// ldapRootDSE is a base-scope search of the root DSE ("") for
// (objectClass=*), no attributes requested, message id 1.
var ldapRootDSE = []byte{0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
	0x30, 0x00}

func probeLDAP(name string) func(net.Conn, time.Duration, *target) (*result, error) {
	return func(c net.Conn, timeout time.Duration, _ *target) (*result, error) {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := c.Write(ldapRootDSE); err != nil {
			return nil, nil
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 64)
		n, _ := io.ReadAtLeast(c, buf, 8)
		if !ldapAnswer(buf[:n]) {
			return nil, nil
		}
		return &result{protocol: name}, nil
	}
}

// ldapAnswer reports an LDAPMessage with message id 1 whose operation is a
// search result entry, done or reference ([APPLICATION 4], 5 or 19).
func ldapAnswer(b []byte) bool {
	if len(b) < 2 || b[0] != 0x30 {
		return false
	}
	i := 2
	if b[1]&0x80 != 0 {
		l := int(b[1] & 0x7f)
		if l < 1 || l > 4 {
			return false
		}
		i += l
	}
	if len(b) < i+4 || b[i] != 0x02 || b[i+1] != 0x01 || b[i+2] != 0x01 {
		return false
	}
	switch b[i+3] {
	case 0x64, 0x65, 0x73:
		return true
	}
	return false
}

// pgSSLRequest is the PostgreSQL SSLRequest message.
var pgSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

func probePostgres(c net.Conn, timeout time.Duration, _ *target) (*result, error) {
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write(pgSSLRequest); err != nil {
		return nil, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 16)
	n, _ := c.Read(buf)
	if n != 1 || (buf[0] != 'S' && buf[0] != 'N') {
		return nil, nil
	}
	// One byte and nothing else: wait briefly for trailing bytes, which a
	// PostgreSQL server never sends here.
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if m, _ := c.Read(buf[1:]); m > 0 {
		return nil, nil
	}
	tlsOffered := "false"
	if buf[0] == 'S' {
		tlsOffered = "true"
	}
	return &result{protocol: "postgresql", details: map[string]string{"tls_offered": tlsOffered}}, nil
}

// bannerHints orders the talk-first probes by what the server sent first.
func bannerHints(first []byte) []string {
	switch {
	case bytes.HasPrefix(first, []byte("SSH-")):
		return []string{"ssh"}
	case bytes.HasPrefix(first, []byte("220")):
		if bytes.Contains(bytes.ToUpper(first), []byte("SMTP")) {
			return []string{"smtp", "ftp"}
		}
		return []string{"ftp", "smtp"}
	case bytes.HasPrefix(first, []byte("+OK")):
		return []string{"pop3"}
	case bytes.HasPrefix(first, []byte("* OK")), bytes.HasPrefix(first, []byte("* PREAUTH")), bytes.HasPrefix(first, []byte("* BYE")):
		return []string{"imap"}
	case bytes.HasPrefix(first, []byte("RFB ")):
		return []string{"vnc"}
	case bytes.HasPrefix(first, []byte("@RSYNCD:")):
		return []string{"rsync"}
	case len(first) > 0 && first[0] == 0xff:
		return []string{"telnet"}
	case len(first) > 4 && (first[4] == 10 || first[4] == 0xff):
		return []string{"mysql"}
	}
	return nil
}
