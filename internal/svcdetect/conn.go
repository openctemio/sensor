package svcdetect

import (
	"errors"
	"io"
	"net"
	"time"
)

// Per-connection bounds: a probe reads at most maxConnRead bytes and writes
// at most maxConnWrite (the largest probe, an HTTP GET with the job's
// identification, is well under 4 KiB).
const (
	maxConnRead  = 64 << 10
	maxConnWrite = 8 << 10
)

// errWriteBudget: a probe tried to write more than a credential-free
// greeting needs.
var errWriteBudget = errors.New("svcdetect: write budget of the connection exhausted")

// boundedConn is the only connection a probe sees. It replays the bytes the
// tool already read (the server's first bytes), keeps every deadline at or
// before the connection's hard deadline (a probe cannot extend its time by
// setting its own), and caps the bytes read and written.
type boundedConn struct {
	net.Conn
	prefix   []byte
	hard     time.Time
	read     int
	written  int
	maxRead  int
	maxWrite int
}

func bound(c net.Conn, hard time.Time, prefix []byte) *boundedConn {
	b := &boundedConn{Conn: c, prefix: prefix, hard: hard, maxRead: maxConnRead, maxWrite: maxConnWrite}
	_ = c.SetDeadline(hard)
	return b
}

func (b *boundedConn) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	if b.read >= b.maxRead {
		return 0, io.EOF
	}
	if len(p) > b.maxRead-b.read {
		p = p[:b.maxRead-b.read]
	}
	n, err := b.Conn.Read(p)
	b.read += n
	return n, err
}

func (b *boundedConn) Write(p []byte) (int, error) {
	if b.written+len(p) > b.maxWrite {
		return 0, errWriteBudget
	}
	n, err := b.Conn.Write(p)
	b.written += n
	return n, err
}

func (b *boundedConn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(b.hard) {
		return b.hard
	}
	return t
}

func (b *boundedConn) SetDeadline(t time.Time) error { return b.Conn.SetDeadline(b.clamp(t)) }

func (b *boundedConn) SetReadDeadline(t time.Time) error { return b.Conn.SetReadDeadline(b.clamp(t)) }

func (b *boundedConn) SetWriteDeadline(t time.Time) error {
	return b.Conn.SetWriteDeadline(b.clamp(t))
}

// preRead reads what the server sends first, waiting at most wait: one
// read, then whatever else arrives within a short grace (a multi-line
// greeting split over packets). The connection is left with no read
// deadline beyond its hard one.
func (b *boundedConn) preRead(wait time.Duration) []byte {
	buf := make([]byte, maxPreRead)
	_ = b.SetReadDeadline(time.Now().Add(wait))
	n, err := b.Read(buf)
	if n > 0 && err == nil && n < len(buf) {
		_ = b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		m, _ := b.Read(buf[n:])
		n += m
	}
	_ = b.SetReadDeadline(time.Time{})
	return buf[:n]
}
