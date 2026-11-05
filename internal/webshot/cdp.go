package webshot

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// The DevTools protocol over the browser's pipe (--remote-debugging-pipe):
// the browser reads commands from its fd 3 and writes replies and events to
// its fd 4, each message one JSON object ended by a NUL byte. No port is
// opened, so nothing else in the task (a page included) can reach the
// protocol.

// maxMessage bounds one message from the browser. A screenshot reply is the
// largest (base64 of the PNG, capped by the clip and the viewport).
const maxMessage = 48 << 20

// errClosed: the browser closed its end of the pipe (it exited).
var errClosed = errors.New("webshot: the browser closed the protocol pipe")

// message is one protocol message in either direction.
type message struct {
	ID        int64           `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *protoError     `json:"error,omitempty"`
}

type protoError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *protoError) Error() string { return fmt.Sprintf("devtools error %d: %s", e.Code, e.Message) }

// event is a protocol event of one session ("" is the browser's).
type event struct {
	SessionID string
	Method    string
	Params    json.RawMessage
}

// conn is one protocol connection. Events go to the handler, which runs on
// the reader goroutine in order: it must not block on a reply (it may send
// a command with sendNoWait or start a goroutine).
type conn struct {
	w       io.Writer
	wmu     sync.Mutex
	next    atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan message
	err     error
	done    chan struct{}
	handler func(event)
}

func newConn(w io.Writer, r io.Reader, handler func(event)) *conn {
	c := &conn{w: w, pending: map[int64]chan message{}, done: make(chan struct{}), handler: handler}
	go c.read(r)
	return c
}

// splitNUL splits the stream at NUL bytes.
func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == 0 {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return 0, nil, nil
}

func (c *conn) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxMessage)
	sc.Split(splitNUL)
	for sc.Scan() {
		var m message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Method != "" && c.handler != nil {
			c.handler(event{SessionID: m.SessionID, Method: m.Method, Params: m.Params})
		}
	}
	err := sc.Err()
	if err == nil {
		err = errClosed
	}
	c.mu.Lock()
	c.err = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *conn) write(m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.w.Write(append(b, 0))
	return err
}

// send runs one command and decodes its result into out (nil: discarded).
func (c *conn) send(ctx context.Context, session, method string, params, out any) error {
	ch, err := c.start(session, method, params)
	if err != nil {
		return err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return c.closedErr()
		}
		if m.Error != nil {
			return fmt.Errorf("%s: %w", method, m.Error)
		}
		if out != nil && len(m.Result) > 0 {
			if err := json.Unmarshal(m.Result, out); err != nil {
				return fmt.Errorf("%s: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendNoWait sends a command and ignores its reply (for event handlers).
func (c *conn) sendNoWait(session, method string, params any) {
	_, _ = c.start(session, method, params)
}

func (c *conn) start(session, method string, params any) (chan message, error) {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	id := c.next.Add(1)
	ch := make(chan message, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.write(message{ID: id, SessionID: session, Method: method, Params: raw}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

func (c *conn) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return errClosed
}
