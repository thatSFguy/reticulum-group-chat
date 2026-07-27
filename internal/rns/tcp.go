package rns

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCPClient is a Reticulum TCPClientInterface — a single TCP connection to a
// peer that exchanges HDLC-framed Reticulum packets in both directions.
// Inbound packets land on the channel returned by Inbox(); outbound packets
// are sent via Send(). The reader goroutine runs until Close() or the
// underlying connection drops.
// tcpWriteTimeout bounds a single Send's conn.Write. Without it, a peer
// that stops draining its socket (congested hub, half-dead NAT path)
// fills the kernel send buffer and Write blocks INDEFINITELY — and since
// the Transport dispatcher emits proofs/announces synchronously, one
// wedged peer freezes the whole service. 5s is generous for pushing a
// few KB to a live peer; a peer that can't manage that is effectively
// down and gets the reconnect treatment.
const tcpWriteTimeout = 5 * time.Second

// tcpFrameAssemblyTimeout bounds how long a single partial frame may sit
// incomplete before the connection is torn down. Applies only while a
// frame is mid-assembly (see readLoop) — an idle connection with no
// bytes in flight is never subject to it. Generous: one frame is at
// most a few hundred bytes, so any peer taking more than 30s to finish
// one is stalled or hostile.
const tcpFrameAssemblyTimeout = 30 * time.Second

type TCPClient struct {
	conn  net.Conn
	mu    sync.Mutex // guards Write
	inbox chan []byte
	done  chan struct{}
	// closing is closed by Close(). readLoop selects on it when handing
	// a frame to inbox: `done` cannot serve that role because it is
	// closed only by readLoop's own defer, so a reader blocked on a full
	// inbox could never observe it and Close() could not reclaim the
	// goroutine (closing the conn does not unblock a channel send).
	closing chan struct{}
	err     atomic.Value // last receive-side error, set once
	closed  atomic.Bool

	// writeTimeout defaults to tcpWriteTimeout; overridable in tests.
	writeTimeout time.Duration

	// frameTimeout bounds how long a PARTIAL frame may remain
	// incomplete. Defaults to tcpFrameAssemblyTimeout; see readLoop.
	frameTimeout time.Duration
}

// DialTCP opens a TCP connection to addr (e.g. "amsterdam.connect.reticulum.network:4965")
// and starts the inbound reader goroutine. timeout=0 means net.Dial defaults.
func DialTCP(addr string, timeout time.Duration) (*TCPClient, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return NewTCPClient(conn), nil
}

// NewTCPClient wraps an already-connected net.Conn (handy for tests via
// net.Pipe and for cases where the caller wants to set socket options
// before handing the connection over).
func NewTCPClient(conn net.Conn) *TCPClient {
	t := &TCPClient{
		conn:         conn,
		inbox:        make(chan []byte, 64),
		done:         make(chan struct{}),
		closing:      make(chan struct{}),
		writeTimeout: tcpWriteTimeout,
		frameTimeout: tcpFrameAssemblyTimeout,
	}
	go t.readLoop()
	return t
}

// Send writes a Reticulum packet to the wire (HDLC-framed). Safe to call
// from multiple goroutines. Each write carries a deadline
// (tcpWriteTimeout); on ANY write error the connection is closed, for
// two reasons: a timed-out or short write may have left a partial HDLC
// frame on the wire (the stream is corrupt from here on), and closing
// makes the read loop exit so ReconnectingTCPClient's supervisor
// notices and redials — a wedged-but-not-dropped peer would otherwise
// keep the broken connection alive indefinitely.
func (t *TCPClient) Send(packet []byte) error {
	if t.closed.Load() {
		return errors.New("tcp client closed")
	}
	framed := EncodeHDLC(packet)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeTimeout > 0 {
		if err := t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout)); err != nil {
			_ = t.Close()
			return fmt.Errorf("set write deadline: %w", err)
		}
	}
	if _, err := t.conn.Write(framed); err != nil {
		_ = t.Close()
		return fmt.Errorf("tcp write: %w", err)
	}
	return nil
}

// Inbox returns a receive-only channel of inbound Reticulum packet bytes.
// The channel is closed when the connection drops; check Err() for the cause.
func (t *TCPClient) Inbox() <-chan []byte { return t.inbox }

// Done returns a channel closed when the reader exits.
func (t *TCPClient) Done() <-chan struct{} { return t.done }

// Err returns the receive-side error that terminated the reader, if any.
// io.EOF on a clean close is normalized to nil.
func (t *TCPClient) Err() error {
	v := t.err.Load()
	if v == nil {
		return nil
	}
	if e, ok := v.(error); ok {
		return e
	}
	return nil
}

// Close shuts down the connection. Idempotent.
func (t *TCPClient) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	close(t.closing)
	return t.conn.Close()
}

func (t *TCPClient) readLoop() {
	defer close(t.inbox)
	defer close(t.done)
	dec := NewHDLCDecoder(t.conn)
	// Bound frame ASSEMBLY, not connection idleness: the deadline is
	// armed once a frame's first byte has arrived and cleared as soon
	// as the frame completes. A connection-wide read deadline would
	// tear down legitimately idle links (Reticulum peers are quiet for
	// minutes at a time); without any deadline, a peer that opens a
	// frame and then stalls mid-frame pins the buffer and this
	// goroutine indefinitely.
	dec.onFrameStart = func() error {
		return t.conn.SetReadDeadline(time.Now().Add(t.frameTimeout))
	}
	dec.onFrameEnd = func() {
		_ = t.conn.SetReadDeadline(time.Time{})
	}
	for {
		frame, err := dec.NextFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) && !t.closed.Load() {
				t.err.Store(err)
			}
			return
		}
		// Defensive: drop frames smaller than the minimum Reticulum header.
		if len(frame) < header1MinLen {
			continue
		}
		select {
		case t.inbox <- frame:
		case <-t.closing:
			return
		}
	}
}
