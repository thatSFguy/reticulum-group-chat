package rns

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeListener exposes a localhost TCP endpoint that captures every
// accepted connection. dropLast() closes the most recently accepted
// conn, simulating a peer-side drop — the same observable behavior a
// long-running fwdsvc sees when an upstream TCPServerInterface or NAT
// silently kills the socket (issue #6).
type fakeListener struct {
	ln       net.Listener
	accepts  chan net.Conn
	mu       sync.Mutex
	accepted []net.Conn
	closed   bool
}

func newFakeListener(t *testing.T) *fakeListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeListener{ln: ln, accepts: make(chan net.Conn, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.accepted = append(f.accepted, c)
			f.closed = false
			f.mu.Unlock()
			select {
			case f.accepts <- c:
			default:
			}
		}
	}()
	return f
}

func (f *fakeListener) addr() string { return f.ln.Addr().String() }

func (f *fakeListener) dropLast() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.accepted) == 0 {
		return
	}
	f.accepted[len(f.accepted)-1].Close()
}

func (f *fakeListener) close() {
	f.ln.Close()
	f.mu.Lock()
	for _, c := range f.accepted {
		c.Close()
	}
	f.mu.Unlock()
}

// TestReconnectingTCPClientSurvivesPeerDrop reproduces issue #6: a TCP
// connection dies and the service must transparently reconnect instead
// of silently sitting on a broken socket forever. The wrapper must:
//   - keep its outer Done() un-fired (Transport.Run's fan-in must not exit)
//   - re-establish the underlying TCP connection to the same address
//   - resume Send() succeeding on the new connection
func TestReconnectingTCPClientSurvivesPeerDrop(t *testing.T) {
	fl := newFakeListener(t)
	defer fl.close()

	logger := log.New(io.Discard, "", 0)
	rc, err := dialReconnectingTCPForTest(fl.addr(), 2*time.Second, logger, 20*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("dialReconnectingTCP: %v", err)
	}
	defer rc.Close()

	// First conn arrives at the listener.
	var first net.Conn
	select {
	case first = <-fl.accepts:
	case <-time.After(1 * time.Second):
		t.Fatal("listener never received first accept")
	}

	// Send a packet — peer reads it on the first conn.
	payload := bytes.Repeat([]byte{0xAB}, 20)
	if err := rc.Send(payload); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	if frame := readFrameWithTimeout(t, first, 500*time.Millisecond); !bytes.Equal(frame, payload) {
		t.Fatalf("first frame mismatch: got %x want %x", frame, payload)
	}

	// Simulate the peer-side TCP drop from issue #6.
	fl.dropLast()

	// Listener must see a fresh dial from the supervisor.
	var second net.Conn
	select {
	case second = <-fl.accepts:
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect never arrived after peer drop")
	}

	// Outer Done() must NOT have fired. If it had, Transport.Run's
	// fan-in goroutine for this interface would have exited and the
	// service would be permanently disconnected (the original bug).
	select {
	case <-rc.Done():
		t.Fatal("outer Done() fired on peer drop; should only fire on explicit Close()")
	default:
	}

	// Send succeeds against the redialed conn. Retry briefly to absorb
	// the tiny window between Accept returning and the supervisor
	// swapping the current inner client under the lock.
	payload = bytes.Repeat([]byte{0xCD}, 20)
	deadline := time.Now().Add(1 * time.Second)
	var sendErr error
	for time.Now().Before(deadline) {
		sendErr = rc.Send(payload)
		if sendErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sendErr != nil {
		t.Fatalf("post-reconnect Send: %v", sendErr)
	}
	if frame := readFrameWithTimeout(t, second, 500*time.Millisecond); !bytes.Equal(frame, payload) {
		t.Fatalf("second frame mismatch: got %x want %x", frame, payload)
	}

	_ = first
}

func TestReconnectingTCPClientOuterDoneFiresOnExplicitClose(t *testing.T) {
	fl := newFakeListener(t)
	defer fl.close()

	logger := log.New(io.Discard, "", 0)
	rc, err := dialReconnectingTCPForTest(fl.addr(), 2*time.Second, logger, 20*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("dialReconnectingTCP: %v", err)
	}

	select {
	case <-fl.accepts:
	case <-time.After(1 * time.Second):
		t.Fatal("listener never received accept")
	}

	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-rc.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("outer Done() did not fire after explicit Close()")
	}
}

func readFrameWithTimeout(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	dec := NewHDLCDecoder(c)
	f, err := dec.NextFrame()
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	return f
}
