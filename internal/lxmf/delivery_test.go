package lxmf

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

// crossInterface implements rns.Interface and pumps each side's Send into
// the OTHER side's Inbox. Used to put two Transports on a shared "wire"
// in-process for end-to-end LXMF round-trip tests.
type crossInterface struct {
	in   chan []byte
	out  chan []byte // receiver-side inbox (peer's incoming)
	done chan struct{}
}

func (c *crossInterface) Send(p []byte) error {
	cp := append([]byte(nil), p...)
	select {
	case c.in <- cp:
	case <-c.done:
	}
	return nil
}
func (c *crossInterface) Inbox() <-chan []byte  { return c.out }
func (c *crossInterface) Done() <-chan struct{} { return c.done }

// pairedInterfaces returns two Interfaces wired such that anything Side A
// sends arrives in Side B's Inbox and vice-versa.
func pairedInterfaces() (*crossInterface, *crossInterface, func()) {
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	done := make(chan struct{})
	a := &crossInterface{in: a2b, out: b2a, done: done}
	b := &crossInterface{in: b2a, out: a2b, done: done}
	return a, b, func() { close(done) }
}

// TestEndToEndRoundTripBetweenTwoDeliveries spins up two Transports on a
// shared wire, exchanges announces, and verifies an LXMF message round-trips.
// This exercises every layer: identity, announce, transport dispatch,
// Token cipher, LXMF wire format, and signature verification.
func TestEndToEndRoundTripBetweenTwoDeliveries(t *testing.T) {
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()

	aIface, bIface, stop := pairedInterfaces()
	defer stop()

	tA := rns.NewTransport(nil)
	tA.AddInterface(aIface)
	tB := rns.NewTransport(nil)
	tB.AddInterface(bIface)

	delA, err := NewDelivery(tA, alice)
	if err != nil {
		t.Fatal(err)
	}
	delB, err := NewDelivery(tB, bob)
	if err != nil {
		t.Fatal(err)
	}

	// Bob's onMessage records what arrived.
	var (
		mu       sync.Mutex
		received [][]byte
	)
	delB.OnMessage = func(m *Message) {
		mu.Lock()
		received = append(received, append([]byte(nil), m.Content...))
		mu.Unlock()
	}
	var errCount int32
	onErr := func(error) { atomic.AddInt32(&errCount, 1) }
	delA.OnError = onErr
	delB.OnError = onErr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tA.Run(ctx)
	go tB.Run(ctx)

	// Each side announces so the other learns its public key. The transport
	// builds the announce packet via BuildAnnounce + Broadcast.
	mustAnnounce := func(t *testing.T, tr *rns.Transport, id *rns.Identity) {
		t.Helper()
		appData, _ := rns.EncodeLXMFAppData([]byte(""), nil)
		pkt, err := rns.BuildAnnounce(id, FullName(), appData, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Broadcast(pkt); err != nil {
			t.Fatal(err)
		}
	}
	mustAnnounce(t, tA, alice)
	mustAnnounce(t, tB, bob)

	// Wait for both sides to learn each other.
	if !waitFor(500*time.Millisecond, func() bool {
		return tA.Recall(bob.DestinationHashFor(FullName())) != nil &&
			tB.Recall(alice.DestinationHashFor(FullName())) != nil
	}) {
		t.Fatal("announces never propagated")
	}

	// Alice sends Bob a message.
	if err := delA.Send(delB.Hash(), nil, []byte("hi bob"), nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !waitFor(500*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	}) {
		t.Fatalf("no message arrived (errCount=%d)", atomic.LoadInt32(&errCount))
	}
	mu.Lock()
	got := string(received[0])
	mu.Unlock()
	if got != "hi bob" {
		t.Errorf("Bob got %q, want %q", got, "hi bob")
	}
}

func TestSendRejectsUnknownRecipient(t *testing.T) {
	id, _ := rns.NewIdentity()
	tr := rns.NewTransport(nil)
	d, _ := NewDelivery(tr, id)

	bogus := make([]byte, rns.IdentityHashLen)
	if err := d.Send(bogus, nil, []byte("x"), nil); err == nil {
		t.Error("Send accepted unknown recipient")
	}
}

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
