package rns

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

// fakeInterface is an in-memory Interface implementation for tests.
type fakeInterface struct {
	inbox chan []byte
	sent  [][]byte
	done  chan struct{}
	mu    sync.Mutex
}

func newFakeInterface() *fakeInterface {
	return &fakeInterface{
		inbox: make(chan []byte, 16),
		done:  make(chan struct{}),
	}
}

func (f *fakeInterface) Send(p []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, append([]byte(nil), p...))
	f.mu.Unlock()
	return nil
}

func (f *fakeInterface) Inbox() <-chan []byte    { return f.inbox }
func (f *fakeInterface) Done() <-chan struct{}   { return f.done }
func (f *fakeInterface) close()                  { close(f.done) }
func (f *fakeInterface) sentCopy() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.sent))
	for i, b := range f.sent {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

type recordingHandler struct {
	mu       sync.Mutex
	received []*Announce
	filter   []byte
}

func (h *recordingHandler) AspectMatch(nameHash []byte) bool {
	if h.filter == nil {
		return true
	}
	return bytes.Equal(h.filter, nameHash)
}
func (h *recordingHandler) OnAnnounce(a *Announce) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.received = append(h.received, a)
}
func (h *recordingHandler) snapshot() []*Announce {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Announce(nil), h.received...)
}

func TestTransportDispatchesVerifiedAnnounceToHandlers(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	handler := &recordingHandler{filter: NameHash(FullName("lxmf", "delivery"))}

	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterAnnounceHandler(handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	deadline := time.After(500 * time.Millisecond)
	for {
		if len(handler.snapshot()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("handler never fired (got %d announces)", len(handler.snapshot()))
		case <-time.After(5 * time.Millisecond):
		}
	}

	known := tr.Recall(id.DestinationHashFor(FullName("lxmf", "delivery")))
	if known == nil {
		t.Fatal("Recall returned nil for known dest")
	}
	if !bytes.Equal(known.PublicKey, id.PublicKey()) {
		t.Errorf("known.PublicKey mismatch")
	}
}

func TestTransportRoutesDataToLocalDest(t *testing.T) {
	tr := NewTransport(nil)
	iface := newFakeInterface()
	tr.AddInterface(iface)

	deliveredCh := make(chan *Packet, 1)
	dest := newDummyHash(0xCC)
	tr.RegisterLocal(&LocalDestination{
		DestHash: dest,
		OnPacket: func(p *Packet) { deliveredCh <- p },
	})

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        dest,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}
	wire, _ := pkt.Pack()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	select {
	case got := <-deliveredCh:
		if !bytes.Equal(got.DestHash, dest) {
			t.Errorf("delivered to wrong dest: %x", got.DestHash)
		}
		if !bytes.Equal(got.Data, []byte("ciphertext")) {
			t.Errorf("data mismatch: %x", got.Data)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("data never delivered to local dest")
	}
}

func TestTransportIgnoresDataForUnknownDest(t *testing.T) {
	tr := NewTransport(nil)
	iface := newFakeInterface()
	tr.AddInterface(iface)

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        newDummyHash(0xFF),
		Context:         ContextNone,
		Data:            []byte("not ours"),
	}
	wire, _ := pkt.Pack()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire
	time.Sleep(50 * time.Millisecond) // give dispatcher time
	// No assertion: just verify nothing panics and the goroutine cleans up.
}

func TestTransportBroadcastFansOut(t *testing.T) {
	tr := NewTransport(nil)
	a, b := newFakeInterface(), newFakeInterface()
	tr.AddInterface(a)
	tr.AddInterface(b)

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        newDummyHash(0xAA),
		Context:         ContextNone,
		Data:            []byte("hi"),
	}
	if err := tr.Broadcast(pkt); err != nil {
		t.Fatal(err)
	}
	if len(a.sentCopy()) != 1 || len(b.sentCopy()) != 1 {
		t.Errorf("broadcast didn't reach both interfaces (a=%d, b=%d)", len(a.sentCopy()), len(b.sentCopy()))
	}
}

func TestTransportCapturesTransportIDFromHeader2Announce(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	// Mutate to HEADER_2 with a known transport_id.
	pkt.HeaderType = HeaderType2
	pkt.TransportType = NetworkTransport
	pkt.TransportID = newDummyHash(0x99)
	pkt.Hops = 3
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	deadline := time.After(500 * time.Millisecond)
	for {
		known := tr.Recall(id.DestinationHashFor(FullName("lxmf", "delivery")))
		if known != nil && known.TransportID != nil {
			if !bytes.Equal(known.TransportID, newDummyHash(0x99)) {
				t.Errorf("transport_id mismatch: got %x", known.TransportID)
			}
			if known.Hops != 3 {
				t.Errorf("hops = %d, want 3", known.Hops)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("transport_id never captured into KnownIdentity")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestTransportDedupesIdenticalRandomHash(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	handler := &recordingHandler{}
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterAnnounceHandler(handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	// Send the same announce three times; handler should fire only once.
	iface.inbox <- wire
	iface.inbox <- wire
	iface.inbox <- wire

	time.Sleep(100 * time.Millisecond)

	if got := len(handler.snapshot()); got != 1 {
		t.Errorf("dedup failed: handler fired %d times, want 1", got)
	}
}
