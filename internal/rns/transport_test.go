package rns

import (
	"bytes"
	"context"
	"encoding/hex"
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

// TestAnnounceRejectsPublicKeyCollision covers SPEC §4.5 step 4
// (first-announcer-wins): an announce for a dest_hash already bound to a
// DIFFERENT public key is rejected. A verifiable announce can never produce
// this (dest_hash is bound to the key), so we pre-seed a bogus key under the
// real announce's dest_hash and confirm the genuine announce doesn't
// overwrite it.
func TestAnnounceRejectsPublicKeyCollision(t *testing.T) {
	tr := NewTransport(nil)
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))

	other := bytes.Repeat([]byte{0x42}, PublicKeyLen)
	tr.mu.Lock()
	tr.known[hex.EncodeToString(dest)] = &KnownIdentity{DestHash: dest, PublicKey: other}
	tr.mu.Unlock()

	tr.handleAnnounce(pkt) // genuine, verifiable — but a colliding key is cached

	got := tr.Recall(dest)
	if got == nil || !bytes.Equal(got.PublicKey, other) {
		t.Fatalf("collision announce was not rejected: cached key changed")
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

func TestRequestPathBroadcastsAndDedups(t *testing.T) {
	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	target := newDummyHash(0x55)

	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}
	// Second + third calls within the dedup window must not re-broadcast.
	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}
	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}

	sent := iface.sentCopy()
	if len(sent) != 1 {
		t.Fatalf("expected exactly 1 path request broadcast (deduped), got %d", len(sent))
	}

	pkt, err := ParsePacket(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PacketType != PacketData || pkt.DestinationType != DestinationPlain {
		t.Errorf("not a path-request shaped packet: type=%d destType=%d", pkt.PacketType, pkt.DestinationType)
	}
	if !bytes.Equal(pkt.Data[:IdentityHashLen], target) {
		t.Errorf("payload target mismatch")
	}
}

func TestRequestPathDedupesPerTarget(t *testing.T) {
	// Distinct targets should NOT dedup — each gets its own request.
	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	_ = tr.RequestPath(newDummyHash(0x01))
	_ = tr.RequestPath(newDummyHash(0x02))
	_ = tr.RequestPath(newDummyHash(0x03))

	if got := len(iface.sentCopy()); got != 3 {
		t.Errorf("expected 3 path requests for 3 distinct targets, got %d", got)
	}
}

func TestTransportEmitsProofForInboundData(t *testing.T) {
	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	// Inject a fake DATA packet addressed to our local destination.
	dataPkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        destHash,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}
	dataWire, _ := dataPkt.Pack()
	iface.inbox <- dataWire

	// Expect to see a PROOF emitted on the same interface.
	deadline := time.After(500 * time.Millisecond)
	for {
		for _, sent := range iface.sentCopy() {
			parsed, err := ParsePacket(sent)
			if err != nil {
				continue
			}
			if parsed.PacketType == PacketProof {
				if parsed.Context != ContextNone {
					t.Errorf("proof context = 0x%02x, want 0x00", parsed.Context)
				}
				if len(parsed.Data) != ProofBodyImplicitLen {
					t.Errorf("proof body length = %d, want %d", len(parsed.Data), ProofBodyImplicitLen)
				}
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("no PROOF emitted (sent %d packets)", len(iface.sentCopy()))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestTransportSkipsProofWhenIdentityAbsent(t *testing.T) {
	destHash := newDummyHash(0xDD)

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		// Identity intentionally nil — used by tests that don't care about proofs.
		OnPacket: func(*Packet) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	dataPkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        destHash,
		Context:         ContextNone,
		Data:            []byte("c"),
	}
	dataWire, _ := dataPkt.Pack()
	iface.inbox <- dataWire

	time.Sleep(80 * time.Millisecond)
	for _, sent := range iface.sentCopy() {
		p, err := ParsePacket(sent)
		if err == nil && p.PacketType == PacketProof {
			t.Error("transport emitted a proof when LocalDestination.Identity was nil")
		}
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
