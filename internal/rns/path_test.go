package rns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPathRequestDestHashRecomputes is a regression guard: if either NameHash
// or the PLAIN-destination derivation rule (16 zero bytes for identity_hash)
// ever changes, this test fails before users hit a silent network bug.
func TestPathRequestDestHashRecomputes(t *testing.T) {
	nh := NameHash("rnstransport.path.request")
	expectedNameHashHex := "7926bbe7dd7f9aba88b0"
	if hex.EncodeToString(nh) != expectedNameHashHex {
		t.Errorf("NameHash(rnstransport.path.request) = %x, want %s", nh, expectedNameHashHex)
	}

	// For PLAIN destinations, the identity hash is OMITTED — not zero-padded.
	// Per upstream RNS.Destination.hash: addr_hash_material = name_hash only
	// when identity is None.
	d := sha256.Sum256(nh)
	got := hex.EncodeToString(d[:IdentityHashLen])
	if got != PathRequestDestHashHex {
		t.Errorf("path-request dest hash recompute mismatch\n got %s\nwant %s", got, PathRequestDestHashHex)
	}
}

func TestBuildPathRequestStructure(t *testing.T) {
	target := newDummyHash(0xAB)
	pkt, err := BuildPathRequest(target)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.PacketType != PacketData {
		t.Errorf("packet_type = %d, want PacketData", pkt.PacketType)
	}
	if pkt.DestinationType != DestinationPlain {
		t.Errorf("dest_type = %d, want DestinationPlain", pkt.DestinationType)
	}
	if pkt.TransportType != BroadcastTransport {
		t.Errorf("transport_type = %d, want BroadcastTransport", pkt.TransportType)
	}
	if pkt.HeaderType != HeaderType1 {
		t.Errorf("header_type = %d, want HEADER_1", pkt.HeaderType)
	}
	if pkt.Context != ContextNone {
		t.Errorf("context = 0x%02x, want 0x00", pkt.Context)
	}
	expectedDest, _ := hex.DecodeString(PathRequestDestHashHex)
	if !bytes.Equal(pkt.DestHash, expectedDest) {
		t.Errorf("dest_hash = %x, want well-known %x", pkt.DestHash, expectedDest)
	}
	if len(pkt.Data) != PathRequestPayloadLen {
		t.Fatalf("payload length = %d, want %d", len(pkt.Data), PathRequestPayloadLen)
	}
	if !bytes.Equal(pkt.Data[:IdentityHashLen], target) {
		t.Errorf("payload target prefix mismatch: got %x, want %x", pkt.Data[:IdentityHashLen], target)
	}
}

func TestBuildPathRequestRejectsBadTarget(t *testing.T) {
	if _, err := BuildPathRequest(nil); err == nil {
		t.Error("expected error for nil target")
	}
	if _, err := BuildPathRequest(make([]byte, 8)); err == nil {
		t.Error("expected error for short target")
	}
}

func TestBuildPathRequestUsesFreshTagEachCall(t *testing.T) {
	target := newDummyHash(0xCD)
	a, _ := BuildPathRequest(target)
	b, _ := BuildPathRequest(target)
	// Tags are random; two builds back-to-back should differ.
	if bytes.Equal(a.Data[IdentityHashLen:], b.Data[IdentityHashLen:]) {
		t.Error("two BuildPathRequest calls produced the same tag (expected random)")
	}
	// Targets are stable.
	if !bytes.Equal(a.Data[:IdentityHashLen], b.Data[:IdentityHashLen]) {
		t.Error("target half changed between calls")
	}
}

func TestPathRequestTargetExtracts(t *testing.T) {
	target := newDummyHash(0x77)
	pkt, _ := BuildPathRequest(target)
	got, err := PathRequestTarget(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, target) {
		t.Errorf("target extraction mismatch")
	}
}

// TestHandlePathRequestEmitsPathResponseAnnounce is the regression test
// for the SPEC §7.2 path-request responder. When an inbound path?
// request targets one of our local destinations, we must broadcast a
// path-response (announce with context = ContextPathResponse) carrying
// our public key so the requester can build a path table entry.
//
// Without this, leaf clients can't bootstrap a path to us via path? —
// they have to wait up to one announce_interval (10 min default) for
// our periodic announce.
func TestHandlePathRequestEmitsPathResponseAnnounce(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	req, err := BuildPathRequest(destHash)
	if err != nil {
		t.Fatalf("BuildPathRequest: %v", err)
	}
	transport.handlePathRequest(req)

	wires := captured.sentCopy()
	if len(wires) != 1 {
		t.Fatalf("expected 1 transmitted packet (path-response), got %d", len(wires))
	}
	resp, err := ParsePacket(wires[0])
	if err != nil {
		t.Fatalf("ParsePacket(response): %v", err)
	}
	if resp.PacketType != PacketAnnounce {
		t.Errorf("response packet_type = %d, want PacketAnnounce", resp.PacketType)
	}
	if resp.Context != ContextPathResponse {
		t.Errorf("response context = 0x%02x, want ContextPathResponse (0x0B)", resp.Context)
	}
	if !bytes.Equal(resp.DestHash, destHash) {
		t.Errorf("response dest_hash = %x, want %x", resp.DestHash, destHash)
	}
	a, err := ParseAnnounce(resp)
	if err != nil {
		t.Fatalf("ParseAnnounce: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Errorf("path-response announce signature does not verify: %v", err)
	}
}

// TestHandlePathRequestIgnoresUnrelatedTarget pins that we don't emit
// path-responses for destinations we don't own — preventing us from
// turning into an inadvertent transit relay for arbitrary path queries.
func TestHandlePathRequestIgnoresUnrelatedTarget(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	ourHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: ourHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	someOtherTarget := newDummyHash(0xAB)
	req, _ := BuildPathRequest(someOtherTarget)
	transport.handlePathRequest(req)

	if got := captured.sentCopy(); len(got) != 0 {
		t.Errorf("expected no transmission for unrelated target, got %d packets", len(got))
	}
}

// TestHandlePathRequestDedupsByTag pins that re-receiving the same
// request (same 16-byte tag) within PathResponseTagDedupWindow does
// NOT cause us to emit a second response — protects against amplifying
// when a single request reaches us via multiple relay hops.
func TestHandlePathRequestDedupsByTag(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	req, _ := BuildPathRequest(destHash)

	transport.handlePathRequest(req)
	transport.handlePathRequest(req) // same tag → suppress

	if got := captured.sentCopy(); len(got) != 1 {
		t.Errorf("expected exactly 1 transmission with tag dedup, got %d", len(got))
	}
}
