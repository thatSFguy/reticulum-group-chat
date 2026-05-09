package rns

import (
	"bytes"
	"testing"
	"time"
)

func TestBuildAndVerifyAnnounceNoRatchet(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	appData, err := EncodeLXMFAppData([]byte("Forwarder"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), appData, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip via packet codec, parse back, verify.
	wire, err := pkt.Pack()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PacketType != PacketAnnounce {
		t.Fatalf("packet_type = %d", parsed.PacketType)
	}
	if parsed.ContextFlag {
		t.Error("context_flag should be false (no ratchet)")
	}

	a, err := ParseAnnounce(parsed)
	if err != nil {
		t.Fatalf("ParseAnnounce: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Display name decodes correctly out of app_data.
	name, err := DecodeLXMFAppDataDisplayName(a.AppData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(name, []byte("Forwarder")) {
		t.Errorf("display_name = %s, want Forwarder", name)
	}
}

func TestBuildAndVerifyAnnounceWithRatchet(t *testing.T) {
	id, _ := NewIdentity()

	// Use any 32-byte X25519 pub as the ratchet — for the verify path we
	// only care that bytes round-trip and signed_data includes them.
	ratchet := bytesOfLen(t, 32)
	pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if !pkt.ContextFlag {
		t.Error("context_flag should be true when ratchet is included")
	}

	wire, _ := pkt.Pack()
	parsed, _ := ParsePacket(wire)
	a, err := ParseAnnounce(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.RatchetPub, ratchet) {
		t.Errorf("ratchet round-trip failed\n got %x\nwant %x", a.RatchetPub, ratchet)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	a, _ := ParseAnnounce(pkt)

	tampered := append([]byte(nil), a.Signature...)
	tampered[0] ^= 0x01
	a.Signature = tampered

	if err := a.Verify(); err == nil {
		t.Error("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsTamperedAppData(t *testing.T) {
	id, _ := NewIdentity()
	appData, _ := EncodeLXMFAppData([]byte("Forwarder"), nil)
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), appData, nil)
	a, _ := ParseAnnounce(pkt)

	a.AppData = append([]byte(nil), a.AppData...)
	a.AppData[0] ^= 0x01

	if err := a.Verify(); err == nil {
		t.Error("Verify accepted tampered app_data")
	}
}

func TestVerifyRejectsForgedDestHash(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	a, _ := ParseAnnounce(pkt)

	// Replace dest_hash with a fake one — sig is still valid over the
	// ORIGINAL signed_data, but Verify should reject because the recomputed
	// dest_hash won't match the (tampered) outer one. Per SPEC §4.5 step 3.
	a.DestHash = make([]byte, IdentityHashLen)
	for i := range a.DestHash {
		a.DestHash[i] = 0xFF
	}

	if err := a.Verify(); err == nil {
		t.Error("Verify accepted a forged dest_hash")
	}
}

func TestParseAnnounceCapturesTransportIDForHeader2(t *testing.T) {
	id, _ := NewIdentity()
	pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Convert the announce packet to HEADER_2 by hand, simulating a relay
	// that inserted its own identity as transport_id.
	pkt.HeaderType = HeaderType2
	pkt.TransportType = NetworkTransport
	pkt.TransportID = newDummyHash(0xCC)
	pkt.Hops = 2

	wire, err := pkt.Pack()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAnnounce(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(a.TransportID, newDummyHash(0xCC)) {
		t.Errorf("TransportID not captured: got %x", a.TransportID)
	}
	if a.Hops != 2 {
		t.Errorf("Hops = %d, want 2", a.Hops)
	}
	if err := a.Verify(); err != nil {
		t.Errorf("Verify on HEADER_2 announce: %v", err)
	}
}

func TestParseAnnounceTransportIDIsNilForHeader1(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	wire, _ := pkt.Pack()
	parsed, _ := ParsePacket(wire)
	a, _ := ParseAnnounce(parsed)
	if a.TransportID != nil {
		t.Errorf("TransportID should be nil for HEADER_1 announce, got %x", a.TransportID)
	}
}

func TestRandomHashTimestamp(t *testing.T) {
	id, _ := NewIdentity()
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	pkt, err := buildAnnounce(id, FullName("lxmf", "delivery"), nil, nil, ContextNone,
		func() time.Time { return now },
		func(p []byte) (int, error) { return len(p), nil }, // deterministic zero entropy
	)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ParseAnnounce(pkt)

	emitted, err := a.EmittedAt()
	if err != nil {
		t.Fatal(err)
	}
	if !emitted.Equal(now) {
		t.Errorf("emitted_at = %v, want %v", emitted, now)
	}
}

func TestEncodeLXMFAppDataEmitsBinNotStr(t *testing.T) {
	// SPEC §4.3 wire example: display_name = "Reticulum5", stamp_cost = nil
	//   0x92                fixarray, 2 elements
	//   0xc4 0x0a           bin8, length 10
	//   "Reticulum5"        10 bytes ASCII
	//   0xc0                nil
	got, err := EncodeLXMFAppData([]byte("Reticulum5"), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x92, 0xc4, 0x0a}
	want = append(want, "Reticulum5"...)
	want = append(want, 0xc0)
	if !bytes.Equal(got, want) {
		t.Errorf("LXMF app_data wire bytes mismatch\n got %x\nwant %x", got, want)
	}
}

func TestDecodeLXMFAppDataAcceptsLegacyForms(t *testing.T) {
	// 1-element msgpack array (just bin name).
	one := []byte{0x91, 0xc4, 0x04, 'S', 'o', 'l', 'o'}
	if got, err := DecodeLXMFAppDataDisplayName(one); err != nil || string(got) != "Solo" {
		t.Errorf("1-element form: got %q err %v", got, err)
	}

	// 3-element msgpack array (name, stamp_cost, capability_flags).
	three := []byte{0x93, 0xc4, 0x04, 'M', 'u', 'l', 't', 0xc0, 0x90}
	if got, err := DecodeLXMFAppDataDisplayName(three); err != nil || string(got) != "Mult" {
		t.Errorf("3-element form: got %q err %v", got, err)
	}

	// Empty.
	if got, err := DecodeLXMFAppDataDisplayName(nil); err != nil || got != nil {
		t.Errorf("empty: got %v err %v", got, err)
	}
}
