package rns

import (
	"bytes"
	"testing"
)

func newDummyHash(seed byte) []byte {
	out := make([]byte, addressHashLen)
	for i := range out {
		out[i] = seed
	}
	return out
}

func TestPackUnpackHeader1(t *testing.T) {
	p := &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketAnnounce,
		Hops:            0,
		DestHash:        newDummyHash(0xAB),
		Context:         ContextNone,
		Data:            []byte("hello"),
	}
	wire, err := p.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != header1MinLen+len("hello") {
		t.Errorf("wire length = %d, want %d", len(wire), header1MinLen+5)
	}

	parsed, err := ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HeaderType != HeaderType1 {
		t.Errorf("header_type = %d", parsed.HeaderType)
	}
	if parsed.ContextFlag {
		t.Error("context_flag should be false")
	}
	if parsed.TransportType != BroadcastTransport {
		t.Errorf("transport_type = %d", parsed.TransportType)
	}
	if parsed.DestinationType != DestinationSingle {
		t.Errorf("dest_type = %d", parsed.DestinationType)
	}
	if parsed.PacketType != PacketAnnounce {
		t.Errorf("packet_type = %d", parsed.PacketType)
	}
	if !bytes.Equal(parsed.DestHash, p.DestHash) {
		t.Errorf("dest_hash mismatch")
	}
	if parsed.TransportID != nil {
		t.Errorf("HEADER_1 should not have transport_id, got %x", parsed.TransportID)
	}
	if !bytes.Equal(parsed.Data, []byte("hello")) {
		t.Errorf("data = %x", parsed.Data)
	}
}

func TestPackUnpackHeader2(t *testing.T) {
	p := &Packet{
		HeaderType:      HeaderType2,
		ContextFlag:     true, // announce-with-ratchet
		TransportType:   NetworkTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		Hops:            3,
		TransportID:     newDummyHash(0x11),
		DestHash:        newDummyHash(0x22),
		Context:         ContextPathResponse,
		Data:            []byte{0x01, 0x02, 0x03},
	}
	wire, err := p.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != header2MinLen+3 {
		t.Errorf("wire length = %d, want %d", len(wire), header2MinLen+3)
	}

	parsed, err := ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HeaderType != HeaderType2 {
		t.Errorf("header_type = %d", parsed.HeaderType)
	}
	if !parsed.ContextFlag {
		t.Error("context_flag should be true")
	}
	if !bytes.Equal(parsed.TransportID, p.TransportID) {
		t.Errorf("transport_id mismatch")
	}
	if !bytes.Equal(parsed.DestHash, p.DestHash) {
		t.Errorf("dest_hash mismatch")
	}
	if parsed.Hops != 3 {
		t.Errorf("hops = %d", parsed.Hops)
	}
	if parsed.Context != ContextPathResponse {
		t.Errorf("context = 0x%02x", parsed.Context)
	}
}

func TestFlagBitsRoundTripExhaustive(t *testing.T) {
	for hdr := byte(0); hdr <= 1; hdr++ {
		for cf := 0; cf < 2; cf++ {
			for tr := byte(0); tr <= 1; tr++ {
				for dt := byte(0); dt <= 3; dt++ {
					for pt := byte(0); pt <= 3; pt++ {
						f := packFlags(hdr, cf == 1, tr, dt, pt)
						gotHdr, gotCF, gotTr, gotDt, gotPt := unpackFlags(f)
						if gotHdr != hdr || (gotCF && cf == 0) || (!gotCF && cf == 1) ||
							gotTr != tr || gotDt != dt || gotPt != pt {
							t.Errorf("flags round-trip failed for (%d,%d,%d,%d,%d) -> 0x%02x -> (%d,%v,%d,%d,%d)",
								hdr, cf, tr, dt, pt, f,
								gotHdr, gotCF, gotTr, gotDt, gotPt)
						}
					}
				}
			}
		}
	}
}

func TestHashablePartHeader1Strips(t *testing.T) {
	// HEADER_1: hashable = (flags & 0x0F) || raw[2:]
	// flags' high nibble (header_type + context_flag + transport_type) and
	// the hops byte at offset 1 are stripped.
	p := &Packet{
		HeaderType:      HeaderType1,
		TransportType:   NetworkTransport, // bit 4 set in raw flags, masked off in hashable
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		Hops:            7, // also stripped
		DestHash:        newDummyHash(0xAA),
		Context:         ContextNone,
		Data:            []byte("payload"),
	}
	hp, err := p.HashablePart()
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.Pack()

	// Expected: low nibble of flags || dest_hash || context || data
	expected := append([]byte{wire[0] & 0x0F}, wire[2:]...)
	if !bytes.Equal(hp, expected) {
		t.Errorf("hashable part mismatch\n got %x\nwant %x", hp, expected)
	}
}

func TestHashablePartHeader2StripsTransportID(t *testing.T) {
	p := &Packet{
		HeaderType:      HeaderType2,
		TransportType:   NetworkTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		Hops:            2,
		TransportID:     newDummyHash(0x11),
		DestHash:        newDummyHash(0x22),
		Context:         ContextNone,
		Data:            []byte("body"),
	}
	hp, err := p.HashablePart()
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.Pack()

	// Expected: low nibble of flags || dest_hash || context || data (transport_id slot at [2:18] stripped)
	expected := append([]byte{wire[0] & 0x0F}, wire[18:]...)
	if !bytes.Equal(hp, expected) {
		t.Errorf("hashable part mismatch\n got %x\nwant %x", hp, expected)
	}
}

func TestUint40RoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 0xFFFFFFFFFF, 1735689600 /* 2025-01-01 */} {
		b := BigEndianUint40(v)
		got, err := DecodeBigEndianUint40(b[:])
		if err != nil {
			t.Fatalf("decode %x: %v", b, err)
		}
		if got != v {
			t.Errorf("uint40 round-trip: got %d, want %d", got, v)
		}
	}
}

func TestParseRejectsTruncated(t *testing.T) {
	if _, err := ParsePacket([]byte{0x00, 0x00}); err == nil {
		t.Error("expected error on truncated packet")
	}
}
