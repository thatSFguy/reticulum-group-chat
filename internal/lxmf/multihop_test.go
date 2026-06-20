package lxmf

import (
	"bytes"
	"testing"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// TestSendUsesHeader1ForDirectNeighbors verifies that when a recipient
// announced directly (HEADER_1, no transport_id), Delivery.Send still
// emits HEADER_1 broadcast packets. This is the existing behavior.
func TestSendUsesHeader1ForDirectNeighbors(t *testing.T) {
	pkt := buildOutboundPacket(make([]byte, rns.IdentityHashLen), []byte("ciphertext"), nil)
	if pkt.HeaderType != rns.HeaderType1 {
		t.Errorf("HeaderType = %d, want HeaderType1", pkt.HeaderType)
	}
	if pkt.TransportType != rns.BroadcastTransport {
		t.Errorf("TransportType = %d, want BroadcastTransport", pkt.TransportType)
	}
	if pkt.TransportID != nil {
		t.Errorf("TransportID should be nil for HEADER_1, got %x", pkt.TransportID)
	}
}

// TestSendUsesHeader2WithTransportIDForMultiHop verifies SPEC §2.3:
// when we know a transport_id for the recipient (because their announce
// arrived as HEADER_2), our outbound DATA packet must be HEADER_2 with
// TransportType=NetworkTransport and the cached transport_id, so
// transport-enabled relays can route it to the multi-hop recipient.
func TestSendUsesHeader2WithTransportIDForMultiHop(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, rns.IdentityHashLen)
	pkt := buildOutboundPacket(make([]byte, rns.IdentityHashLen), []byte("ciphertext"), want)

	if pkt.HeaderType != rns.HeaderType2 {
		t.Errorf("HeaderType = %d, want HeaderType2", pkt.HeaderType)
	}
	if pkt.TransportType != rns.NetworkTransport {
		t.Errorf("TransportType = %d, want NetworkTransport", pkt.TransportType)
	}
	if !bytes.Equal(pkt.TransportID, want) {
		t.Errorf("TransportID mismatch: got %x, want %x", pkt.TransportID, want)
	}
	if pkt.PacketType != rns.PacketData {
		t.Errorf("PacketType = %d, want PacketData", pkt.PacketType)
	}
	if pkt.Hops != 0 {
		t.Errorf("originator must emit Hops=0, got %d", pkt.Hops)
	}
}

// TestSendIgnoresMalformedTransportID guards against accidentally producing
// an invalid HEADER_2 packet if a future bug populates TransportID with
// the wrong number of bytes.
func TestSendIgnoresMalformedTransportID(t *testing.T) {
	tooShort := []byte{0xAB, 0xCD}
	pkt := buildOutboundPacket(make([]byte, rns.IdentityHashLen), []byte("c"), tooShort)
	if pkt.HeaderType != rns.HeaderType1 {
		t.Errorf("malformed transport_id should fall back to HEADER_1, got %d", pkt.HeaderType)
	}
}
