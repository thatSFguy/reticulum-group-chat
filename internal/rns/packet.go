package rns

import (
	"errors"
	"fmt"
)

// Header-byte bit layout (SPEC §2.1, official manual §4.6.3):
//
//	bit 7   : ifac_flag        (0=open, 1=IFAC-sealed; we reject these)
//	bit 6   : header_type      (0 = HEADER_1, 1 = HEADER_2)
//	bit 5   : context_flag     (1 = announce includes a ratchet pubkey)
//	bit 4   : transport_type   (0 = BROADCAST, 1 = TRANSPORT)
//	bit 3-2 : destination_type (0=SINGLE, 1=GROUP, 2=PLAIN, 3=LINK)
//	bit 1-0 : packet_type      (0=DATA, 1=ANNOUNCE, 2=LINKREQUEST, 3=PROOF)
//
// Bit 7 was wrongly grouped with header_type in earlier spec revisions
// (corrected at thatSFguy/reticulum-specifications@0c2021e). An
// implementation that reads bits 7-6 as a 2-bit header_type will silently
// drop every inbound packet from an IFAC-sealed interface, since the
// header_type comes back as 2 or 3 and never matches HEADER_1/HEADER_2.
const (
	HeaderType1 = 0
	HeaderType2 = 1

	BroadcastTransport = 0
	NetworkTransport   = 1

	DestinationSingle = 0
	DestinationGroup  = 1
	DestinationPlain  = 2
	DestinationLink   = 3

	PacketData        = 0
	PacketAnnounce    = 1
	PacketLinkRequest = 2
	PacketProof       = 3
)

// Context-byte values (SPEC §2.5). Only the ones we actually handle are
// listed; the rest are accepted opaquely.
const (
	ContextNone         = 0x00
	ContextPathResponse = 0x0B
	// ContextLinkIdentify (SPEC §6.6) is the link-DATA context byte for
	// LINKIDENTIFY — an initiator-emitted, link-encrypted packet that
	// proves which identity (and therefore which destination) the link
	// is being driven from. Plaintext is identity_hash(16) ||
	// signature(64), where the signature covers link_id || full
	// public_key. Lets a responder route asynchronous follow-up traffic
	// (e.g. tap-back reactions on a relayed bubble) back through the
	// same destination the link originated from — critical for
	// forwarding-relay group chats where the LXMF source_hash on
	// link-delivered bubbles is the relay, not the human originator.
	ContextLinkIdentify = 0xFB
	ContextLRProof      = 0xFF
)

const (
	addressHashLen = 16

	header1MinLen = 1 + 1 + addressHashLen + 1            // 19
	header2MinLen = 1 + 1 + addressHashLen*2 + 1          // 35
)

// errIFACUnsupported is returned by ParsePacket when the inbound packet's
// ifac_flag is set. We don't speak IFAC: the IFAC field's per-interface
// size is configured out-of-band, and we have no way to verify the seal,
// so we drop rather than guess. Surfaces in transport logs as a clear
// "this packet came from an IFAC interface and we can't decode it"
// signal, distinct from a generic parse error.
var errIFACUnsupported = errors.New("IFAC-sealed packet rejected (ifac_flag=1, SPEC §2.1)")

// Packet is a parsed Reticulum packet. The header bit fields are exploded
// into named integers so callers don't have to mask manually.
type Packet struct {
	HeaderType      byte // HeaderType1 or HeaderType2
	ContextFlag     bool
	TransportType   byte // BroadcastTransport or NetworkTransport
	DestinationType byte // DestinationSingle/Group/Plain/Link
	PacketType      byte // PacketData/Announce/LinkRequest/Proof

	Hops        byte
	TransportID []byte // 16 bytes when HeaderType == HeaderType2, else nil
	DestHash    []byte // 16 bytes
	Context     byte
	Data        []byte
}

// Pack encodes the packet to wire bytes. For HEADER_2, TransportID must be
// 16 bytes; for HEADER_1 it is ignored.
func (p *Packet) Pack() ([]byte, error) {
	if len(p.DestHash) != addressHashLen {
		return nil, fmt.Errorf("dest hash must be %d bytes, got %d", addressHashLen, len(p.DestHash))
	}

	flags := packFlags(p.HeaderType, p.ContextFlag, p.TransportType, p.DestinationType, p.PacketType)

	switch p.HeaderType {
	case HeaderType1:
		out := make([]byte, 0, header1MinLen+len(p.Data))
		out = append(out, flags, p.Hops)
		out = append(out, p.DestHash...)
		out = append(out, p.Context)
		out = append(out, p.Data...)
		return out, nil
	case HeaderType2:
		if len(p.TransportID) != addressHashLen {
			return nil, fmt.Errorf("HEADER_2 requires %d-byte transport_id, got %d", addressHashLen, len(p.TransportID))
		}
		out := make([]byte, 0, header2MinLen+len(p.Data))
		out = append(out, flags, p.Hops)
		out = append(out, p.TransportID...)
		out = append(out, p.DestHash...)
		out = append(out, p.Context)
		out = append(out, p.Data...)
		return out, nil
	default:
		return nil, fmt.Errorf("unknown header_type %d", p.HeaderType)
	}
}

// ParsePacket decodes a packet from wire bytes. The returned Packet's
// DestHash, TransportID, and Data slices alias into the input — copy if you
// intend to retain them.
func ParsePacket(raw []byte) (*Packet, error) {
	if len(raw) < header1MinLen {
		return nil, fmt.Errorf("packet too short: %d bytes", len(raw))
	}
	flags := raw[0]
	ifacFlag, headerType, contextFlag, transportType, destType, packetType := unpackFlags(flags)
	if ifacFlag {
		return nil, errIFACUnsupported
	}

	p := &Packet{
		HeaderType:      headerType,
		ContextFlag:     contextFlag,
		TransportType:   transportType,
		DestinationType: destType,
		PacketType:      packetType,
		Hops:            raw[1],
	}

	switch headerType {
	case HeaderType1:
		// flags(1) hops(1) dest_hash(16) context(1) data(...)
		if len(raw) < header1MinLen {
			return nil, errors.New("HEADER_1 packet truncated")
		}
		p.DestHash = raw[2 : 2+addressHashLen]
		p.Context = raw[2+addressHashLen]
		p.Data = raw[header1MinLen:]
	case HeaderType2:
		// flags(1) hops(1) transport_id(16) dest_hash(16) context(1) data(...)
		if len(raw) < header2MinLen {
			return nil, errors.New("HEADER_2 packet truncated")
		}
		p.TransportID = raw[2 : 2+addressHashLen]
		p.DestHash = raw[2+addressHashLen : 2+addressHashLen*2]
		p.Context = raw[2+addressHashLen*2]
		p.Data = raw[header2MinLen:]
	default:
		return nil, fmt.Errorf("unknown header_type %d", headerType)
	}
	return p, nil
}

// HashablePart returns the canonical bytes used for packet hashing (proof
// binding etc.), per SPEC §6.5 / §17.3:
//
//	HEADER_1: (flags & 0x0F) || raw[2:]
//	HEADER_2: (flags & 0x0F) || raw[18:]
//
// The high nibble of flags (header_type, context_flag, transport_type) and
// the hops byte are stripped, plus for HEADER_2 the transport_id slot —
// so a HEADER_1↔HEADER_2 conversion in flight does not change the hash.
func (p *Packet) HashablePart() ([]byte, error) {
	raw, err := p.Pack()
	if err != nil {
		return nil, err
	}
	low := raw[0] & 0x0F
	switch p.HeaderType {
	case HeaderType1:
		out := make([]byte, 0, 1+len(raw)-2)
		out = append(out, low)
		out = append(out, raw[2:]...)
		return out, nil
	case HeaderType2:
		out := make([]byte, 0, 1+len(raw)-18)
		out = append(out, low)
		out = append(out, raw[18:]...)
		return out, nil
	default:
		return nil, fmt.Errorf("unknown header_type %d", p.HeaderType)
	}
}

func packFlags(headerType byte, contextFlag bool, transportType, destType, packetType byte) byte {
	var f byte
	// header_type is bit 6 only; bit 7 is ifac_flag and we never set it
	// (we don't originate IFAC-sealed traffic).
	f |= (headerType & 0x01) << 6
	if contextFlag {
		f |= 1 << 5
	}
	f |= (transportType & 0x01) << 4
	f |= (destType & 0x03) << 2
	f |= packetType & 0x03
	return f
}

func unpackFlags(f byte) (ifacFlag bool, headerType byte, contextFlag bool, transportType, destType, packetType byte) {
	ifacFlag = (f>>7)&0x01 == 1
	headerType = (f >> 6) & 0x01
	contextFlag = (f>>5)&0x01 == 1
	transportType = (f >> 4) & 0x01
	destType = (f >> 2) & 0x03
	packetType = f & 0x03
	return
}

// PrependDestinationHash re-prepends a destination hash to a payload that
// arrived stripped of it (the opportunistic LXMF receive path strips the
// recipient's dest_hash from the LXMF body before transmission, per SPEC §5.1).
//
// Provided here as a small utility so the LXMF layer doesn't need to
// re-implement byte slicing logic.
func PrependDestinationHash(destHash, payload []byte) []byte {
	out := make([]byte, 0, len(destHash)+len(payload))
	out = append(out, destHash...)
	out = append(out, payload...)
	return out
}

// BigEndianUint40 packs a uint64 into 5 big-endian bytes. Used for the
// timestamp half of an announce's random_hash (SPEC §4.1).
func BigEndianUint40(v uint64) [5]byte {
	return [5]byte{
		byte(v >> 32),
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

// DecodeBigEndianUint40 is the inverse.
func DecodeBigEndianUint40(b []byte) (uint64, error) {
	if len(b) != 5 {
		return 0, fmt.Errorf("uint40 needs 5 bytes, got %d", len(b))
	}
	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4]), nil
}
