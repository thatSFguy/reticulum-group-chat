package rns

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
)

// Link DATA wire format (SPEC §6.4): a regular DATA packet whose outer
// header has dest_type=LINK and dest_hash=link_id; the body is the
// link-form Token ciphertext (no eph_pub prefix; session keys are
// pre-derived from the handshake).
//
// Link DATA proofs (SPEC §6.5.6) are always the explicit 96-byte form
// (packet_hash || signature). The signature is computed with the
// link-derived signing key (used as an Ed25519 seed), NOT either side's
// long-term Ed25519 priv. Both sides share the same session keys, so
// either can sign and either can verify.

// BuildLinkDataPacket encrypts plaintext under the link's session keys
// and wraps the ciphertext in a Reticulum DATA packet addressed to the
// link.
func BuildLinkDataPacket(linkID, signing, encryption, plaintext []byte) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes, got %d", IdentityHashLen, len(linkID))
	}
	ciphertext, err := LinkTokenEncrypt(plaintext, signing, encryption)
	if err != nil {
		return nil, fmt.Errorf("link encrypt: %w", err)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextNone,
		Data:            ciphertext,
	}, nil
}

// ParseLinkDataPacket decrypts the payload of a DATA packet that
// arrived addressed to this link's link_id. Verifies the wire form is
// link DATA (dest_type=LINK), then runs the link-form Token decryptor.
func ParseLinkDataPacket(p *Packet, signing, encryption []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketData {
		return nil, fmt.Errorf("packet_type %d is not DATA", p.PacketType)
	}
	if p.DestinationType != DestinationLink {
		return nil, fmt.Errorf("dest_type %d is not LINK", p.DestinationType)
	}
	if p.Context != ContextNone {
		return nil, fmt.Errorf("link DATA context = 0x%02x, want 0x00", p.Context)
	}
	return LinkTokenDecrypt(p.Data, signing, encryption)
}

// BuildLinkProof builds the explicit-form (96-byte) PROOF packet that
// acknowledges receipt of an inbound link DATA packet (SPEC §6.5.6).
// Per upstream RNS 1.2.0 link DATA proofs are ALWAYS explicit
// regardless of the global use_implicit_proof setting.
//
// The signature is over SHA-256(original.HashablePart()), signed by the
// LOCAL endpoint's Ed25519 key — NOT a link-derived shared key. Per
// upstream RNS/Link.py:279 the responder uses its destination identity's
// long-term sig_prv; the initiator uses an ephemeral sig_prv generated
// at link-creation time and advertised in the LINKREQUEST. Either way
// the local side knows the priv; the remote side has the corresponding
// pub from the handshake (responder pub from LRPROOF body, initiator
// pub from LINKREQUEST body) and uses it to verify.
//
// `sign` is the local sign function — pass id.Sign as a method value
// when signing as the responder (id is the destination identity), or a
// closure over the ephemeral priv when signing as the initiator.
func BuildLinkProof(linkID []byte, sign func([]byte) []byte, original *Packet) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	if sign == nil {
		return nil, errors.New("sign function is nil")
	}
	if original == nil {
		return nil, errors.New("nil original packet")
	}

	hashable, err := original.HashablePart()
	if err != nil {
		return nil, fmt.Errorf("hashable part: %w", err)
	}
	digest := sha256.Sum256(hashable)
	sig := sign(digest[:])
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("sign returned %d bytes, want %d (Ed25519 signature size)", len(sig), ed25519.SignatureSize)
	}

	// Explicit form body: packet_hash || signature
	body := make([]byte, 0, ProofBodyExplicitLen)
	body = append(body, digest[:]...)
	body = append(body, sig...)

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketProof,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextNone, // proof-ness is in packet_type, not context
		Data:            body,
	}, nil
}

// ValidateLinkProof verifies an inbound explicit-form link DATA proof
// against the remote endpoint's Ed25519 pubkey (responder pub for
// initiator-side validation, initiator pub for responder-side
// validation). Returns the 32-byte packet_hash on success.
func ValidateLinkProof(p *Packet, peerEd25519Pub []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketProof {
		return nil, fmt.Errorf("packet_type %d is not PROOF", p.PacketType)
	}
	if p.DestinationType != DestinationLink {
		return nil, fmt.Errorf("dest_type %d is not LINK", p.DestinationType)
	}
	if p.Context != ContextNone {
		return nil, fmt.Errorf("link DATA proof context = 0x%02x, want 0x00", p.Context)
	}
	if len(p.Data) != ProofBodyExplicitLen {
		return nil, fmt.Errorf("link proof must be explicit form (%d bytes), got %d", ProofBodyExplicitLen, len(p.Data))
	}
	if len(peerEd25519Pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("peer pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(peerEd25519Pub))
	}

	packetHash := p.Data[:32]
	sig := p.Data[32:]
	if !ed25519.Verify(ed25519.PublicKey(peerEd25519Pub), packetHash, sig) {
		return nil, errors.New("link proof signature invalid")
	}
	return append([]byte(nil), packetHash...), nil
}

// Context byte for KEEPALIVE on a link (SPEC §6 / RNS source).
const ContextKeepalive = 0xFA

// Context byte for LRRTT (link-request round-trip time measurement).
// Sent by the initiator to the responder immediately after validating the
// LRPROOF; carries the measured round-trip time as a msgpack-packed
// float. The responder uses receipt of this packet as the trigger to
// transition its link from HANDSHAKE to ACTIVE — which is what fires the
// destination's link_established_callback (e.g. LXMRouter sets
// resource_strategy=ACCEPT_APP only at that moment). Without LRRTT, the
// responder silently drops Resource ADV / link DATA because its
// resource_strategy is still default ACCEPT_NONE. Upstream:
// RNS/Link.py:440-442 (initiator send) + 534-553 (responder activate).
const ContextLRRTT = 0xFE

// BuildLinkKeepalive builds a small DATA packet with context=KEEPALIVE
// addressed to the link, used to refresh the activity timer at both
// ends. Body is a single 0x00 byte (matches upstream RNS, which sends
// `bytes([0x00])` as the keepalive payload).
func BuildLinkKeepalive(linkID []byte) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextKeepalive,
		Data:            []byte{0x00},
	}, nil
}

// BuildLinkRTT builds the LRRTT packet the initiator sends to the
// responder right after the link transitions to Active on the
// initiator's side. Body is a msgpack-packed float64 carrying the
// measured RTT in seconds. The responder takes max(its own measurement,
// our reported value) — so a small estimate here is fine; the value
// matters less than the act of sending it (which triggers the
// responder's link_established_callback).
func BuildLinkRTT(linkID, signing, encryption []byte, rttSeconds float64) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	body, err := msgpackMarshalFloat64(rttSeconds)
	if err != nil {
		return nil, fmt.Errorf("rtt msgpack: %w", err)
	}
	ciphertext, err := LinkTokenEncrypt(body, signing, encryption)
	if err != nil {
		return nil, fmt.Errorf("rtt encrypt: %w", err)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextLRRTT,
		Data:            ciphertext,
	}, nil
}

// BuildLinkIdentify constructs the SPEC §6.6 LINKIDENTIFY packet an
// initiator emits on an Active link to prove which identity (and
// therefore which destination) it's driving the link from. Plaintext
// before link-DATA encryption is:
//
//	identity_hash(16) || ed25519_signature(64)
//
// where the signature covers (link_id(16) || identity.public_key(64)).
// The responder verifies the signature against the identity's known
// Ed25519 public key (looked up from the announce table by
// identity_hash) and caches the identity (and the matching destination)
// on the session, so asynchronous follow-up traffic — most importantly
// tap-back reactions on a relayed group bubble — gets routed back
// through the initiator's destination rather than to some peer hash
// the receiving app inferred from the LXMF body.
//
// `id` is the LOCAL endpoint's long-term identity; it signs. The link's
// session signing/encryption keys protect the wire bytes.
func BuildLinkIdentify(linkID []byte, signing, encryption []byte, id *Identity) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	if id == nil {
		return nil, errors.New("nil identity")
	}
	pubkey := id.PublicKey()
	signedData := make([]byte, 0, len(linkID)+len(pubkey))
	signedData = append(signedData, linkID...)
	signedData = append(signedData, pubkey...)
	sig := id.Sign(signedData)
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("identity sign returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	plaintext := make([]byte, 0, IdentityHashLen+len(sig))
	plaintext = append(plaintext, id.Hash()...)
	plaintext = append(plaintext, sig...)

	ciphertext, err := LinkTokenEncrypt(plaintext, signing, encryption)
	if err != nil {
		return nil, fmt.Errorf("link encrypt: %w", err)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextLinkIdentify,
		Data:            ciphertext,
	}, nil
}

// msgpackMarshalFloat64 packs a single float64 in msgpack format —
// emits one float64 marker byte (0xCB) followed by big-endian IEEE 754
// double. Matches upstream `umsgpack.packb(rtt)` output for a Python
// float, which is what the responder unpacks via umsgpack.unpackb at
// RNS/Link.py:539.
func msgpackMarshalFloat64(v float64) ([]byte, error) {
	bits := math.Float64bits(v)
	out := make([]byte, 9)
	out[0] = 0xCB
	out[1] = byte(bits >> 56)
	out[2] = byte(bits >> 48)
	out[3] = byte(bits >> 40)
	out[4] = byte(bits >> 32)
	out[5] = byte(bits >> 24)
	out[6] = byte(bits >> 16)
	out[7] = byte(bits >> 8)
	out[8] = byte(bits)
	return out, nil
}
