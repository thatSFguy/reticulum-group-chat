// Package lxmf is a minimal-viable LXMF implementation built on top of the
// pure-Go rns package. It implements opportunistic single-packet delivery
// (SPEC §5.1) — direct (Link) delivery, propagation nodes, stamps, and
// tickets are intentionally out of scope.
package lxmf

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

// safeUnmarshal wraps msgpack.Unmarshal for inbound attacker-controlled
// payloads. All receive-path decodes route through this; today it is a
// thin wrapper because vmihailenco/msgpack/v5's default allocation
// limit (see Decoder.DisableAllocLimit) already caps memory during a
// single decode, which is the load-bearing defense against decoder
// bombs. If we ever swap msgpack libraries or want a stricter cap we
// have one place to change.
func safeUnmarshal(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}

// LXMF wire constants (SPEC §5).
const (
	signatureLen = 64

	// Opportunistic body = source_hash(16) || signature(64) || msgpack_payload
	// (the recipient's dest_hash is in the outer Reticulum packet header
	// and is omitted from the body itself).
	minOpportunisticBodyLen = rns.IdentityHashLen + signatureLen

	// MaxOpportunisticPayload is the upstream LXMF limit on the msgpack
	// payload size for a single-packet opportunistic LXMF message,
	// matching LXMessage.ENCRYPTED_PACKET_MAX_CONTENT in upstream Python
	// LXMF 0.9.6. Larger messages downgrade to link-based delivery in
	// upstream — which we don't implement yet — so we surface
	// ErrPayloadTooLarge instead.
	MaxOpportunisticPayload = 295
)

// ErrPayloadTooLarge is returned by SignAndPackOpportunistic / Delivery.Send
// when the msgpack payload would exceed MaxOpportunisticPayload. Callers can
// catch it with errors.Is to provide structured feedback (e.g. tell the
// original sender their message was too long for single-packet relay).
var ErrPayloadTooLarge = errors.New("LXMF opportunistic payload exceeds size limit")

// AppName + AspectDelivery yield the dotted full name "lxmf.delivery"
// (SPEC §1.2 / §4.4).
const (
	AppName         = "lxmf"
	AspectDelivery  = "delivery"
)

// FullName returns "lxmf.delivery" — the well-known LXMF delivery aspect.
func FullName() string { return rns.FullName(AppName, AspectDelivery) }

// Message is a parsed LXMF message. On the send side, fill in the
// addressing + content fields and call SignAndPackOpportunistic. On the
// receive side, ParseOpportunisticBody fills it; call Verify before
// trusting Title/Content.
type Message struct {
	// Addressing.
	DestHash   []byte // recipient's destination_hash (16 bytes, from outer packet header on receive)
	SourceHash []byte // sender's destination_hash (NOT identity hash — SPEC §5.4)

	// Crypto.
	Signature []byte // 64 bytes Ed25519

	// Payload — the four logical msgpack array elements (SPEC §5.3).
	Timestamp time.Time
	Title     []byte
	Content   []byte
	Fields    map[any]any // usually empty {}

	// Stamp (optional 5th msgpack element; SPEC §5.7).
	Stamp []byte

	// rawPayload preserves the exact msgpack bytes as received, for use in
	// Verify per the SPEC §5.6 dual-variant tolerance rule.
	rawPayload []byte
}

// SignAndPackOpportunistic builds the opportunistic LXMF body bytes that
// go inside the Token-encrypted Reticulum DATA packet.
//
//	wire = source_hash(16) || signature(64) || msgpack_payload
//
// destHash is the recipient's destination_hash; senderID signs.
// senderDestHash is the SENDER's destination_hash (NOT the identity hash
// — SPEC §5.4). title may be nil. content may be nil but typically isn't.
// fields may be nil (encoded as an empty msgpack map). The returned
// msgID is the 32-byte LXMF message_id the recipient will compute when
// they parse this body — used by the forwarder to register per-recipient
// IDs for cross-client reaction / reply rewriting.
func SignAndPackOpportunistic(senderID *rns.Identity, senderDestHash, destHash []byte, title, content []byte, fields map[any]any) (wire, msgID []byte, err error) {
	return signAndPackOpportunisticAt(senderID, senderDestHash, destHash, title, content, fields, time.Now())
}

// SignAndPackDirect builds the link-form (direct) LXMF body bytes for
// transmission inside a Reticulum Link DATA packet (SPEC §5.2):
//
//	destination_hash(16) || source_hash(16) || signature(64) || msgpack_payload
//
// Unlike SignAndPackOpportunistic, the body includes the destination
// hash (the outer packet is addressed to a link_id, not the recipient's
// destination). No size cap is enforced here — link DATA can carry
// arbitrary-size payloads, fragmented by the link layer.
func SignAndPackDirect(senderID *rns.Identity, senderDestHash, destHash []byte, title, content []byte, fields map[any]any) (wire, msgID []byte, err error) {
	return signAndPackDirectAt(senderID, senderDestHash, destHash, title, content, fields, time.Now())
}

func signAndPackDirectAt(senderID *rns.Identity, senderDestHash, destHash []byte, title, content []byte, fields map[any]any, ts time.Time) (wire, msgID []byte, err error) {
	if senderID == nil {
		return nil, nil, errors.New("nil sender identity")
	}
	if len(senderDestHash) != rns.IdentityHashLen || len(destHash) != rns.IdentityHashLen {
		return nil, nil, errors.New("dest_hash and source_hash must each be 16 bytes")
	}
	if title == nil {
		title = []byte{}
	}
	if content == nil {
		content = []byte{}
	}
	if fields == nil {
		fields = map[any]any{}
	}

	tsSeconds := float64(ts.UnixMicro()) / 1_000_000.0
	payload, err := msgpack.Marshal([]any{tsSeconds, title, content, fields})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal payload: %w", err)
	}
	signedData, id := buildSignedDataWithID(destHash, senderDestHash, payload)
	sig := senderID.Sign(signedData)

	out := make([]byte, 0, 2*rns.IdentityHashLen+len(sig)+len(payload))
	out = append(out, destHash...)
	out = append(out, senderDestHash...)
	out = append(out, sig...)
	out = append(out, payload...)
	return out, id, nil
}

// signAndPackOpportunisticAt is the testable form: timestamp is injected
// rather than read from the wall clock, so deterministic test vectors
// (which pin the timestamp) can be reproduced exactly. The returned
// msgID is the recipient-view LXMF message_id (independent of signature
// — it's just H(dest||source||payload)).
func signAndPackOpportunisticAt(senderID *rns.Identity, senderDestHash, destHash []byte, title, content []byte, fields map[any]any, ts time.Time) (wire, msgID []byte, err error) {
	if senderID == nil {
		return nil, nil, errors.New("nil sender identity")
	}
	if len(senderDestHash) != rns.IdentityHashLen || len(destHash) != rns.IdentityHashLen {
		return nil, nil, errors.New("dest_hash and source_hash must each be 16 bytes")
	}
	if title == nil {
		title = []byte{}
	}
	if content == nil {
		content = []byte{}
	}
	if fields == nil {
		fields = map[any]any{}
	}

	tsSeconds := float64(ts.UnixMicro()) / 1_000_000.0
	payload, err := msgpack.Marshal([]any{tsSeconds, title, content, fields})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal payload: %w", err)
	}
	if len(payload) > MaxOpportunisticPayload {
		return nil, nil, fmt.Errorf("%w: msgpack payload is %d bytes, limit is %d (link-based delivery for larger messages is not implemented)",
			ErrPayloadTooLarge, len(payload), MaxOpportunisticPayload)
	}

	signedData, id := buildSignedDataWithID(destHash, senderDestHash, payload)
	sig := senderID.Sign(signedData)

	out := make([]byte, 0, len(senderDestHash)+len(sig)+len(payload))
	out = append(out, senderDestHash...)
	out = append(out, sig...)
	out = append(out, payload...)
	return out, id, nil
}

// ParseDirectBody decodes the link-form LXMF body (SPEC §5.2):
//
//	destination_hash(16) || source_hash(16) || signature(64) || msgpack_payload
//
// Unlike opportunistic, the dest_hash is in the body (the outer Reticulum
// packet is addressed to a link_id, not the recipient's destination_hash).
// The returned Message can be Verify()'d the same way as opportunistic.
func ParseDirectBody(body []byte) (*Message, error) {
	const minDirectBodyLen = 2*rns.IdentityHashLen + signatureLen
	if len(body) < minDirectBodyLen {
		return nil, fmt.Errorf("direct body too short: %d", len(body))
	}
	m := &Message{
		DestHash:   body[:rns.IdentityHashLen],
		SourceHash: body[rns.IdentityHashLen : 2*rns.IdentityHashLen],
		Signature:  body[2*rns.IdentityHashLen : 2*rns.IdentityHashLen+signatureLen],
		rawPayload: body[2*rns.IdentityHashLen+signatureLen:],
	}
	if err := m.unpackPayload(); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseOpportunisticBody decodes the LXMF body bytes (without dest_hash).
// destHash MUST come from the outer Reticulum packet header — passing the
// raw body bytes alone would let a malicious sender forge sigs against
// arbitrary destinations.
func ParseOpportunisticBody(body, destHash []byte) (*Message, error) {
	if len(body) < minOpportunisticBodyLen {
		return nil, fmt.Errorf("opportunistic body too short: %d", len(body))
	}
	if len(destHash) != rns.IdentityHashLen {
		return nil, fmt.Errorf("dest_hash must be %d bytes, got %d", rns.IdentityHashLen, len(destHash))
	}

	m := &Message{
		DestHash:   destHash,
		SourceHash: body[:rns.IdentityHashLen],
		Signature:  body[rns.IdentityHashLen : rns.IdentityHashLen+signatureLen],
		rawPayload: body[rns.IdentityHashLen+signatureLen:],
	}

	if err := m.unpackPayload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Verify checks the Ed25519 signature using the SPEC §5.6 dual-variant rule:
// try the raw msgpack bytes first; if that fails AND the payload had an
// optional 5th element (stamp), retry with a stripped+re-encoded 4-element
// msgpack. Returns nil on success.
func (m *Message) Verify(senderEd25519Pub []byte) error {
	if len(senderEd25519Pub) != ed25519.PublicKeySize {
		return errors.New("sender Ed25519 public must be 32 bytes")
	}

	// Variant 1: raw bytes as-received.
	signedData := buildSignedData(m.DestHash, m.SourceHash, m.rawPayload)
	if rns.Validate(senderEd25519Pub, signedData, m.Signature) {
		return nil
	}

	// Variant 2: strip optional 5th element (stamp) and re-encode the
	// first 4. Only attempt if a stamp was actually present.
	if m.Stamp == nil {
		return errors.New("LXMF signature invalid")
	}
	stripped, err := reencodeFirstFour(m.rawPayload)
	if err != nil {
		return fmt.Errorf("strip stamp re-encode: %w", err)
	}
	signedData = buildSignedData(m.DestHash, m.SourceHash, stripped)
	if rns.Validate(senderEd25519Pub, signedData, m.Signature) {
		return nil
	}
	return errors.New("LXMF signature invalid (both raw and stamp-stripped variants)")
}

// CheckOpportunisticSize returns nil if a SignAndPackOpportunistic call with
// these inputs would fit in a single Reticulum DATA packet, or an error
// wrapping ErrPayloadTooLarge if not. It does the msgpack marshal but no
// crypto and no network I/O — safe to call as a pre-check before iterating
// recipients.
func CheckOpportunisticSize(title, content []byte, fields map[any]any) error {
	if title == nil {
		title = []byte{}
	}
	if content == nil {
		content = []byte{}
	}
	if fields == nil {
		fields = map[any]any{}
	}
	payload, err := msgpack.Marshal([]any{0.0, title, content, fields})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(payload) > MaxOpportunisticPayload {
		return fmt.Errorf("%w: msgpack payload is %d bytes, limit is %d",
			ErrPayloadTooLarge, len(payload), MaxOpportunisticPayload)
	}
	return nil
}

func buildSignedData(destHash, sourceHash, msgpackPayload []byte) []byte {
	signedData, _ := buildSignedDataWithID(destHash, sourceHash, msgpackPayload)
	return signedData
}

// buildSignedDataWithID is buildSignedData but also returns the 32-byte
// SHA-256 hash inserted between hashedPart and the signature input — that
// hash IS the LXMF message_id (SPEC §5.4: H(dest||source||payload)). Two
// callers want both pieces; everyone else just calls buildSignedData.
func buildSignedDataWithID(destHash, sourceHash, msgpackPayload []byte) (signedData, msgID []byte) {
	hashedPart := make([]byte, 0, len(destHash)+len(sourceHash)+len(msgpackPayload))
	hashedPart = append(hashedPart, destHash...)
	hashedPart = append(hashedPart, sourceHash...)
	hashedPart = append(hashedPart, msgpackPayload...)
	mh := sha256.Sum256(hashedPart)
	out := make([]byte, 0, len(hashedPart)+len(mh))
	out = append(out, hashedPart...)
	out = append(out, mh[:]...)
	return out, append([]byte(nil), mh[:]...)
}

// ComputeMessageID returns the LXMF message_id for a given (dest_hash,
// source_hash, msgpack_payload) tuple — SPEC §5.4 defines it as
// SHA-256(dest_hash || source_hash || msgpack_payload). Used by the
// forwarding service to register per-recipient message_ids in the
// id-rewrite cache without re-packing the body.
func ComputeMessageID(destHash, sourceHash, msgpackPayload []byte) []byte {
	mh := sha256.Sum256(append(append(append([]byte{}, destHash...), sourceHash...), msgpackPayload...))
	return mh[:]
}

// MessageID returns the LXMF message_id (32 bytes, SPEC §5.4) for a
// parsed inbound message. Only valid after a successful Parse; Verify is
// not required, since message_id is independent of the signature.
func (m *Message) MessageID() []byte {
	return ComputeMessageID(m.DestHash, m.SourceHash, m.rawPayload)
}

// msgpackNil is the msgpack format byte for nil (0xc0).
const msgpackNil = 0xc0

// decodeFields decodes the LXMF "fields" payload element into a
// map[any]any with interface-keyed maps at EVERY nesting level.
//
// The default msgpack interface-map decoder produces
// map[string]interface{} for nested map *values*, which rejects the
// integer-keyed inner dicts that FIELD_REACTION (0x40), FIELD_COMMENT
// (0x41), and FIELD_CONTINUATION (0x42) use: it fails with "invalid
// code=0 decoding string/bytes length" the moment it hits inner key
// 0x00, and the whole message is dropped before it ever reaches the
// relay logic. (Top-level reply-to 0x30 raw bytes and image arrays
// decode fine, which is why only reactions/comments/continuations
// vanished.) Wiring DecodeUntypedMap in as the map decoder makes every
// level decode into map[any]any regardless of key type.
func decodeFields(raw []byte) (map[any]any, error) {
	// msgpack nil → no fields (tolerated like an empty map).
	if len(raw) == 1 && raw[0] == msgpackNil {
		return nil, nil
	}
	dec := msgpack.NewDecoder(bytes.NewReader(raw))
	dec.SetMapDecoder(func(d *msgpack.Decoder) (interface{}, error) {
		return d.DecodeUntypedMap()
	})
	return dec.DecodeUntypedMap()
}

// unpackPayload extracts Timestamp/Title/Content/Fields/Stamp from rawPayload.
func (m *Message) unpackPayload() error {
	var elems []msgpack.RawMessage
	if err := safeUnmarshal(m.rawPayload, &elems); err != nil {
		return fmt.Errorf("decode payload array: %w", err)
	}
	if len(elems) < 4 {
		return fmt.Errorf("payload has %d elements, need at least 4", len(elems))
	}

	var tsSeconds float64
	if err := safeUnmarshal(elems[0], &tsSeconds); err != nil {
		return fmt.Errorf("decode timestamp: %w", err)
	}
	whole, frac := splitSeconds(tsSeconds)
	m.Timestamp = time.Unix(whole, frac).UTC()

	if err := safeUnmarshal(elems[1], &m.Title); err != nil {
		// Tolerate msgpack str — some implementations write title as str.
		var titleStr string
		if err2 := safeUnmarshal(elems[1], &titleStr); err2 == nil {
			m.Title = []byte(titleStr)
		} else {
			return fmt.Errorf("decode title: %w", err)
		}
	}
	if err := safeUnmarshal(elems[2], &m.Content); err != nil {
		var contentStr string
		if err2 := safeUnmarshal(elems[2], &contentStr); err2 == nil {
			m.Content = []byte(contentStr)
		} else {
			return fmt.Errorf("decode content: %w", err)
		}
	}
	fields, err := decodeFields(elems[3])
	if err != nil {
		return fmt.Errorf("decode fields: %w", err)
	}
	m.Fields = fields
	if len(elems) >= 5 {
		_ = safeUnmarshal(elems[4], &m.Stamp) // best-effort; stamp is optional
	}
	return nil
}

// reencodeFirstFour decodes the msgpack array, drops everything past
// element [3], and re-encodes — used to strip an optional stamp before
// signature verification (SPEC §5.6).
func reencodeFirstFour(payload []byte) ([]byte, error) {
	var elems []msgpack.RawMessage
	if err := safeUnmarshal(payload, &elems); err != nil {
		return nil, err
	}
	if len(elems) < 4 {
		return nil, errors.New("payload has fewer than 4 elements")
	}
	first4 := make([]any, 4)
	for i := 0; i < 4; i++ {
		var raw any
		if err := safeUnmarshal(elems[i], &raw); err != nil {
			return nil, err
		}
		first4[i] = raw
	}
	return msgpack.Marshal(first4)
}

func splitSeconds(secs float64) (whole int64, nanos int64) {
	w := int64(secs)
	frac := secs - float64(w)
	if frac < 0 {
		frac = 0
	}
	return w, int64(frac * 1e9)
}
