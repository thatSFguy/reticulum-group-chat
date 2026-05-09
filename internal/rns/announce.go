package rns

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// safeUnmarshalAnnounce wraps msgpack.Unmarshal for inbound
// attacker-controlled announce app_data. Centralised here so a future
// stricter cap (e.g. switching msgpack libraries) lands in one place.
// vmihailenco/msgpack/v5's built-in allocation limit already bounds
// memory during a single decode, which is the practical defense
// against decoder bombs.
func safeUnmarshalAnnounce(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}

// Announce wire body (SPEC §4.1):
//
//	public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub(32)] || signature(64) || app_data
//
// signed_data over which the Ed25519 signature is computed (SPEC §4.2):
//
//	dest_hash(16) || public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub] || app_data
//
// dest_hash comes from the OUTER packet header, not the announce body.
// ratchet_pub is empty bytes (b"") — not absent — in signed_data when
// context_flag == 0.
const (
	announceMinNoRatchet = PublicKeyLen + NameHashLen + 10 + 64 // 148
	announceMinWithRatch = announceMinNoRatchet + 32            // 180
	ratchetPubLen        = 32
	announceSigLen       = 64
	randomHashLen        = 10
)

// Announce is a parsed and validated (or unvalidated) announce.
type Announce struct {
	DestHash    []byte // from outer packet header (16 bytes)
	PublicKey   []byte // 64 bytes
	NameHash    []byte // 10 bytes
	RandomHash  []byte // 10 bytes
	RatchetPub  []byte // 32 bytes when context_flag == 1, nil otherwise
	Signature   []byte // 64 bytes
	AppData     []byte // may be empty
	ContextFlag bool
	Hops        byte

	// TransportID is the next-hop transport node's identity hash, taken
	// from the outer packet header when the announce arrived as HEADER_2
	// (i.e. the announcer is multiple hops away and the announce was
	// relayed). Nil for HEADER_1 announces from direct neighbors. When
	// non-nil, callers should use HEADER_2 with this transport_id when
	// sending DATA back to the announcer's destination, per SPEC §2.3.
	TransportID []byte
}

// EmittedAt returns the timestamp half of random_hash decoded as a unix-time
// seconds value (SPEC §4.1).
func (a *Announce) EmittedAt() (time.Time, error) {
	if len(a.RandomHash) != randomHashLen {
		return time.Time{}, fmt.Errorf("random_hash must be %d bytes, got %d", randomHashLen, len(a.RandomHash))
	}
	secs, err := DecodeBigEndianUint40(a.RandomHash[5:])
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(secs), 0), nil
}

// BuildAnnounce constructs and signs a new announce for `fullName` (e.g.
// "lxmf.delivery"), wraps it in a HEADER_1 ANNOUNCE packet, and returns
// the packet ready for transmission.
//
// `appData` is the application-defined payload (for an LXMF delivery
// destination, build it via EncodeLXMFAppData). Pass nil for none.
//
// `ratchetPub`, if non-nil, MUST be 32 bytes and turns on context_flag.
// Pass nil to omit (recommended for the first-cut implementation —
// SPEC §7.3 ratchet rotation is deferred).
//
// The packet's Context is ContextNone (regular announce). To produce a
// path-response announce (SPEC §7.2, context = ContextPathResponse),
// call BuildAnnounceWithContext.
func BuildAnnounce(id *Identity, fullName string, appData []byte, ratchetPub []byte) (*Packet, error) {
	return BuildAnnounceWithContext(id, fullName, appData, ratchetPub, ContextNone)
}

// BuildAnnounceWithContext is BuildAnnounce with an explicit context
// byte. Used by the Transport's path-request responder to emit
// path-response announces (context = 0x0B) — same body bytes as a
// regular announce so any signature-verifying client can validate
// either form.
func BuildAnnounceWithContext(id *Identity, fullName string, appData []byte, ratchetPub []byte, context byte) (*Packet, error) {
	return buildAnnounce(id, fullName, appData, ratchetPub, context, time.Now, randReader)
}

// buildAnnounce is the testable form: the clock and randomness source are
// injected so tests can produce deterministic announces.
func buildAnnounce(
	id *Identity,
	fullName string,
	appData []byte,
	ratchetPub []byte,
	context byte,
	now func() time.Time,
	rnd func(p []byte) (int, error),
) (*Packet, error) {
	if id == nil {
		return nil, errors.New("nil identity")
	}
	if ratchetPub != nil && len(ratchetPub) != ratchetPubLen {
		return nil, fmt.Errorf("ratchet_pub must be %d bytes, got %d", ratchetPubLen, len(ratchetPub))
	}

	nameHash := NameHash(fullName)
	destHash := DestinationHash(nameHash, id.Hash())

	// random_hash = 5 random || 5 BE uint40 unix seconds
	rh := make([]byte, randomHashLen)
	if _, err := rnd(rh[:5]); err != nil {
		return nil, fmt.Errorf("random_hash entropy: %w", err)
	}
	ts := BigEndianUint40(uint64(now().Unix()))
	copy(rh[5:], ts[:])

	signedData := buildAnnounceSignedData(destHash, id.PublicKey(), nameHash, rh, ratchetPub, appData)
	sig := id.Sign(signedData)

	// Assemble wire body: pubkey || name_hash || random_hash || [ratchet] || sig || app_data
	bodyLen := announceMinNoRatchet + len(appData)
	if ratchetPub != nil {
		bodyLen += ratchetPubLen
	}
	body := make([]byte, 0, bodyLen)
	body = append(body, id.PublicKey()...)
	body = append(body, nameHash...)
	body = append(body, rh...)
	if ratchetPub != nil {
		body = append(body, ratchetPub...)
	}
	body = append(body, sig...)
	body = append(body, appData...)

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     ratchetPub != nil,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketAnnounce,
		Hops:            0,
		DestHash:        destHash,
		Context:         context,
		Data:            body,
	}, nil
}

// ParseAnnounce extracts the announce body from a packet (whose
// PacketType MUST be PacketAnnounce). The returned Announce is NOT yet
// signature-verified — call Verify() before trusting any fields.
func ParseAnnounce(p *Packet) (*Announce, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketAnnounce {
		return nil, fmt.Errorf("packet_type %d is not ANNOUNCE", p.PacketType)
	}
	body := p.Data

	a := &Announce{
		DestHash:    p.DestHash,
		ContextFlag: p.ContextFlag,
		Hops:        p.Hops,
		TransportID: p.TransportID,
	}

	if p.ContextFlag {
		if len(body) < announceMinWithRatch {
			return nil, fmt.Errorf("announce body too short for ratchet form: %d", len(body))
		}
		a.PublicKey = body[0:PublicKeyLen]
		a.NameHash = body[PublicKeyLen : PublicKeyLen+NameHashLen]
		a.RandomHash = body[PublicKeyLen+NameHashLen : PublicKeyLen+NameHashLen+randomHashLen]
		a.RatchetPub = body[PublicKeyLen+NameHashLen+randomHashLen : PublicKeyLen+NameHashLen+randomHashLen+ratchetPubLen]
		sigStart := PublicKeyLen + NameHashLen + randomHashLen + ratchetPubLen
		a.Signature = body[sigStart : sigStart+announceSigLen]
		a.AppData = body[sigStart+announceSigLen:]
	} else {
		if len(body) < announceMinNoRatchet {
			return nil, fmt.Errorf("announce body too short: %d", len(body))
		}
		a.PublicKey = body[0:PublicKeyLen]
		a.NameHash = body[PublicKeyLen : PublicKeyLen+NameHashLen]
		a.RandomHash = body[PublicKeyLen+NameHashLen : PublicKeyLen+NameHashLen+randomHashLen]
		sigStart := PublicKeyLen + NameHashLen + randomHashLen
		a.Signature = body[sigStart : sigStart+announceSigLen]
		a.AppData = body[sigStart+announceSigLen:]
	}
	return a, nil
}

// Verify performs SPEC §4.5 steps 2 + 3: signature verification and
// destination-hash recomputation. Returns nil iff the announce is valid.
func (a *Announce) Verify() error {
	if len(a.PublicKey) != PublicKeyLen || len(a.Signature) != announceSigLen {
		return errors.New("announce: malformed pubkey or signature length")
	}

	signed := buildAnnounceSignedData(a.DestHash, a.PublicKey, a.NameHash, a.RandomHash, a.RatchetPub, a.AppData)
	ed25519Pub := a.PublicKey[32:]
	if !Validate(ed25519Pub, signed, a.Signature) {
		return errors.New("announce: Ed25519 signature invalid")
	}

	idHash := sha256.Sum256(a.PublicKey)
	expected := DestinationHash(a.NameHash, idHash[:IdentityHashLen])
	if !bytesEqual(expected, a.DestHash) {
		return fmt.Errorf("announce: destination_hash mismatch (got %x, derived %x)", a.DestHash, expected)
	}
	return nil
}

func buildAnnounceSignedData(destHash, pubKey, nameHash, randomHash, ratchetPub, appData []byte) []byte {
	out := make([]byte, 0, len(destHash)+len(pubKey)+len(nameHash)+len(randomHash)+len(ratchetPub)+len(appData))
	out = append(out, destHash...)
	out = append(out, pubKey...)
	out = append(out, nameHash...)
	out = append(out, randomHash...)
	out = append(out, ratchetPub...) // empty when context_flag == 0
	out = append(out, appData...)
	return out
}

// EncodeLXMFAppData builds the msgpack app_data blob for an lxmf.delivery
// announce per SPEC §4.3:
//
//	[display_name_bytes (msgpack bin), stamp_cost (int or nil)]
//
// display_name MUST be encoded as msgpack `bin` type — encoders that
// emit msgpack `str` will produce app_data that upstream parsers reject
// (SPEC §9.3).
func EncodeLXMFAppData(displayName []byte, stampCost *int) ([]byte, error) {
	// vmihailenco/msgpack/v5 encodes Go []byte as msgpack bin and Go nil
	// as msgpack nil, which is exactly what we want.
	var stampField any
	if stampCost != nil {
		stampField = *stampCost
	}
	// The slice element type must be `any` so the encoder picks per-element
	// types instead of an array-typed homogeneous encoding.
	return msgpack.Marshal([]any{displayName, stampField})
}

// DecodeLXMFAppDataDisplayName extracts the display_name from an LXMF
// announce app_data. Tolerant of:
//   - 1-element msgpack array [bin]
//   - 2-element msgpack array [bin, stamp_cost]
//   - 3-element msgpack array [bin, stamp_cost, capability_flags]
//   - raw UTF-8 string (legacy "original announce format" — SPEC §4.3)
//
// Returns nil display_name + nil error if app_data is empty.
func DecodeLXMFAppDataDisplayName(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Try msgpack array first.
	var arr []msgpack.RawMessage
	if err := safeUnmarshalAnnounce(data, &arr); err == nil && len(arr) >= 1 {
		var name []byte
		// Element 0 may be bin (preferred) or str.
		if uerr := safeUnmarshalAnnounce(arr[0], &name); uerr == nil {
			return name, nil
		}
		var nameStr string
		if uerr := safeUnmarshalAnnounce(arr[0], &nameStr); uerr == nil {
			return []byte(nameStr), nil
		}
		return nil, errors.New("app_data: first element neither bin nor str")
	}
	// Fall back to legacy raw-UTF8 form.
	return data, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// randReader is the production randomness source; tests inject deterministic
// alternatives.
func randReader(p []byte) (int, error) { return rand.Read(p) }
