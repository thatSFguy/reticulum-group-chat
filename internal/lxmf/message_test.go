package lxmf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

func TestSignParseVerifyRoundTrip(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()

	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, msgID, err := SignAndPackOpportunistic(
		sender, senderDest, recipientDest,
		[]byte(""),
		[]byte("hello world"),
		nil,
	)
	if err != nil {
		t.Fatalf("SignAndPackOpportunistic: %v", err)
	}
	if len(msgID) != 32 {
		t.Errorf("msgID length = %d, want 32", len(msgID))
	}

	m, err := ParseOpportunisticBody(body, recipientDest)
	if err != nil {
		t.Fatalf("ParseOpportunisticBody: %v", err)
	}
	if !bytes.Equal(m.SourceHash, senderDest) {
		t.Errorf("source_hash mismatch")
	}
	if string(m.Content) != "hello world" {
		t.Errorf("content = %q, want %q", m.Content, "hello world")
	}

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestParseDecodesNestedIntKeyedReactionFields is the regression guard
// for the dropped-reaction bug: a FIELD_REACTION (0x40) carries a nested
// integer-keyed dict {0x00: raw msgid, 0x01: emoji}. The default msgpack
// interface-map decoder decodes nested map values as map[string]any and
// chokes on the integer keys ("invalid code=0 decoding string/bytes
// length"), dropping the whole message before it reaches the relay. This
// round-trips the exact wire shape a client emits and asserts the inner
// dict survives parse with its integer keys intact.
func TestParseDecodesNestedIntKeyedReactionFields(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	target := bytes.Repeat([]byte{0xAB}, 32)
	fields := map[any]any{
		0x40: map[any]any{ // FIELD_REACTION
			0x00: target,      // REACTION_TO (raw 32B)
			0x01: []byte("👍"), // REACTION_CONTENT
		},
	}

	// Reactions carry empty content; the field map is the payload.
	body, _, err := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, nil, fields)
	if err != nil {
		t.Fatalf("SignAndPackOpportunistic: %v", err)
	}

	m, err := ParseOpportunisticBody(body, recipientDest)
	if err != nil {
		t.Fatalf("ParseOpportunisticBody (this failed before the fix): %v", err)
	}

	// Keys may decode as int8/int64/etc depending on value; look them up
	// tolerantly, exactly as the relay does via keyAsInt.
	reactV, ok := fieldByInt(m.Fields, 0x40)
	if !ok {
		t.Fatalf("fields has no 0x40; full fields=%#v", m.Fields)
	}
	react, ok := reactV.(map[any]any)
	if !ok {
		t.Fatalf("fields[0x40] = %T, want map[any]any", reactV)
	}
	to, _ := fieldByInt(react, 0x00)
	if got, _ := to.([]byte); !bytes.Equal(got, target) {
		t.Errorf("REACTION_TO = %x, want %x", got, target)
	}
	content, _ := fieldByInt(react, 0x01)
	if c, _ := content.([]byte); string(c) != "👍" {
		t.Errorf("REACTION_CONTENT = %q, want 👍", c)
	}
}

// fieldByInt looks up a map[any]any entry by integer value, tolerating
// whatever integer width the msgpack decoder produced for the key.
func fieldByInt(m map[any]any, want int) (any, bool) {
	for k, v := range m {
		var got int
		switch n := k.(type) {
		case int:
			got = n
		case int8:
			got = int(n)
		case int16:
			got = int(n)
		case int32:
			got = int(n)
		case int64:
			got = int(n)
		case uint:
			got = int(n)
		case uint8:
			got = int(n)
		case uint16:
			got = int(n)
		case uint32:
			got = int(n)
		case uint64:
			got = int(n)
		default:
			continue
		}
		if got == want {
			return v, true
		}
	}
	return nil, false
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, _, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hello"), nil)
	m, _ := ParseOpportunisticBody(body, recipientDest)

	// Tamper directly with the rawPayload bytes (preserved on the message).
	m.rawPayload = append([]byte(nil), m.rawPayload...)
	m.rawPayload[len(m.rawPayload)-1] ^= 0x01

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err == nil {
		t.Error("Verify accepted tampered payload")
	}
}

func TestVerifyRejectsForgedDestHash(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, _, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hello"), nil)

	bogusDest := bytes.Repeat([]byte{0xAA}, rns.IdentityHashLen)
	m, _ := ParseOpportunisticBody(body, bogusDest)
	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err == nil {
		t.Error("Verify accepted forged dest_hash")
	}
}

func TestVerifyAcceptsStampStrippedVariant(t *testing.T) {
	// Simulate a sender that signed over a 4-element payload, then
	// appended a stamp as element [4]. Receiver must strip and re-verify.
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	// Step 1: produce a normal 4-element body and capture its msgpack payload.
	body, _, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hi"), nil)
	headerEnd := rns.IdentityHashLen + signatureLen
	source := body[:rns.IdentityHashLen]
	sig := body[rns.IdentityHashLen:headerEnd]
	payload4 := body[headerEnd:]

	// Step 2: re-encode as a 5-element msgpack with a fake stamp.
	var elems []any
	for _, e := range mustDecodeArray(t, payload4) {
		elems = append(elems, e)
	}
	stamp := bytes.Repeat([]byte{0xBE}, 32)
	elems = append(elems, stamp)
	payload5, err := msgpack.Marshal(elems)
	if err != nil {
		t.Fatal(err)
	}

	body5 := make([]byte, 0, len(source)+len(sig)+len(payload5))
	body5 = append(body5, source...)
	body5 = append(body5, sig...)
	body5 = append(body5, payload5...)

	m, err := ParseOpportunisticBody(body5, recipientDest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Stamp, stamp) {
		t.Errorf("stamp not extracted: got %x want %x", m.Stamp, stamp)
	}
	if string(m.Content) != "hi" {
		t.Errorf("content = %q, want hi", m.Content)
	}

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err != nil {
		t.Errorf("Verify with stamp-stripped variant failed: %v", err)
	}
}

func TestRoundTripPreservesTimestamp(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	before := time.Now().Truncate(time.Microsecond)
	body, _, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hi"), nil)
	after := time.Now()

	m, _ := ParseOpportunisticBody(body, recipientDest)
	if m.Timestamp.Before(before.Add(-time.Second)) || m.Timestamp.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v not within [%v, %v]", m.Timestamp, before, after)
	}
}

func TestSendRejectsOversizePayload(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	// 1 KB content is well over the 295-byte msgpack payload cap.
	huge := bytes.Repeat([]byte("x"), 1024)
	_, _, err := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, huge, nil)
	if err == nil {
		t.Fatal("expected error for oversize payload")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("error should wrap ErrPayloadTooLarge, got %v", err)
	}
}

func TestCheckOpportunisticSize(t *testing.T) {
	// Empty title + empty fields gives 16 bytes overhead with bin16 prefix
	// (1 array + 9 ts + 2 empty title + 3 bin16 content prefix + 1 fields).
	// MaxOpportunisticPayload = 295, so 295 - 16 = 279 bytes content
	// (worst-case bin16) is the boundary. bin8 (content < 256) saves 1 byte
	// of prefix, so up to 280 bytes of content can fit in that path.

	if err := CheckOpportunisticSize(nil, []byte(""), nil); err != nil {
		t.Errorf("empty content should fit: %v", err)
	}

	// 280-byte payload: msgpack uses bin16 prefix, so total payload is
	// 1 + 9 + 2 + 3 + 280 + 1 = 296 — over by one byte. Verify rejection.
	just_over := bytes.Repeat([]byte("x"), 280)
	if err := CheckOpportunisticSize(nil, just_over, nil); err == nil {
		t.Errorf("280-byte content should be rejected (uses bin16 prefix, payload = 296)")
	}

	// 255-byte payload: msgpack uses bin8 prefix (1+9+2+2+255+1 = 270),
	// well under the limit.
	bin8_max := bytes.Repeat([]byte("x"), 255)
	if err := CheckOpportunisticSize(nil, bin8_max, nil); err != nil {
		t.Errorf("255-byte content should fit (bin8): %v", err)
	}

	// 1KB: clearly too large.
	too_big := bytes.Repeat([]byte("x"), 1024)
	err := CheckOpportunisticSize(nil, too_big, nil)
	if err == nil {
		t.Fatal("1KB should be rejected")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("error should wrap ErrPayloadTooLarge, got %v", err)
	}
}

func mustDecodeArray(t *testing.T, raw []byte) []any {
	t.Helper()
	var arr []any
	if err := msgpack.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("decode array: %v", err)
	}
	return arr
}

// TestParseRejectsMsgpackBombPreVerification is the end-to-end
// regression for the remote unauthenticated OOM.
//
// The attack needs no relationship with the service: anyone can
// Token-encrypt to our announced public key, and the payload is
// msgpack-decoded here BEFORE the LXMF signature is checked (Verify is
// the caller's next step). With the pinned msgpack library's broken
// allocation limit, the 5-byte array32 header below requests ~103 GB —
// an unrecoverable Go runtime OOM that no recover() can catch.
func TestParseRejectsMsgpackBombPreVerification(t *testing.T) {
	bomb := []byte{0xdd, 0xff, 0xff, 0xff, 0xff} // array32, 2^32-1 elements

	body := make([]byte, 0, rns.IdentityHashLen+signatureLen+len(bomb))
	body = append(body, bytes.Repeat([]byte{0x11}, rns.IdentityHashLen)...) // source
	body = append(body, bytes.Repeat([]byte{0x22}, signatureLen)...)        // junk sig
	body = append(body, bomb...)

	destHash := bytes.Repeat([]byte{0x33}, rns.IdentityHashLen)
	if _, err := ParseOpportunisticBody(body, destHash); err == nil {
		t.Fatal("msgpack bomb accepted by the opportunistic parse path")
	}

	// Same body over the link (direct) form.
	direct := append(append([]byte{}, destHash...), body...)
	if _, err := ParseDirectBody(direct); err == nil {
		t.Fatal("msgpack bomb accepted by the direct parse path")
	}
}

// TestParseRejectsNestedFieldBomb covers the untyped decode path: a
// well-formed payload whose FIELDS map carries a bogus array header.
func TestParseRejectsNestedFieldBomb(t *testing.T) {
	// [ts, title, content, {6: array32(2^32-1)}] hand-assembled so the
	// bomb survives into the fields element.
	payload := []byte{0x94, 0xcb} // fixarray(4), float64 marker
	payload = append(payload, make([]byte, 8)...)
	payload = append(payload, 0xc4, 0x00) // bin8 len 0 (title)
	payload = append(payload, 0xc4, 0x00) // bin8 len 0 (content)
	payload = append(payload, 0x81, 0x06) // fixmap(1), key 6
	payload = append(payload, 0xdd, 0xff, 0xff, 0xff, 0xff)

	body := append(bytes.Repeat([]byte{0x11}, rns.IdentityHashLen),
		bytes.Repeat([]byte{0x22}, signatureLen)...)
	body = append(body, payload...)

	if _, err := ParseOpportunisticBody(body, bytes.Repeat([]byte{0x33}, rns.IdentityHashLen)); err == nil {
		t.Fatal("nested field bomb accepted")
	}
}

// TestDedupKeyIsStampInvariant is the regression for the replay bypass:
// SPEC §5.6 lets a stamp be added/changed without invalidating the
// signature, so message_id (computed over the stamp-inclusive payload)
// differs for every stamp value. Keying dedup on it let one captured
// signed body be replayed unboundedly, each copy looking new.
func TestDedupKeyIsStampInvariant(t *testing.T) {
	sender, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	destHash := bytes.Repeat([]byte{0x33}, rns.IdentityHashLen)

	body, _, err := SignAndPackOpportunistic(sender, senderDest, destHash,
		nil, []byte("replay me"), nil)
	if err != nil {
		t.Fatal(err)
	}

	base, err := ParseOpportunisticBody(body, destHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Verify(sender.PublicKey()[32:]); err != nil {
		t.Fatal(err)
	}

	// Re-encode the payload with an added 5th element (a stamp), the
	// mutation the spec explicitly tolerates.
	var elems []msgpack.RawMessage
	if err := msgpack.Unmarshal(base.rawPayload, &elems); err != nil {
		t.Fatal(err)
	}
	seenIDs := map[string]bool{}
	seenKeys := map[string]bool{}
	for _, stamp := range [][]byte{
		bytes.Repeat([]byte{0x00}, StampSize),
		bytes.Repeat([]byte{0x01}, StampSize),
		bytes.Repeat([]byte{0x02}, StampSize),
	} {
		parts := make([]any, 0, 5)
		for _, e := range elems[:4] {
			var v any
			if err := msgpack.Unmarshal(e, &v); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, v)
		}
		parts = append(parts, stamp)
		payload, err := msgpack.Marshal(parts)
		if err != nil {
			t.Fatal(err)
		}
		mutated := append(append([]byte{}, body[:rns.IdentityHashLen+signatureLen]...), payload...)

		m, err := ParseOpportunisticBody(mutated, destHash)
		if err != nil {
			t.Fatalf("stamped variant did not parse: %v", err)
		}
		// Premise: the signature still verifies under the spec's
		// stamp-stripping tolerance. That is what makes this a replay.
		if err := m.Verify(sender.PublicKey()[32:]); err != nil {
			t.Fatalf("premise broken — stamped variant should verify: %v", err)
		}
		seenIDs[hex.EncodeToString(m.MessageID())] = true
		seenKeys[hex.EncodeToString(m.DedupKey())] = true
	}

	if len(seenIDs) == 1 {
		t.Error("premise broken — message_id should differ per stamp")
	}
	if len(seenKeys) != 1 {
		t.Errorf("DedupKey produced %d distinct values across stamp variants; want 1", len(seenKeys))
	}
	// And it must match the unstamped original, so the first replay is caught.
	if hex.EncodeToString(base.DedupKey()) != firstKey(seenKeys) {
		t.Error("DedupKey of stamped variants differs from the unstamped original")
	}
}

func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}

func TestDedupKeyDiffersAcrossSenders(t *testing.T) {
	// Distinct senders must never collide, even with identical content.
	a, _ := rns.NewIdentity()
	b, _ := rns.NewIdentity()
	dest := bytes.Repeat([]byte{0x33}, rns.IdentityHashLen)

	keyFor := func(id *rns.Identity) string {
		body, _, err := SignAndPackOpportunistic(id, id.DestinationHashFor(FullName()),
			dest, nil, []byte("same text"), nil)
		if err != nil {
			t.Fatal(err)
		}
		m, err := ParseOpportunisticBody(body, dest)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(m.DedupKey())
	}
	if keyFor(a) == keyFor(b) {
		t.Error("different senders produced the same DedupKey")
	}
}

// TestVerifyStampedMessageWithIntKeyedFields is the regression for the
// variant-2 interop bug: a stamped message carrying the integer-keyed
// field maps real clients send (reply-to, reaction, image) must still
// verify. Previously reencodeFirstFour decoded with the default map
// decoder, which chokes on integer keys, so every such message was
// dropped — stamp-using senders lost all reactions, replies and images.
func TestVerifyStampedMessageWithIntKeyedFields(t *testing.T) {
	sender, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	destHash := bytes.Repeat([]byte{0x33}, rns.IdentityHashLen)

	cases := map[string]map[any]any{
		"reply-to": {0x30: bytes.Repeat([]byte{0xAB}, 32)},
		"reaction": {0x40: map[any]any{
			0x00: bytes.Repeat([]byte{0x01}, 32),
			0x01: []byte("👍"),
		}},
		"image": {0x06: []any{[]byte("png"), bytes.Repeat([]byte{0x89}, 64)}},
		"multi-key": {
			0x30: bytes.Repeat([]byte{0xCD}, 32),
			0x31: []byte("quoted text"),
			0x40: map[any]any{0x00: bytes.Repeat([]byte{0x02}, 32), 0x01: []byte("🎉")},
		},
	}

	for name, fields := range cases {
		body, _, err := SignAndPackOpportunistic(sender, senderDest, destHash,
			nil, []byte("hello"), fields)
		if err != nil {
			t.Fatalf("%s: pack: %v", name, err)
		}

		// Append a stamp as the 5th element — the mutation SPEC §5.6
		// tolerates, and what a stamp-using client actually sends.
		parsed, err := ParseOpportunisticBody(body, destHash)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		var elems []msgpack.RawMessage
		if err := msgpack.Unmarshal(parsed.rawPayload, &elems); err != nil {
			t.Fatalf("%s: split payload: %v", name, err)
		}
		stamped := []byte{0x95} // fixarray, 5 elements
		for _, e := range elems[:4] {
			stamped = append(stamped, e...)
		}
		stampBytes, _ := msgpack.Marshal(bytes.Repeat([]byte{0x7F}, StampSize))
		stamped = append(stamped, stampBytes...)

		wire := append(append([]byte{}, body[:rns.IdentityHashLen+signatureLen]...), stamped...)
		m, err := ParseOpportunisticBody(wire, destHash)
		if err != nil {
			t.Fatalf("%s: parse stamped: %v", name, err)
		}
		if m.Stamp == nil {
			t.Fatalf("%s: stamp not parsed — test setup wrong", name)
		}
		if err := m.Verify(sender.PublicKey()[32:]); err != nil {
			t.Errorf("%s: stamped message with int-keyed fields failed verification: %v", name, err)
		}
		// The fields must survive intact for forwarding.
		if len(m.Fields) != len(fields) {
			t.Errorf("%s: decoded %d fields, want %d", name, len(m.Fields), len(fields))
		}
	}
}
