package lxmf

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
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
			0x00: target,        // REACTION_TO (raw 32B)
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
