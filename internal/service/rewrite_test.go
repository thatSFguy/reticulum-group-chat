package service

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// fakeBubble implements just the ViewFor lookup the substitute helpers
// need, so we can drive them without a real idmap.Cache.
type fakeBubble struct {
	views map[string]string
}

func (b *fakeBubble) ViewFor(recipientHex string) (string, bool) {
	v, ok := b.views[recipientHex]
	return v, ok
}

func TestSubstituteReactionRewritesPerRecipient(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const aliceMsgIDHex = "deadbeef" + // dest_hash || source_hash || payload hash
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	bubble := &fakeBubble{views: map[string]string{aliceHex: aliceMsgIDHex}}

	in := map[any]any{
		16: map[any]any{
			"reaction_to": "originalsenderview",
			"emoji":       "👍",
			"sender":      "babecafe",
		},
	}

	out, ok := substituteReaction(in, aliceHex, bubble)
	if !ok {
		t.Fatal("substituteReaction returned ok=false for known recipient")
	}
	react, _ := out[16].(map[any]any)
	if react["reaction_to"] != aliceMsgIDHex {
		t.Errorf("reaction_to = %q, want %q", react["reaction_to"], aliceMsgIDHex)
	}
	if react["emoji"] != "👍" {
		t.Errorf("emoji clobbered: %q", react["emoji"])
	}
}

func TestSubstituteReactionUnknownRecipient(t *testing.T) {
	bubble := &fakeBubble{views: map[string]string{"alice": "aliceview"}}
	in := map[any]any{
		16: map[any]any{
			"reaction_to": "anything",
			"emoji":       "🔥",
		},
	}
	if _, ok := substituteReaction(in, "bob", bubble); ok {
		t.Error("substituteReaction returned ok=true for unknown recipient bob")
	}
}

func TestSubstituteReplyHashRewritesRawBytes(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliceMsgID := bytes.Repeat([]byte{0xCA, 0xFE}, 16) // 32 bytes
	aliceMsgIDHex := hex.EncodeToString(aliceMsgID)

	bubble := &fakeBubble{views: map[string]string{aliceHex: aliceMsgIDHex}}

	in := map[any]any{
		48: bytes.Repeat([]byte{0xDE, 0xAD}, 16),       // sender's view
		49: []byte("> original message quoted preview"), // text passes through
	}
	out, ok := substituteReplyHash(in, aliceHex, bubble)
	if !ok {
		t.Fatal("substituteReplyHash returned ok=false for known recipient")
	}
	got, _ := out[48].([]byte)
	if !bytes.Equal(got, aliceMsgID) {
		t.Errorf("rewritten reply hash = %x, want %x", got, aliceMsgID)
	}
	// fields[49] (quoted text) must remain untouched.
	if string(out[49].([]byte)) != "> original message quoted preview" {
		t.Errorf("fields[49] clobbered: %q", out[49])
	}
}

func TestStripReplyHashRemovesOnly48(t *testing.T) {
	in := map[any]any{
		48: bytes.Repeat([]byte{0x01}, 32),
		49: []byte("preview"),
	}
	out := stripReplyHash(in)
	if _, ok := out[48]; ok {
		t.Error("fields[48] should have been removed")
	}
	if _, ok := out[49]; !ok {
		t.Error("fields[49] should have survived stripReplyHash")
	}
}

func TestCloneFieldsIsIndependent(t *testing.T) {
	in := map[any]any{16: map[any]any{"emoji": "👍"}}
	out := cloneFields(in)
	out[16] = "tampered"
	if _, ok := in[16].(map[any]any); !ok {
		t.Error("cloneFields not independent: source got mutated")
	}
}

func TestNormalizeHexLowercases(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"abcd":     "abcd",
		"ABCD":     "abcd",
		"DeAdBeEf": "deadbeef",
	}
	for in, want := range cases {
		if got := normalizeHex(in); got != want {
			t.Errorf("normalizeHex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRewriteReturnsNilWhenNoTargetFields(t *testing.T) {
	// Service with no fields[16] or fields[48] in input — buildRewrite
	// should return nil (caller skips rewrite entirely).
	s := &Service{}
	if got := s.buildRewrite(nil); got != nil {
		t.Error("buildRewrite(nil) should be nil")
	}
	if got := s.buildRewrite(map[any]any{6: []any{"jpg", []byte{1, 2}}}); got != nil {
		t.Error("buildRewrite(image-only) should be nil")
	}
}
