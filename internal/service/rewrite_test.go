package service

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/idmap"
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

func TestSubstituteDictTargetRewritesRawBytesPerRecipient(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliceMsgID := bytes.Repeat([]byte{0xDE, 0xAD}, 16) // 32 bytes
	aliceMsgIDHex := hex.EncodeToString(aliceMsgID)

	bubble := &fakeBubble{views: map[string]string{aliceHex: aliceMsgIDHex}}

	// FIELD_REACTION (0x40): integer-keyed dict, raw-bytes target at 0x00,
	// UTF-8 content at 0x01.
	in := map[any]any{
		fieldReaction: map[any]any{
			targetIdx: bytes.Repeat([]byte{0xCA, 0xFE}, 16), // sender's view
			0x01:      []byte("👍"),
		},
	}

	out, ok := substituteDictTarget(in, fieldReaction, aliceHex, bubble)
	if !ok {
		t.Fatal("substituteDictTarget returned ok=false for known recipient")
	}
	react, _ := out[fieldReaction].(map[any]any)
	got, _ := react[targetIdx].([]byte)
	if !bytes.Equal(got, aliceMsgID) {
		t.Errorf("REACTION_TO = %x, want %x", got, aliceMsgID)
	}
	if string(react[0x01].([]byte)) != "👍" {
		t.Errorf("REACTION_CONTENT clobbered: %q", react[0x01])
	}
}

func TestSubstituteDictTargetCommentAndContinuation(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliceMsgID := bytes.Repeat([]byte{0x11, 0x22}, 16)
	bubble := &fakeBubble{views: map[string]string{aliceHex: hex.EncodeToString(aliceMsgID)}}

	for _, key := range []int{fieldComment, fieldContinuation} {
		in := map[any]any{
			key: map[any]any{targetIdx: bytes.Repeat([]byte{0x99}, 32)},
		}
		out, ok := substituteDictTarget(in, key, aliceHex, bubble)
		if !ok {
			t.Fatalf("field 0x%x: ok=false for known recipient", key)
		}
		m, _ := out[key].(map[any]any)
		if got, _ := m[targetIdx].([]byte); !bytes.Equal(got, aliceMsgID) {
			t.Errorf("field 0x%x target = %x, want %x", key, got, aliceMsgID)
		}
	}
}

func TestSubstituteDictTargetUnknownRecipient(t *testing.T) {
	bubble := &fakeBubble{views: map[string]string{"alice": "aliceview"}}
	in := map[any]any{
		fieldReaction: map[any]any{
			targetIdx: bytes.Repeat([]byte{0x01}, 32),
			0x01:      []byte("🔥"),
		},
	}
	if _, ok := substituteDictTarget(in, fieldReaction, "bob", bubble); ok {
		t.Error("substituteDictTarget returned ok=true for unknown recipient bob")
	}
}

func TestExtractDictTarget(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, 32)
	cases := map[string]struct {
		v    any
		want string
	}{
		"int-keyed raw bytes": {
			v:    map[any]any{targetIdx: raw, 0x01: []byte("👍")},
			want: hex.EncodeToString(raw),
		},
		"no target key": {
			v:    map[any]any{0x01: []byte("👍")},
			want: "",
		},
		"target not bytes (str carrier unsupported → pass-through)": {
			v:    map[any]any{targetIdx: "not-bytes"},
			want: "",
		},
		"not a dict": {
			v:    []byte("nope"),
			want: "",
		},
	}
	for name, tc := range cases {
		if got := extractDictTarget(tc.v); got != tc.want {
			t.Errorf("%s: extractDictTarget = %q, want %q", name, got, tc.want)
		}
	}
}

func TestSubstituteReplyHashRewritesRawBytes(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliceMsgID := bytes.Repeat([]byte{0xCA, 0xFE}, 16) // 32 bytes
	aliceMsgIDHex := hex.EncodeToString(aliceMsgID)

	bubble := &fakeBubble{views: map[string]string{aliceHex: aliceMsgIDHex}}

	in := map[any]any{
		fieldReplyTo:    bytes.Repeat([]byte{0xDE, 0xAD}, 16),       // sender's view
		fieldReplyQuote: []byte("> original message quoted preview"), // text passes through
	}
	out, ok := substituteReplyHash(in, aliceHex, bubble)
	if !ok {
		t.Fatal("substituteReplyHash returned ok=false for known recipient")
	}
	got, _ := out[fieldReplyTo].([]byte)
	if !bytes.Equal(got, aliceMsgID) {
		t.Errorf("rewritten reply hash = %x, want %x", got, aliceMsgID)
	}
	// fields[0x31] (quoted text) must remain untouched.
	if string(out[fieldReplyQuote].([]byte)) != "> original message quoted preview" {
		t.Errorf("fields[0x31] clobbered: %q", out[fieldReplyQuote])
	}
}

func TestStripReplyHashRemovesOnlyReplyTo(t *testing.T) {
	in := map[any]any{
		fieldReplyTo:    bytes.Repeat([]byte{0x01}, 32),
		fieldReplyQuote: []byte("preview"),
	}
	out := stripReplyHash(in)
	if _, ok := out[fieldReplyTo]; ok {
		t.Error("fields[0x30] should have been removed")
	}
	if _, ok := out[fieldReplyQuote]; !ok {
		t.Error("fields[0x31] should have survived stripReplyHash")
	}
}

func TestCloneFieldsIsIndependent(t *testing.T) {
	in := map[any]any{fieldReaction: map[any]any{0x01: []byte("👍")}}
	out := cloneFields(in)
	out[fieldReaction] = "tampered"
	if _, ok := in[fieldReaction].(map[any]any); !ok {
		t.Error("cloneFields not independent: source got mutated")
	}
}

func TestIsPrimaryBubble(t *testing.T) {
	cases := map[string]struct {
		content string
		fields  map[any]any
		want    bool
	}{
		"text content":            {content: "hi", want: true},
		"image, empty content":    {fields: map[any]any{6: []any{"jpg", []byte{1}}}, want: true},
		"reaction, empty content": {fields: map[any]any{fieldReaction: map[any]any{targetIdx: []byte{1}}}, want: false},
		"reply-to, empty content": {fields: map[any]any{fieldReplyTo: []byte{1}}, want: false},
		"comment marker only":     {fields: map[any]any{fieldComment: map[any]any{targetIdx: []byte{1}}}, want: false},
		"nothing":                 {want: false},
	}
	for name, tc := range cases {
		if got := isPrimaryBubble(tc.content, tc.fields); got != tc.want {
			t.Errorf("%s: isPrimaryBubble = %v, want %v", name, got, tc.want)
		}
	}
}

func TestBuildRewriteReturnsNilWhenNoTargetFields(t *testing.T) {
	// Service with no rewritable target fields in input — buildRewrite
	// should return nil (caller skips rewrite entirely). idmap must be
	// non-nil or buildRewrite short-circuits to nil for a different
	// reason.
	s := &Service{
		idmap:  idmap.New(time.Minute, 0),
		logger: log.New(io.Discard, "", 0),
	}
	if got := s.buildRewrite(nil); got != nil {
		t.Error("buildRewrite(nil) should be nil")
	}
	if got := s.buildRewrite(map[any]any{6: []any{"jpg", []byte{1, 2}}}); got != nil {
		t.Error("buildRewrite(image-only) should be nil")
	}
	// idmap disabled → always nil even with a reaction present.
	disabled := &Service{logger: log.New(io.Discard, "", 0)}
	if got := disabled.buildRewrite(map[any]any{fieldReaction: map[any]any{targetIdx: []byte{1}}}); got != nil {
		t.Error("buildRewrite with nil idmap should be nil")
	}
}

func TestBuildRewriteBindsReactionToRecipientView(t *testing.T) {
	const aliceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const bobHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cache := idmap.New(time.Minute, 0)
	now := time.Now()
	bubble := idmap.NewBubble(time.Minute, now)

	// Original message went to Alice and Bob; each computed a distinct
	// message_id (the whole reason this cache exists).
	senderView := bytes.Repeat([]byte{0x77}, 32)
	aliceView := bytes.Repeat([]byte{0xA1}, 32)
	bobView := bytes.Repeat([]byte{0xB2}, 32)
	cache.RegisterView(bubble, aliceHex, hex.EncodeToString(aliceView))
	cache.RegisterView(bubble, bobHex, hex.EncodeToString(bobView))
	// The reactor (some third member) reacted using their own view; here
	// we just need any registered key to resolve the bubble — use the
	// sender's view as the inbound reaction_to so it must be looked up.
	cache.RegisterView(bubble, "reactor", hex.EncodeToString(senderView))

	s := &Service{idmap: cache, logger: log.New(io.Discard, "", 0)}

	in := map[any]any{
		fieldReaction: map[any]any{
			targetIdx: senderView,
			0x01:      []byte("👍"),
		},
	}
	rewrite := s.buildRewrite(in)
	if rewrite == nil {
		t.Fatal("buildRewrite returned nil for a reaction with a cached target")
	}

	// Alice gets her own view; the inner map is rebuilt, not shared.
	aliceOut, ok := rewrite(aliceHex, in)
	if !ok {
		t.Fatal("rewrite(alice) returned ok=false")
	}
	aliceReact := aliceOut[fieldReaction].(map[any]any)
	if got := aliceReact[targetIdx].([]byte); !bytes.Equal(got, aliceView) {
		t.Errorf("alice REACTION_TO = %x, want %x", got, aliceView)
	}

	bobOut, ok := rewrite(bobHex, in)
	if !ok {
		t.Fatal("rewrite(bob) returned ok=false")
	}
	bobReact := bobOut[fieldReaction].(map[any]any)
	if got := bobReact[targetIdx].([]byte); !bytes.Equal(got, bobView) {
		t.Errorf("bob REACTION_TO = %x, want %x", got, bobView)
	}

	// A recipient who never received the original is skipped entirely.
	if _, ok := rewrite("cccccccccccccccccccccccccccccccc", in); ok {
		t.Error("rewrite(stranger) should return ok=false")
	}

	// The original input must be untouched (per-recipient clone).
	if got := in[fieldReaction].(map[any]any)[targetIdx].([]byte); !bytes.Equal(got, senderView) {
		t.Errorf("input mutated: REACTION_TO = %x, want %x", got, senderView)
	}
}
