package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
)

// defaultAttachmentCfg mirrors config.defaults(): attachments on, 32 KB
// cap, FIELD_IMAGE (6) allowed. Each test overrides what it needs.
func defaultAttachmentCfg() config.ServiceConfig {
	return config.ServiceConfig{
		ForwardAttachments: true,
		MaxAttachmentBytes: 32768,
		ForwardedFields:    []int{6},
	}
}

func TestFilterAttachmentsPassesAllowedImage(t *testing.T) {
	// Canonical FIELD_IMAGE wire shape: [extension_string, image_bytes].
	in := map[any]any{
		6: []any{"jpg", bytes.Repeat([]byte{0xAB}, 1000)},
	}
	out, drops := filterAttachments(in, defaultAttachmentCfg())
	if len(drops) != 0 {
		t.Errorf("unexpected drops: %v", drops)
	}
	if len(out) != 1 {
		t.Fatalf("out has %d entries, want 1", len(out))
	}
	if _, ok := out[6]; !ok {
		t.Errorf("key 6 missing from out: %v", out)
	}
}

func TestFilterAttachmentsForwardAttachmentsFalseDropsAll(t *testing.T) {
	cfg := defaultAttachmentCfg()
	cfg.ForwardAttachments = false
	in := map[any]any{
		6: []any{"jpg", bytes.Repeat([]byte{0xAB}, 100)},
	}
	out, drops := filterAttachments(in, cfg)
	if out != nil {
		t.Errorf("expected nil out when ForwardAttachments=false, got %v", out)
	}
	// Silent drop — operator opted out, no user-visible suffix.
	if len(drops) != 0 {
		t.Errorf("expected no drop notes when ForwardAttachments=false, got %v", drops)
	}
}

func TestFilterAttachmentsDropsDisallowedKeysSilently(t *testing.T) {
	// Allowlist = [6]; sender ships keys 5 (file), 6 (image), 99 (junk).
	// Only 6 should survive, with no user-visible note for 5/99 — those
	// are defense-against-misbehaving-client drops, not "image too big"
	// drops.
	in := map[any]any{
		5:  []any{"data.bin", []byte("hello")},
		6:  []any{"jpg", []byte{0xFF, 0xD8, 0xFF, 0xE0}},
		99: "junk",
	}
	out, drops := filterAttachments(in, defaultAttachmentCfg())
	if len(out) != 1 {
		t.Fatalf("out has %d entries, want 1 (key 6 only)", len(out))
	}
	if _, ok := out[6]; !ok {
		t.Errorf("key 6 missing")
	}
	if len(drops) != 0 {
		t.Errorf("expected no drop notes for allowlist filtering, got %v", drops)
	}
}

func TestFilterAttachmentsCapDropsOversized(t *testing.T) {
	cfg := defaultAttachmentCfg()
	cfg.MaxAttachmentBytes = 1024
	// 4 KB image is well over the 1 KB cap.
	in := map[any]any{
		6: []any{"jpg", bytes.Repeat([]byte{0xCC}, 4096)},
	}
	out, drops := filterAttachments(in, cfg)
	if len(out) != 0 {
		t.Errorf("oversized image survived filter: %v", out)
	}
	if len(drops) != 1 {
		t.Fatalf("drops = %v, want 1 drop note", drops)
	}
	note := drops[0]
	for _, want := range []string{"image", "not forwarded", "KB", "limit"} {
		if !strings.Contains(note, want) {
			t.Errorf("drop note %q missing %q", note, want)
		}
	}
}

func TestFilterAttachmentsCapZeroDisablesCap(t *testing.T) {
	// MaxAttachmentBytes = 0 means "no cap" — even a huge image passes
	// (still bounded by the link layer itself, just no policy cap).
	cfg := defaultAttachmentCfg()
	cfg.MaxAttachmentBytes = 0
	in := map[any]any{
		6: []any{"jpg", bytes.Repeat([]byte{0xCC}, 4096)},
	}
	out, drops := filterAttachments(in, cfg)
	if len(out) != 1 {
		t.Errorf("cap=0 should pass everything, got out=%v", out)
	}
	if len(drops) != 0 {
		t.Errorf("cap=0 should produce no drops, got %v", drops)
	}
}

func TestFilterAttachmentsEmptyInputReturnsNil(t *testing.T) {
	out, drops := filterAttachments(nil, defaultAttachmentCfg())
	if out != nil || drops != nil {
		t.Errorf("nil input: got out=%v drops=%v, want nil/nil", out, drops)
	}
	out, drops = filterAttachments(map[any]any{}, defaultAttachmentCfg())
	if out != nil || drops != nil {
		t.Errorf("empty input: got out=%v drops=%v, want nil/nil", out, drops)
	}
}

func TestFilterAttachmentsCoercesIntegerKeyTypes(t *testing.T) {
	// msgpack decodes integer keys as int8/int16/int32/int64 depending
	// on magnitude. The filter must accept all of them so a tolerant
	// allowlist lookup works regardless of encoder choice.
	cases := []any{int8(6), int16(6), int32(6), int64(6), uint(6), uint8(6), "6"}
	for _, key := range cases {
		in := map[any]any{
			key: []any{"jpg", []byte{0xFF, 0xD8, 0xFF}},
		}
		out, _ := filterAttachments(in, defaultAttachmentCfg())
		if len(out) != 1 {
			t.Errorf("key type %T (%v) should be coerced to 6 and kept; got out=%v",
				key, key, out)
		}
	}
}

func TestFieldLabelKnownNumbers(t *testing.T) {
	cases := map[int]string{
		5:  "file",
		6:  "image",
		7:  "audio",
		48: "reply-to",     // 0x30 — FIELD_REPLY_TO hash
		49: "reply text",   // 0x31 — FIELD_REPLY_QUOTE text
		64: "reaction",     // 0x40 — FIELD_REACTION
		65: "comment",      // 0x41 — FIELD_COMMENT
		66: "continuation", // 0x42 — FIELD_CONTINUATION
		42: "field 42",
	}
	for k, want := range cases {
		if got := fieldLabel(k); got != want {
			t.Errorf("fieldLabel(%d) = %q, want %q", k, got, want)
		}
	}
}

func TestFilterAttachmentsPassesReactionAndReplyFields(t *testing.T) {
	// Issue #8: upstream LXMF 1.0.0 fields — reactions on 0x40, comments
	// 0x41, continuations 0x42, reply-to 0x30 + quote 0x31. The default
	// allowlist must pass all of them through unchanged.
	cfg := defaultAttachmentCfg()
	cfg.ForwardedFields = []int{6, 48, 49, 64, 65, 66}

	in := map[any]any{
		64: map[any]any{ // 0x40 FIELD_REACTION
			0x00: bytes.Repeat([]byte{0xDE}, 32),
			0x01: []byte("👍"),
		},
		65: map[any]any{0x00: bytes.Repeat([]byte{0xCC}, 32)}, // 0x41 FIELD_COMMENT
		66: map[any]any{0x00: bytes.Repeat([]byte{0xEE}, 32)}, // 0x42 FIELD_CONTINUATION
		48: bytes.Repeat([]byte{0xAA}, 32),                    // 0x30 reply-to hash
		49: []byte("> original message"),                      // 0x31 quote
	}
	out, drops := filterAttachments(in, cfg)
	if len(drops) != 0 {
		t.Errorf("unexpected drops for reaction/reply fields: %v", drops)
	}
	for _, k := range []int{48, 49, 64, 65, 66} {
		if _, ok := out[k]; !ok {
			t.Errorf("field %d missing from out: %v", k, out)
		}
	}
}

func TestHumanBytesSwitchesUnits(t *testing.T) {
	cases := map[int]string{
		0:      "0 B",
		1023:   "1023 B",
		1024:   "1.0 KB",
		32768:  "32.0 KB",
		131072: "128.0 KB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
