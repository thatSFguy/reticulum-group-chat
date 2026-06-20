package service

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/config"
)

// filterAttachments applies the operator's attachment policy to an
// inbound msg.Fields map:
//
//   - cfg.ForwardAttachments == false → returns (nil, nil). Every field
//     is silently dropped; only the text body is forwarded.
//   - keys not in cfg.ForwardedFields → dropped silently. Not
//     user-visible; it's defense against a misbehaving client stuffing
//     unknown keys.
//   - allowed keys whose msgpack-encoded value exceeds
//     cfg.MaxAttachmentBytes → dropped, with one human-readable note
//     appended to drops so the inbox can suffix the forwarded body
//     ("[image not forwarded: 87 KB > 32 KB limit]").
//   - cfg.MaxAttachmentBytes == 0 → cap is disabled.
//
// Returned map is nil when no fields survive (so the queue stays on the
// text-only path and doesn't allocate an empty map for every forward).
func filterAttachments(in map[any]any, cfg config.ServiceConfig) (out map[any]any, drops []string) {
	if len(in) == 0 || !cfg.ForwardAttachments {
		return nil, nil
	}
	for k, v := range in {
		keyInt, ok := keyAsInt(k)
		if !ok || !slices.Contains(cfg.ForwardedFields, keyInt) {
			continue
		}
		size, err := msgpackSize(v)
		if err != nil {
			continue // unencodable value — drop silently
		}
		if cfg.MaxAttachmentBytes > 0 && size > cfg.MaxAttachmentBytes {
			drops = append(drops, fmt.Sprintf("[%s not forwarded: %s > %s limit]",
				fieldLabel(keyInt), humanBytes(size), humanBytes(cfg.MaxAttachmentBytes)))
			continue
		}
		if out == nil {
			out = make(map[any]any, len(in))
		}
		out[k] = v
	}
	return out, drops
}

// keyAsInt coerces a msgpack-decoded key (could be any signed/unsigned
// integer type, or a numeric string from a tolerant client) into a plain
// int. Returns false for keys we can't map.
func keyAsInt(k any) (int, bool) {
	switch v := k.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// msgpackSize returns the encoded size of v, used to gate field values
// against MaxAttachmentBytes. We measure msgpack-encoded size rather
// than just len(image_bytes) because the field can also carry small
// shape metadata (e.g. FIELD_IMAGE = ["jpg", bytes]) and the wire
// overhead of that wrapper is exactly what's consuming the link budget.
func msgpackSize(v any) (int, error) {
	encoded, err := msgpack.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

// fieldLabel returns a short human name for an LXMF field number, used
// only in the "[X not forwarded: …]" suffix recipients see. Falls back
// to "field N" for unknown keys.
func fieldLabel(key int) string {
	switch key {
	case 5:
		return "file"
	case 6:
		return "image"
	case 7:
		return "audio"
	case 48: // 0x30 — FIELD_REPLY_TO hash
		return "reply-to"
	case 49: // 0x31 — FIELD_REPLY_QUOTE text
		return "reply text"
	case 64: // 0x40 — FIELD_REACTION
		return "reaction"
	case 65: // 0x41 — FIELD_COMMENT
		return "comment"
	case 66: // 0x42 — FIELD_CONTINUATION
		return "continuation"
	default:
		return fmt.Sprintf("field %d", key)
	}
}

// humanBytes renders a byte count as "NNN B" / "NN.N KB" — short enough
// for an inline suffix in the chat body.
func humanBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}
