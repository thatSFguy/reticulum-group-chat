package service

import (
	"encoding/hex"
)

// reactionField is LXMF field key 16 — the Columba + MeshChatX tap-back
// reaction shape. Payload is a map: {"reaction_to": <hex>, "emoji": "👍",
// "sender": <hex>}. reaction_to is a string-hex message_id and is the
// field we have to rewrite per recipient.
const reactionField = 16

// replyHashField is LXMF field key 0x30 = 48 — MeshChatX reply-to hash
// (raw 32-byte message_id, NOT hex). The companion 0x31 = 49 is the
// optional quoted-content preview; it doesn't need rewriting since it's
// just UTF-8 text and passes through verbatim.
const replyHashField = 48

// buildRewrite returns a per-recipient field rewrite closure suitable
// for forwardOpts.rewrite, or nil if this inbound message has no
// reaction_to / reply-to fields that need substituting.
//
// The closure runs once per recipient and:
//
//   - clones the field map (the per-recipient substitutions must NOT
//     leak into the next recipient's copy)
//   - substitutes reaction_to (fields[16].reaction_to) with the
//     recipient's view of the targeted bubble's message_id
//   - substitutes reply-to hash (fields[48]) similarly
//   - returns ok=false when the recipient has no view of the target
//     bubble (the target was never sent to them — typically because
//     they joined after the original message was relayed); the caller
//     skips that recipient because the rewrite would land on nothing
//     anyway.
//
// Cache miss on lookup → returns the closure WITHOUT a target bubble
// for the missing key, which causes the rewrite to pass through
// unchanged (legacy behavior). Same when s.idmap is nil (cache
// disabled).
func (s *Service) buildRewrite(fields map[any]any) func(recipientHex string, fields map[any]any) (map[any]any, bool) {
	if s.idmap == nil || len(fields) == 0 {
		return nil
	}

	// Scan once for fields that need rewriting + their target bubbles.
	// Doing this up-front keeps the per-recipient closure cheap (no
	// map iteration per recipient).
	type target struct {
		// reactionTargetHex is the bubble lookup key (lowercase hex)
		// for the reaction_to substring. Empty if no reaction in input.
		reactionTargetHex string
		replyTargetHex    string // empty if no reply-to in input
	}
	var t target
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok {
			continue
		}
		switch ki {
		case reactionField:
			// The reaction map's outer Go type depends on whether the
			// msgpack decoder picked map[any]any or map[string]any —
			// vmihailenco/msgpack/v5 chooses based on the key type it
			// sees on the wire when decoding into `any`. Accept both
			// so we interop with Kotlin/Java/Python encoders that emit
			// string-keyed inner maps (Columba + MeshChatX both do).
			rt := extractReactionTarget(v)
			t.reactionTargetHex = normalizeHex(rt)
		case replyHashField:
			b, ok := v.([]byte)
			if !ok {
				continue
			}
			t.replyTargetHex = hex.EncodeToString(b)
		}
	}
	if t.reactionTargetHex == "" && t.replyTargetHex == "" {
		return nil
	}

	// Resolve target bubbles up-front. A miss means we can't bind on
	// any recipient — the rewrite will pass through unchanged (legacy
	// behavior; clients render "replying to a message" without a
	// quote, reactions don't render at all).
	reactionBubble := s.idmap.Lookup(t.reactionTargetHex)
	replyBubble := s.idmap.Lookup(t.replyTargetHex)

	if t.reactionTargetHex != "" {
		if reactionBubble != nil {
			s.logger.Printf("rewrite: reaction_to=%s hit (cache size=%d)",
				shortHex(t.reactionTargetHex), s.idmap.Len())
		} else {
			// Full hash on miss so we can grep for unmatched values
			// against client-side message_id computations — surfaces
			// off-canon hash schemes (e.g. reply bubbles computing a
			// non-spec id) without having to add ad-hoc logging next
			// time.
			s.logger.Printf("rewrite: reaction_to=%s miss (cache size=%d) FULL=%s",
				shortHex(t.reactionTargetHex), s.idmap.Len(), t.reactionTargetHex)
		}
	}
	if t.replyTargetHex != "" {
		if replyBubble != nil {
			s.logger.Printf("rewrite: reply_to=%s hit", shortHex(t.replyTargetHex))
		} else {
			s.logger.Printf("rewrite: reply_to=%s miss FULL=%s",
				shortHex(t.replyTargetHex), t.replyTargetHex)
		}
	}

	if reactionBubble == nil && replyBubble == nil {
		// Nothing to rewrite — return nil so forwardToRoster skips the
		// rewrite step entirely.
		return nil
	}

	return func(recipientHex string, in map[any]any) (map[any]any, bool) {
		out := cloneFields(in)
		if reactionBubble != nil {
			rewritten, ok := substituteReaction(out, recipientHex, reactionBubble)
			if !ok {
				// Recipient never received the targeted bubble — skip
				// them entirely so they don't get an orphan reaction.
				return nil, false
			}
			out = rewritten
		}
		if replyBubble != nil {
			rewritten, ok := substituteReplyHash(out, recipientHex, replyBubble)
			if !ok {
				// Same logic for replies — although replies have a
				// human-visible fallback (fields[0x31] quoted text), so
				// we still send the reply, just without the bound
				// hash. That gives the receiver the quote preview at
				// least.
				out = stripReplyHash(out)
				_ = rewritten
			} else {
				out = rewritten
			}
		}
		return out, true
	}
}

func cloneFields(in map[any]any) map[any]any {
	out := make(map[any]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// substituteReaction rewrites fields[16].reaction_to to the recipient's
// view of the targeted message_id. Returns (out, true) on success or
// (nil, false) when the recipient has no view of the bubble (forward
// would land on nothing).
func substituteReaction(fields map[any]any, recipientHex string, bubble interface {
	ViewFor(string) (string, bool)
}) (map[any]any, bool) {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != reactionField {
			continue
		}
		view, ok := bubble.ViewFor(recipientHex)
		if !ok {
			return nil, false
		}
		switch m := v.(type) {
		case map[any]any:
			newMap := make(map[any]any, len(m))
			for mk, mv := range m {
				newMap[mk] = mv
			}
			newMap["reaction_to"] = view
			fields[k] = newMap
			return fields, true
		case map[string]any:
			// Mobile/Python encoders typically emit a string-keyed
			// reaction map. Preserve the wire shape on output by
			// rebuilding it as the same Go type — the msgpack
			// encoder we use will re-emit it as a string-keyed
			// map, matching the original sender's choice.
			newMap := make(map[string]any, len(m))
			for mk, mv := range m {
				newMap[mk] = mv
			}
			newMap["reaction_to"] = view
			fields[k] = newMap
			return fields, true
		default:
			continue
		}
	}
	return fields, true
}

// extractReactionTarget pulls "reaction_to" out of a fields[16] value
// regardless of whether the decoder produced map[any]any or
// map[string]any. Returns the hex string, or empty string if absent /
// not a string. Empty result signals "this isn't a recognisable
// reaction shape" and the caller should pass the LXMF through
// unrewritten.
func extractReactionTarget(v any) string {
	switch m := v.(type) {
	case map[any]any:
		s, _ := m["reaction_to"].(string)
		return s
	case map[string]any:
		s, _ := m["reaction_to"].(string)
		return s
	}
	return ""
}

// substituteReplyHash rewrites fields[0x30] (raw 32-byte hash) to the
// recipient's view of the targeted message_id. Returns (out, true) on
// success or (out, false) when the recipient has no view of the bubble.
func substituteReplyHash(fields map[any]any, recipientHex string, bubble interface {
	ViewFor(string) (string, bool)
}) (map[any]any, bool) {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != replyHashField {
			continue
		}
		if _, ok := v.([]byte); !ok {
			continue
		}
		view, ok := bubble.ViewFor(recipientHex)
		if !ok {
			return fields, false
		}
		raw, err := hex.DecodeString(view)
		if err != nil {
			return fields, false
		}
		fields[k] = raw
		return fields, true
	}
	return fields, true
}

// stripReplyHash removes fields[0x30] but keeps fields[0x31] so the
// receiver still renders the quote preview. Used when we can't bind
// the reply hash on this recipient but they should still see the
// quoted-text context.
func stripReplyHash(fields map[any]any) map[any]any {
	for k := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != replyHashField {
			continue
		}
		delete(fields, k)
	}
	return fields
}

// shortHex returns the first 8 hex chars of s for log lines — enough to
// disambiguate while keeping log lines tidy.
func shortHex(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// normalizeHex lowercases a hex string from an inbound msgpack map.
// Empty input returns empty. We don't validate further — Lookup will
// just miss on a malformed key.
func normalizeHex(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}
