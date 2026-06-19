package service

import (
	"encoding/hex"
)

// LXMF app-extension field keys that fwdsvc rewrites per recipient.
// All of these reference ANOTHER message's message_id, so in fwdsvc's
// rebroadcast relay model (see internal/idmap) the referenced id must
// be substituted with each recipient's own view of the targeted bubble
// — otherwise the annotation binds on no row on the receiving client.
//
// Reaction/comment/continuation are integer-keyed msgpack dicts that
// carry their target at inner key 0x00 as raw 32 bytes (NOT hex); the
// upstream allocation landed in LXMF 1.0.0 (markqvist/LXMF, FIELD_*
// constants). Reply-to carries the raw 32-byte target at the top level.
const (
	// fieldReplyTo is FIELD_REPLY_TO = 0x30 (48) — raw 32-byte
	// message_id being replied to (top-level value, not a dict).
	fieldReplyTo = 0x30

	// fieldReplyQuote is FIELD_REPLY_QUOTE = 0x31 (49) — optional UTF-8
	// quoted-content preview. Passes through verbatim; never rewritten.
	fieldReplyQuote = 0x31

	// fieldReaction is FIELD_REACTION = 0x40 (64) — tap-back reaction.
	// Dict {0x00: raw msgid (REACTION_TO), 0x01: UTF-8 (REACTION_CONTENT)}.
	fieldReaction = 0x40

	// fieldComment is FIELD_COMMENT = 0x41 (65) — message-as-comment.
	// Dict {0x00: raw msgid (COMMENT_FOR)}.
	fieldComment = 0x41

	// fieldContinuation is FIELD_CONTINUATION = 0x42 (66) —
	// message-as-continuation. Dict {0x00: raw msgid (CONTINUATION_OF)}.
	fieldContinuation = 0x42

	// targetIdx is the inner integer key carrying the raw-bytes target
	// message_id inside a reaction/comment/continuation dict —
	// REACTION_TO / COMMENT_FOR / CONTINUATION_OF, all 0x00 upstream.
	targetIdx = 0x00

	// fieldCustomType is FIELD_CUSTOM_TYPE = 0xFB (251) and
	// fieldCustomData is FIELD_CUSTOM_DATA = 0xFC (252) — upstream's
	// app-convention fields (SPEC §5.9.1 / LXMF/LXMF.py). fwdsvc uses
	// them to carry reactor attribution on relayed reactions; see
	// stampReactorIdentity.
	fieldCustomType = 0xFB
	fieldCustomData = 0xFC
)

// originatorIdentityType is the exact FIELD_CUSTOM_TYPE tag cooperating
// clients match to read the original reactor's identity hash from
// FIELD_CUSTOM_DATA. It MUST be byte-exact: a client that doesn't match
// it silently falls back to source-based attribution — which, for a
// relayed reaction, means attributing it to fwdsvc instead of the
// reactor. Documented for other clients in docs/reaction-attribution.md.
const originatorIdentityType = "originator-identity"

// hasReactionField reports whether the field map carries a
// FIELD_REACTION (0x40), tolerating whatever integer type the msgpack
// decoder produced for the key.
func hasReactionField(fields map[any]any) bool {
	for k := range fields {
		if ki, ok := keyAsInt(k); ok && ki == fieldReaction {
			return true
		}
	}
	return false
}

// stampReactorIdentity adds the originator-identity custom fields
// (FIELD_CUSTOM_TYPE 0xFB = "originator-identity", FIELD_CUSTOM_DATA
// 0xFC = the reactor's raw 16-byte RNS identity hash) to a relayed
// reaction's field map, so cooperating clients attribute the reaction to
// the original reactor rather than the relay's source_hash.
//
// identityHash MUST be the reactor's RNS identity hash
// (SHA-256(public_key)[:16]), NOT their lxmf delivery destination hash —
// clients aggregate reactions by identity hash.
//
// No-op (returns false) when the map carries no reaction or identityHash
// is missing/empty. Reactions only: replies/comments/continuations carry
// a body whose author rides the relay's "[nick]" prefix, so they need no
// stamp.
func stampReactorIdentity(fields map[any]any, identityHash []byte) bool {
	if fields == nil || len(identityHash) == 0 || !hasReactionField(fields) {
		return false
	}
	fields[fieldCustomType] = originatorIdentityType
	fields[fieldCustomData] = identityHash
	return true
}

// viewer is the part of idmap.Bubble the substitute helpers depend on:
// "what message_id will this recipient compute for the targeted
// bubble?". Declaring it as an interface lets the tests drive the
// helpers with a fake bubble.
type viewer interface {
	ViewFor(recipientHex string) (string, bool)
}

// isPrimaryBubble reports whether a forwarded message is a standalone,
// reactable bubble as opposed to a reaction / comment / continuation /
// bare reply-to that merely annotates an existing bubble. Only primary
// bubbles get a new idmap cache entry, so later reactions can be
// rewritten to bind to them.
//
// A message is primary when it has visible text content OR carries any
// field that is not itself an annotation marker — i.e. an attachment
// such as FIELD_IMAGE. An image message arrives with content=="" but IS
// a reactable bubble; the original `content != ""` check missed it, so
// reactions to forwarded images never bound.
func isPrimaryBubble(content string, fields map[any]any) bool {
	if content != "" {
		return true
	}
	for k := range fields {
		ki, ok := keyAsInt(k)
		if !ok {
			continue
		}
		switch ki {
		case fieldReplyTo, fieldReplyQuote, fieldReaction, fieldComment, fieldContinuation:
			continue
		default:
			// An attachment field (image/audio/file, …) — this message
			// is a bubble in its own right.
			return true
		}
	}
	return false
}

// buildRewrite returns a per-recipient field rewrite closure suitable
// for forwardOpts.rewrite, or nil if this inbound message carries no
// reaction / comment / continuation / reply-to target that needs
// substituting.
//
// The closure runs once per recipient and:
//
//   - clones the field map (the per-recipient substitutions must NOT
//     leak into the next recipient's copy)
//   - substitutes each dict field's inner 0x00 target (reaction/comment/
//     continuation) with the recipient's view of the targeted bubble's
//     message_id, as raw bytes
//   - substitutes the reply-to hash (fields[0x30]) similarly
//   - returns ok=false when the recipient has no view of a reaction/
//     comment/continuation target (the target was never sent to them —
//     typically because they joined after the original was relayed);
//     the caller skips that recipient because the rewrite would land on
//     nothing anyway. Reply-to is gentler: the hash is stripped but the
//     message (and its fields[0x31] quote preview) is still delivered.
//
// Cache miss on lookup → that target is dropped from the rewrite set and
// the field passes through unchanged (legacy behavior). Same when
// s.idmap is nil (cache disabled).
func (s *Service) buildRewrite(fields map[any]any) func(recipientHex string, fields map[any]any) (map[any]any, bool) {
	if s.idmap == nil || len(fields) == 0 {
		return nil
	}

	// Scan once for fields that need rewriting + their target bubbles.
	// Doing this up-front keeps the per-recipient closure cheap (no
	// map iteration per recipient).
	type dictTarget struct {
		key    int
		bubble viewer
	}
	var dicts []dictTarget
	var replyBubble viewer

	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok {
			continue
		}
		switch ki {
		case fieldReaction, fieldComment, fieldContinuation:
			targetHex := extractDictTarget(v)
			if targetHex == "" {
				continue
			}
			b := s.idmap.Lookup(targetHex)
			s.logTargetLookup(fieldLabel(ki), targetHex, b != nil)
			if b != nil {
				dicts = append(dicts, dictTarget{key: ki, bubble: b})
			}
		case fieldReplyTo:
			raw, ok := v.([]byte)
			if !ok {
				continue
			}
			targetHex := hex.EncodeToString(raw)
			b := s.idmap.Lookup(targetHex)
			s.logTargetLookup(fieldLabel(ki), targetHex, b != nil)
			if b != nil {
				replyBubble = b
			}
		}
	}

	if len(dicts) == 0 && replyBubble == nil {
		// Nothing to rewrite — return nil so forwardToRoster skips the
		// rewrite step entirely.
		return nil
	}

	return func(recipientHex string, in map[any]any) (map[any]any, bool) {
		out := cloneFields(in)
		for _, d := range dicts {
			rewritten, ok := substituteDictTarget(out, d.key, recipientHex, d.bubble)
			if !ok {
				// Recipient never received the targeted bubble — skip
				// them entirely so they don't get an orphan
				// reaction/comment/continuation.
				return nil, false
			}
			out = rewritten
		}
		if replyBubble != nil {
			rewritten, ok := substituteReplyHash(out, recipientHex, replyBubble)
			if !ok {
				// Replies have a human-visible fallback (fields[0x31]
				// quoted text), so we still send the reply, just
				// without the bound hash — the receiver keeps the quote
				// preview at least.
				out = stripReplyHash(out)
			} else {
				out = rewritten
			}
		}
		return out, true
	}
}

// logTargetLookup emits one line per resolved target so cache hits/misses
// can be grepped. On a miss the full hash is logged (not just the short
// prefix) so unmatched values can be diffed against client-side
// message_id computations — surfaces off-canon hash schemes without
// having to add ad-hoc logging next time.
func (s *Service) logTargetLookup(label, targetHex string, hit bool) {
	if hit {
		s.logger.Printf("rewrite: %s target=%s hit (cache size=%d)",
			label, shortHex(targetHex), s.idmap.Len())
		return
	}
	s.logger.Printf("rewrite: %s target=%s miss (cache size=%d) FULL=%s",
		label, shortHex(targetHex), s.idmap.Len(), targetHex)
}

func cloneFields(in map[any]any) map[any]any {
	out := make(map[any]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// extractDictTarget pulls the raw-bytes target message_id out of a
// reaction/comment/continuation dict value (inner key 0x00) and returns
// it hex-encoded for idmap lookup. Returns "" when the value isn't a
// recognisable dict or carries no raw-bytes target — the caller then
// passes the LXMF through unrewritten.
//
// Integer-keyed msgpack dicts decode to map[any]any under
// vmihailenco/msgpack/v5 (it picks map[any]any once it sees a non-string
// key); keyAsInt tolerates whatever integer width the decoder produced.
func extractDictTarget(v any) string {
	m, ok := v.(map[any]any)
	if !ok {
		return ""
	}
	for mk, mv := range m {
		if ki, ok := keyAsInt(mk); !ok || ki != targetIdx {
			continue
		}
		if b, ok := mv.([]byte); ok {
			return hex.EncodeToString(b)
		}
	}
	return ""
}

// substituteDictTarget rewrites the inner 0x00 target of a reaction/
// comment/continuation dict (fields[key]) to recipientHex's view of the
// targeted message_id, as raw bytes. Returns (out, true) on success or
// (nil, false) when the recipient has no view of the bubble (forward
// would land on nothing).
//
// The inner map is rebuilt (not mutated in place) so the per-recipient
// substitution doesn't leak across recipients sharing the cloned outer
// map's inner-map pointer.
func substituteDictTarget(fields map[any]any, key int, recipientHex string, bubble viewer) (map[any]any, bool) {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != key {
			continue
		}
		m, ok := v.(map[any]any)
		if !ok {
			continue
		}
		var targetKey any
		found := false
		for mk := range m {
			if ik, ok := keyAsInt(mk); ok && ik == targetIdx {
				targetKey = mk
				found = true
				break
			}
		}
		if !found {
			continue
		}
		view, ok := bubble.ViewFor(recipientHex)
		if !ok {
			return nil, false
		}
		raw, err := hex.DecodeString(view)
		if err != nil {
			return nil, false
		}
		newMap := make(map[any]any, len(m))
		for mk, mv := range m {
			newMap[mk] = mv
		}
		newMap[targetKey] = raw
		fields[k] = newMap
		return fields, true
	}
	return fields, true
}

// substituteReplyHash rewrites fields[0x30] (raw 32-byte hash) to the
// recipient's view of the targeted message_id. Returns (out, true) on
// success or (out, false) when the recipient has no view of the bubble.
func substituteReplyHash(fields map[any]any, recipientHex string, bubble viewer) (map[any]any, bool) {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != fieldReplyTo {
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
// receiver still renders the quote preview. Used when we can't bind the
// reply hash on this recipient but they should still see the quoted-text
// context.
func stripReplyHash(fields map[any]any) map[any]any {
	for k := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != fieldReplyTo {
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
