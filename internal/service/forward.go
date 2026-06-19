package service

import (
	"encoding/hex"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/idmap"
)

// forwardOpts bundles the optional per-fan-out knobs forwardToRoster
// needs from inbox.go. Keeping it a struct rather than additional
// positional args keeps callers readable when most fields are zero
// (text-only forwards from a command reply, say).
type forwardOpts struct {
	// rewrite, when non-nil, lets the inbox transform the fields map
	// per recipient before enqueue (used for reaction/comment/
	// continuation and reply-to rewrites so each member's target
	// message_id matches their own view of the original message_id).
	// The function may
	// return nil to indicate "skip this recipient" — e.g. when we
	// can't find the recipient's view of the original bubble, so the
	// reaction would land on nothing on their side anyway.
	rewrite func(recipientHex string, fields map[any]any) (out map[any]any, ok bool)

	// bubble, when non-nil, is registered with each successful Send
	// so future reactions and reply-tos referencing this fan-out's
	// per-recipient message_ids can be looked up and rewritten.
	bubble *idmap.Bubble
}

// forwardToRoster fans the body out to every ACTIVE (non-paused) roster
// member except the sender by enqueueing one outbound message per
// recipient. fields is the LXMF fields map (FIELD_IMAGE, reactions,
// reply-to, …) to attach, or nil for text-only forwards. Recipients
// with TextOnly set on their roster entry receive the text body alone —
// fields are stripped per-recipient so a single sender's image fans out
// only to members who want it. If the body itself is empty (metadata-
// only forwards like a tap-back reaction) the text-only recipient is
// skipped entirely so we don't deliver an empty bubble to a client that
// won't render the reaction chip anyway. Returns the count of
// recipients enqueued.
//
// The OutboundQueue handles all retry semantics — if a recipient hasn't
// announced yet the queue defers with a path request; if the link
// establishment fails the queue retries up to maxDeliveryAttempts.
// Per-recipient errors are no longer surfaced from this function; they
// surface from the queue's drain loop with the message ID for
// correlation.
func (s *Service) forwardToRoster(senderHex, body string, fields map[any]any, opts forwardOpts) int {
	hashes := s.roster.ActiveHashes()
	enqueued := 0
	for _, h := range hashes {
		if h == senderHex {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			continue
		}
		recipientFields := fields
		if opts.rewrite != nil {
			rw, ok := opts.rewrite(h, recipientFields)
			if !ok {
				continue // recipient has no view of the targeted bubble — skip
			}
			recipientFields = rw
		}
		if s.roster.IsTextOnly(h) {
			recipientFields = nil
			if body == "" {
				continue
			}
		}
		s.outbound.EnqueueBubble(raw, []byte(body), recipientFields, opts.bubble)
		enqueued++
	}
	return enqueued
}

// newBubbleForForward returns a fresh bubble bound to the configured
// id-cache TTL, or nil if the cache isn't installed (the legacy path).
// Returning nil keeps the EnqueueBubble call ergonomic — the queue
// already short-circuits when bubble == nil.
func (s *Service) newBubbleForForward() *idmap.Bubble {
	if s.idmap == nil {
		return nil
	}
	ttl := time.Duration(s.cfg.Service.IDCacheTTL)
	if ttl <= 0 {
		return nil
	}
	return idmap.NewBubble(ttl, s.now())
}
