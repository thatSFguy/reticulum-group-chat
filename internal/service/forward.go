package service

import (
	"encoding/hex"
)

// forwardToRoster fans the body out to every ACTIVE (non-paused) roster
// member except the sender by enqueueing one outbound message per
// recipient. fields is the LXMF fields map (FIELD_IMAGE, …) to attach,
// or nil for text-only forwards. Recipients with TextOnly set on their
// roster entry receive the text body alone — fields are stripped per-
// recipient so a single sender's image fans out only to members who
// want it. Returns the count of recipients enqueued.
//
// The OutboundQueue handles all retry semantics — if a recipient hasn't
// announced yet the queue defers with a path request; if the link
// establishment fails the queue retries up to maxDeliveryAttempts.
// Per-recipient errors are no longer surfaced from this function; they
// surface from the queue's drain loop with the message ID for
// correlation.
func (s *Service) forwardToRoster(senderHex, body string, fields map[any]any) int {
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
		if s.roster.IsTextOnly(h) {
			recipientFields = nil
		}
		s.outbound.EnqueueWithFields(raw, []byte(body), recipientFields)
		enqueued++
	}
	return enqueued
}
