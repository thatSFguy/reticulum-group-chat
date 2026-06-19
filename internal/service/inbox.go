package service

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/commands"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/history"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
)

// onLXMFReceived is the lxmf.Delivery callback for verified inbound
// messages. Banlist drops happen here (post-verify so banned users still
// can't impersonate someone else), then commands route to the dispatcher
// and ordinary messages forward to the roster + append to history.
func (s *Service) onLXMFReceived(msg *lxmf.Message) {
	now := s.now()
	senderBytes := msg.SourceHash
	senderHex := hex.EncodeToString(senderBytes)

	// Diagnostic: dump the inbound shape (sender prefix, content length,
	// raw fields-map key list with concrete Go types). Lets us see exactly
	// what the wire is delivering when reactions / replies vanish before
	// the rewrite stage. Will be tightened once cross-client reaction
	// interop is stable.
	if len(msg.Fields) > 0 || len(msg.Content) == 0 {
		fieldKeys := make([]string, 0, len(msg.Fields))
		for k := range msg.Fields {
			fieldKeys = append(fieldKeys, fmt.Sprintf("%v(%T)", k, k))
		}
		s.logger.Printf("inbound LXMF: from=%s content_len=%d field_keys=%v",
			senderHex[:8], len(msg.Content), fieldKeys)
	}

	if s.roster.IsBanned(senderBytes) {
		s.logger.Printf("dropping banned sender %s", senderHex[:8])
		return
	}

	// Log the full sender hash on first contact so operators can find it
	// (e.g. to add a user to the admins/mods list) without digging into
	// state.json. Subsequent messages from the same sender don't re-log.
	if !s.roster.Has(senderBytes) {
		s.logger.Printf("new sender contact: full dest_hash = %s", senderHex)
	}

	// Any inbound traffic from a member — a command, an over-limit
	// message, or a message from a paused member — counts as activity so
	// Prune doesn't sweep a demonstrably present user. Most of those
	// paths return before the forward step below, so the refresh has to
	// happen up here. No-op for non-members (they must /join before
	// anything counts).
	if _, err := s.roster.Touch(senderBytes, now); err != nil {
		s.logger.Printf("roster touch: %v", err)
	}

	content := strings.TrimRight(string(msg.Content), "\r\n")

	// Commands route to the dispatcher regardless of membership state —
	// the dispatcher's helpers (like /join, /?) need to handle non-
	// members. The dispatcher returns role/membership-aware replies.
	if commands.IsCommand(content) {
		parsed := commands.Parse(content)
		s.logger.Printf("cmd from=%s name=/%s argc=%d",
			senderHex[:8], parsed.Name, len(parsed.Args))
		reply := s.dispatcher.Dispatch(senderHex, parsed)
		if reply != "" {
			id := s.outbound.Enqueue(senderBytes, []byte(reply))
			s.logger.Printf("cmd reply queued: to=%s name=/%s reply_len=%d id=%s",
				senderHex[:8], parsed.Name, len(reply), id)
		}
		return
	}

	// Non-command path. Apply the per-message char cap first.
	if s.cfg.Service.MaxInboundChars > 0 {
		if charCount := utf8.RuneCountInString(content); charCount > s.cfg.Service.MaxInboundChars {
			s.replyOverInboundLimit(senderBytes, charCount)
			return
		}
	}

	// Non-members get an invitation, NOT auto-joined. They have to
	// explicitly send /join to participate.
	if !s.roster.Has(senderBytes) {
		s.replyInvite(senderBytes)
		return
	}

	// Paused members get a notice; their message isn't forwarded and
	// isn't appended to history.
	if s.roster.IsPaused(senderHex) {
		s.replyPaused(senderBytes)
		return
	}

	// last_message_at was already refreshed by the Touch above (which
	// runs for every member, paused or not), so the forward path doesn't
	// need to re-update the roster here.
	senderUser, _ := s.roster.Get(senderHex)
	senderNick := senderUser.Nickname
	if senderNick == "" {
		senderNick = senderHex[:8]
	}

	// Strip C0 controls + DEL from the forwarded copy so a sender can't
	// inject ANSI escape sequences (cursor moves, line clears, color
	// resets) that would mess up receivers' terminals or impersonate
	// other senders' output. Applied to the text body only — field
	// values (image bytes, …) pass through raw.
	content = sanitizeForward(content)

	// Apply the operator's attachment policy. Disallowed keys drop
	// silently; oversized values drop with a "[image not forwarded: …]"
	// suffix appended to the body so recipients know the sender tried.
	fwdFields, drops := filterAttachments(msg.Fields, s.cfg.Service)

	// Compose the forwarded body. Reactions (FIELD_REACTION 0x40) and
	// reply-to-only messages can arrive with content=""
	// — the metadata IS the field payload, and clients render the chip
	// on the original message bubble. In that case the "[nick] " prefix
	// would broadcast a trailing-space empty bubble, so we omit it and
	// forward an empty body alongside the fields.
	var body string
	if content != "" {
		body = "[" + senderNick + "] " + content
	}
	for _, note := range drops {
		s.logger.Printf("attachment dropped: from=%s %s", senderHex[:8], note)
		if body == "" {
			body = note
		} else {
			body += " " + note
		}
	}

	// If a metadata-only message (e.g. a reaction) had all its fields
	// stripped by the operator policy, there's nothing left to deliver
	// — bail out so we don't fan out empty bubbles to every member.
	if body == "" && len(fwdFields) == 0 {
		s.logger.Printf("inbound LXMF: bailing — empty body and no fields survived filter (from=%s msg_fields_in=%d, allowlist=%v)",
			senderHex[:8], len(msg.Fields), s.cfg.Service.ForwardedFields)
		return
	}

	// Detect inbound reactions and reply-to fields targeting an earlier
	// fan-out we cached. When the lookup succeeds we get a per-recipient
	// rewrite closure that lets forwardToRoster substitute each
	// recipient's view of the target message_id. On a cache miss the
	// closure is nil and forwarding falls back to byte-for-byte
	// passthrough (which won't bind — see Limitations in README).
	opts := forwardOpts{rewrite: s.buildRewrite(fwdFields)}

	// Register a new bubble for primary, reactable bubbles — text
	// messages AND image/attachment messages (which arrive with
	// content=="" but ARE reacted to). Reactions and bare replies are
	// excluded: they annotate an existing bubble rather than being one,
	// and keeping them out of the cache prevents reaction-of-reaction
	// chains from thrashing the table.
	if isPrimaryBubble(content, fwdFields) {
		opts.bubble = s.newBubbleForForward()
		// Pre-register the original sender's view of THIS message — fwdsvc
		// already knows it (= msg.MessageID(), the same value the sender
		// computed for what they sent us). Without this, when somebody
		// else reacts to this bubble and the reaction fans out back to
		// the original sender, the rewrite would miss the sender's view
		// (sender was never a fan-out recipient) and we'd skip them
		// entirely — meaning the originator of a message never sees the
		// reactions to it. This is the load-bearing fix for the common
		// 2-person case.
		if opts.bubble != nil && s.idmap != nil {
			senderMsgIDHex := hex.EncodeToString(msg.MessageID())
			s.idmap.RegisterView(opts.bubble, senderHex, senderMsgIDHex)
			s.logger.Printf("idmap: registered sender view from=%s msgid=%s",
				senderHex[:8], senderMsgIDHex[:8])
		}
	}

	// Stamp the original reactor's identity onto relayed reactions. A
	// reaction has no body to carry the "[nick]" prefix, and per SPEC
	// §5.9.8 attribution is the carrying LXMF's source identity — which,
	// after we re-sign and re-emit, is fwdsvc. Without this stamp every
	// relayed reaction collapses onto the service identity. The
	// originator-identity custom fields (0xFB/0xFC) let cooperating
	// clients attribute it to the reactor instead. Reactions only;
	// replies/comments/continuations carry a body and need no stamp.
	//
	// Done here (after the isPrimaryBubble check, before fan-out) on
	// purpose: the custom-field keys aren't reaction markers, so
	// stamping earlier would make isPrimaryBubble treat an empty-content
	// reaction as a reactable bubble. The per-recipient rewrite closure
	// clones these fields through unchanged.
	if hasReactionField(fwdFields) {
		if idh := s.reactorIdentityHash(senderBytes); stampReactorIdentity(fwdFields, idh) {
			s.logger.Printf("reaction relay: stamped originator-identity=%s for %s",
				hex.EncodeToString(idh), senderHex[:8])
		} else {
			s.logger.Printf("reaction relay: no recalled identity for %s — attribution falls back to source",
				senderHex[:8])
		}
	}

	// Delivery.Send routes opportunistic vs link automatically based on
	// payload size, so we no longer need a pre-flight size check or the
	// "message too large" reply path. The MaxInboundChars policy cap
	// above (s.cfg.Service.MaxInboundChars) is the only ceiling on
	// content length that's still enforced here.
	delivered := s.forwardToRoster(senderHex, body, fwdFields, opts)

	// Reactions and bare reply-to messages have no visible text — keep
	// them out of the replay buffer so a freshly-joining member doesn't
	// see a bunch of orphan "" bubbles without the original messages
	// they refer to.
	if delivered > 0 && content != "" {
		_ = s.history.Append(history.Entry{
			At:         now,
			SenderHash: senderHex,
			SenderNick: senderNick,
			Content:    content,
		})
	}
}

// replyInvite tells a non-member how to join. Sent on every non-command
// message from a non-member; the message itself isn't forwarded.
func (s *Service) replyInvite(senderBytes []byte) {
	const msg = "Welcome. To join this chat send /join. Send /? for help. Until you join, your messages aren't forwarded."
	s.outbound.Enqueue(senderBytes, []byte(msg))
}

// replyPaused tells a paused member that their non-command message
// wasn't forwarded.
func (s *Service) replyPaused(senderBytes []byte) {
	const msg = "You're paused. Your message wasn't forwarded. Send /resume to come back."
	s.outbound.Enqueue(senderBytes, []byte(msg))
}

// replyOverInboundLimit notifies a sender that their message exceeded
// the configured per-message character cap (service.max_inbound_chars).
// The message is dropped — not forwarded, not added to history, and
// the sender is not joined to the roster on the strength of an
// oversized first message.
func (s *Service) replyOverInboundLimit(senderBytes []byte, charCount int) {
	limit := s.cfg.Service.MaxInboundChars
	msg := fmt.Sprintf("Message rejected: limit is %d characters per message, yours was %d. Please shorten and resend.",
		limit, charCount)
	s.outbound.Enqueue(senderBytes, []byte(msg))
}
