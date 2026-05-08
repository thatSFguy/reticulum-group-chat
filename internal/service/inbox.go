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

	// Refresh last_message_at so prune doesn't sweep an active member.
	if _, err := s.roster.AddOrUpdate(senderBytes, now); err != nil {
		s.logger.Printf("roster update: %v", err)
		return
	}

	senderUser, _ := s.roster.Get(senderHex)
	senderNick := senderUser.Nickname
	if senderNick == "" {
		senderNick = senderHex[:8]
	}

	// Strip C0 controls + DEL from the forwarded copy so a sender can't
	// inject ANSI escape sequences (cursor moves, line clears, color
	// resets) that would mess up receivers' terminals or impersonate
	// other senders' output.
	content = sanitizeForward(content)

	body := "[" + senderNick + "] " + content

	// Delivery.Send routes opportunistic vs link automatically based on
	// payload size, so we no longer need a pre-flight size check or the
	// "message too large" reply path. The MaxInboundChars policy cap
	// above (s.cfg.Service.MaxInboundChars) is the only ceiling on
	// content length that's still enforced here.
	delivered := s.forwardToRoster(senderHex, body)

	if delivered > 0 {
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
