package service

import (
	"encoding/hex"
	"strings"

	"github.com/svanichkin/go-lxmf/lxmf"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/commands"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/history"
)

// onLXMFReceived is the LXMRouter delivery callback. Each inbound LXMF
// message lands here.
func (s *Service) onLXMFReceived(msg *lxmf.LXMessage) {
	now := s.now()
	senderBytes := msg.SourceHash
	if len(senderBytes) != 16 {
		s.logger.Printf("dropping message with malformed source hash (len=%d)", len(senderBytes))
		return
	}
	senderHex := hexHash(senderBytes)

	if s.roster.IsBanned(senderBytes) {
		s.logger.Printf("dropping banned sender %s", senderHex[:8])
		return
	}

	content := strings.TrimRight(string(msg.Content), "\r\n")

	if commands.IsCommand(content) {
		parsed := commands.Parse(content)
		reply := s.dispatcher.Dispatch(senderHex, parsed)
		if reply != "" {
			s.sendDirect(senderBytes, "", reply)
		}
		return
	}

	isNewOrReturning, err := s.roster.AddOrUpdate(senderBytes, now)
	if err != nil {
		s.logger.Printf("roster update failed for %s: %v", senderHex[:8], err)
		return
	}

	if isNewOrReturning && s.cfg.Replay.Count > 0 {
		go s.replayHistoryTo(senderBytes, now)
	}

	senderUser, _ := s.roster.Get(senderHex)
	senderNick := senderUser.Nickname
	if senderNick == "" {
		senderNick = senderHex[:8]
	}

	recipients := s.forwardRecipients(senderHex)
	if len(recipients) == 0 {
		return
	}

	body := "[" + senderNick + "] " + content
	for _, r := range recipients {
		s.sendDirect(r, "", body)
	}

	_ = s.history.Append(history.Entry{
		At:         now,
		SenderHash: senderHex,
		SenderNick: senderNick,
		Content:    content,
	})
}

// forwardRecipients returns every roster member's identity hash bytes,
// excluding the original sender.
func (s *Service) forwardRecipients(senderHex string) [][]byte {
	hashes := s.roster.Hashes()
	out := make([][]byte, 0, len(hashes))
	for _, h := range hashes {
		if h == senderHex {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			continue
		}
		out = append(out, raw)
	}
	return out
}
