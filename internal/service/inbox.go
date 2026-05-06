package service

import (
	"encoding/hex"
	"strings"

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

	content := strings.TrimRight(string(msg.Content), "\r\n")

	if commands.IsCommand(content) {
		parsed := commands.Parse(content)
		reply := s.dispatcher.Dispatch(senderHex, parsed)
		if reply != "" {
			if err := s.delivery.Send(senderBytes, nil, []byte(reply), nil); err != nil {
				s.logger.Printf("command reply send: %v", err)
			}
		}
		return
	}

	isNewOrReturning, err := s.roster.AddOrUpdate(senderBytes, now)
	if err != nil {
		s.logger.Printf("roster update: %v", err)
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

	body := "[" + senderNick + "] " + content
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
