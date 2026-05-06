package service

import "encoding/hex"

// forwardToRoster fans the body out to every roster member except the
// sender. Each Send drops silently with a log entry if the recipient
// hasn't announced yet (we can't encrypt to an unknown public key).
// Returns the count of recipients we successfully queued sends for.
func (s *Service) forwardToRoster(senderHex, body string) int {
	hashes := s.roster.Hashes()
	delivered := 0
	for _, h := range hashes {
		if h == senderHex {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			continue
		}
		if err := s.delivery.Send(raw, nil, []byte(body), nil); err != nil {
			s.logger.Printf("forward to %s: %v", h[:8], err)
			continue
		}
		delivered++
	}
	return delivered
}
