package service

import (
	"fmt"
	"time"
)

// replayHistoryTo sends recent buffered messages to a newly-joined user.
// Runs in its own goroutine; one slow recipient won't stall the inbox loop.
func (s *Service) replayHistoryTo(joinerHash []byte, now time.Time) {
	cfg := s.cfg.Replay
	cutoff := time.Time{}
	if cfg.MaxAge.Std() > 0 {
		cutoff = now.Add(-cfg.MaxAge.Std())
	}
	entries := s.history.SinceOldest(cutoff)
	if len(entries) == 0 {
		return
	}

	for _, e := range entries {
		body := fmt.Sprintf("[replay %s] [%s] %s",
			humanizeAge(now.Sub(e.At)),
			e.SenderNick,
			sanitizeForward(e.Content),
		)
		s.outbound.Enqueue(joinerHash, []byte(body))
	}
}

// humanizeAge renders a duration as "5s", "12m", "3h", "4d". Always rounds
// down — for replay context that's clearer than rounding-up artifacts.
func humanizeAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
