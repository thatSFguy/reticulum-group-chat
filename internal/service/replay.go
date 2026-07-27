package service

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// replayCooldown is the minimum interval between history replays to the
// same destination.
//
// WHY: /join fires a replay of up to replay.count messages (default
// 100), and handleJoin only refuses callers who are ALREADY members —
// so /leave followed by /join re-arms it indefinitely, and the two
// commands carry distinct message_ids so dedup cannot collapse them.
// One unauthenticated peer could therefore drive 100 queued messages
// (and their full retry budgets) per cycle, indefinitely. Legitimate
// rejoins are rare; a per-destination cooldown makes the amplifier
// unusable while leaving normal use untouched.
const replayCooldown = 10 * time.Minute

// replayLimiter tracks the last replay per destination.
type replayLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newReplayLimiter() *replayLimiter {
	return &replayLimiter{last: map[string]time.Time{}}
}

// allow reports whether a replay to dest may proceed now, recording the
// attempt when it may. Entries older than the cooldown are swept on
// each call, so the map stays proportional to recent joiners.
func (l *replayLimiter) allow(dest string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, t := range l.last {
		if now.Sub(t) > replayCooldown {
			delete(l.last, k)
		}
	}
	if t, ok := l.last[dest]; ok && now.Sub(t) < replayCooldown {
		return false
	}
	l.last[dest] = now
	return true
}

// replayHistoryTo sends recent buffered messages to a newly-joined user.
// Runs in its own goroutine; one slow recipient won't stall the inbox loop.
func (s *Service) replayHistoryTo(joinerHash []byte, now time.Time) {
	if !s.replayLimit.allow(hex.EncodeToString(joinerHash), now) {
		s.logger.Printf("replay suppressed for %x (within %s cooldown)",
			joinerHash[:4], replayCooldown)
		return
	}
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
