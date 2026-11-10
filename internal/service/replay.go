package service

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/groupinfo"
)

// replayCooldown is the minimum interval between join catch-ups (history
// replay + pinned messages) to the same destination.
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

// sendJoinCatchup delivers everything a new member gets on the way in: the
// recent history replay first, then the pinned-message list.
//
// The pins go LAST, and that is the requirement rather than an accident of
// how the function reads. A joiner's catch-up arrives as a burst of up to
// replay.count separate messages, so anything queued ahead of it is the
// first thing to scroll off — a pins block sent first is a pins block nobody
// reads. Sent after the backlog it is what is on screen when the burst
// stops.
//
// Enqueueing it last is not enough on its own. The outbound queue sends on
// a worker pool and lets a failed message retry behind later ones, so
// enqueue order is not delivery order — the pins could reach the joiner
// mid-replay or ahead of it. EnqueueAfterEarlier holds the pins message
// until every replay message to this joiner has left the queue, which is
// what actually makes "last" true on the wire.
//
// One message for the whole list, not one per pin: a fan-out of N pins to
// every joiner would multiply the /join amplifier this file already exists
// to bound, each entry carrying its own retry budget.
//
// Runs in its own goroutine; one slow recipient won't stall the inbox loop.
func (s *Service) sendJoinCatchup(joinerHash []byte, now time.Time) {
	cfg := s.cfg.Replay
	pinned := ""
	if cfg.PinsOnJoin && s.info != nil {
		pinned = groupinfo.Render(s.info.Pins(), now)
	}
	// Check for "nothing to send" BEFORE consuming the limiter. A group
	// with replay off and no pins would otherwise record a cooldown for a
	// joiner it sent nothing to, so the first pin a mod added afterwards
	// would be silently withheld from anyone who joined in the last ten
	// minutes.
	if cfg.Count <= 0 && pinned == "" {
		return
	}
	if !s.replayLimit.allow(hex.EncodeToString(joinerHash), now) {
		s.logger.Debugf("join catch-up suppressed for %x (within %s cooldown)",
			joinerHash[:4], replayCooldown)
		return
	}

	if cfg.Count > 0 {
		cutoff := time.Time{}
		if cfg.MaxAge.Std() > 0 {
			cutoff = now.Add(-cfg.MaxAge.Std())
		}
		for _, e := range s.history.SinceOldest(cutoff) {
			body := fmt.Sprintf("[replay %s] [%s] %s",
				humanizeAge(now.Sub(e.At)),
				e.SenderNick,
				sanitizeForward(e.Content),
			)
			s.outbound.Enqueue(joinerHash, []byte(body))
		}
	}

	if pinned != "" {
		// groupinfo.Render already scrubs control bytes out of pin text;
		// sanitizeForward is applied anyway because it is the one function
		// every byte this service puts on the wire passes through, and an
		// exception to that rule is not worth the saved microsecond.
		s.outbound.EnqueueAfterEarlier(joinerHash, []byte(sanitizeForward(pinned)))
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

// groupInfoPath sites the group description + pin store beside the roster,
// mirroring announceStorePath. Both are per-instance derived state that an
// operator moving state_path expects to move with it, and neither is worth
// a config key of its own.
func groupInfoPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "groupinfo.json")
}
