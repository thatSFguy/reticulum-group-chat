package service

import (
	"sync"
	"time"
)

// dedupCache remembers recently-seen inbound LXMF message_ids so a message
// delivered more than once — via multiple interfaces, a retransmit, or a
// propagation-node replay — is forwarded only the first time. Reticulum can
// and does redeliver the same message, and neither the transport layer (no
// packet hashlist) nor the LXMF layer dedups, so without this every duplicate
// would be fanned out to the whole roster again — a prime source of the
// duplicate/echoed group messages operators see.
//
// message_id is SHA-256(dest || source || payload) and the payload carries
// the sender's timestamp, so two genuinely distinct sends (even identical
// text) get different ids and are never falsely collapsed; only a true
// redelivery of the same message repeats an id.
//
// In-memory only: a restart drops the table, so a duplicate that straddles a
// restart can still slip through. That window is tiny and acceptable.
type dedupCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newDedupCache(ttl time.Duration, max int) *dedupCache {
	return &dedupCache{seen: make(map[string]time.Time), ttl: ttl, max: max}
}

// seenBefore reports whether id was already recorded within the TTL window.
// On a miss it records id (stamped now) and returns false; on a hit it
// returns true WITHOUT refreshing the timestamp, so a sustained flood of the
// same duplicate can't keep an id alive past its window. A nil cache (or one
// with ttl <= 0) never dedups — the feature is simply off.
func (c *dedupCache) seenBefore(id string, now time.Time) bool {
	if c == nil || c.ttl <= 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[id]; ok && now.Sub(t) < c.ttl {
		return true
	}
	c.seen[id] = now
	if len(c.seen) > c.max {
		c.evictLocked(now)
	}
	return false
}

// evictLocked drops expired entries; if the table is still over cap it is
// cleared wholesale. The wholesale clear is a cheap backstop — worst case a
// handful of just-seen ids are forgotten and a straggler duplicate slips
// through, which the TTL would have released shortly anyway. Called with the
// lock held.
func (c *dedupCache) evictLocked(now time.Time) {
	for id, t := range c.seen {
		if now.Sub(t) >= c.ttl {
			delete(c.seen, id)
		}
	}
	if len(c.seen) > c.max {
		c.seen = make(map[string]time.Time, c.max)
	}
}
