package service

import (
	"strconv"
	"testing"
	"time"
)

func TestDedupFirstSeenThenDuplicate(t *testing.T) {
	c := newDedupCache(time.Hour, 100)
	t0 := time.Now()
	if c.seenBefore("abc", t0) {
		t.Fatal("first sighting should not be a duplicate")
	}
	if !c.seenBefore("abc", t0.Add(time.Minute)) {
		t.Fatal("second sighting within the window should be a duplicate")
	}
	// A different id is independent.
	if c.seenBefore("def", t0.Add(time.Minute)) {
		t.Fatal("distinct id should not be a duplicate")
	}
}

func TestDedupExpiresAfterWindow(t *testing.T) {
	c := newDedupCache(time.Hour, 100)
	t0 := time.Now()
	c.seenBefore("abc", t0)
	// Same id, but past the TTL — should be treated as new again.
	if c.seenBefore("abc", t0.Add(time.Hour+time.Second)) {
		t.Fatal("id past the TTL window should not count as a duplicate")
	}
}

func TestDedupDisabledOrNil(t *testing.T) {
	// ttl <= 0 disables dedup: every sighting is "new".
	c := newDedupCache(0, 100)
	t0 := time.Now()
	if c.seenBefore("abc", t0) || c.seenBefore("abc", t0) {
		t.Error("dedup with ttl=0 must never report a duplicate")
	}
	// A nil cache is the "feature off" case and must be safe to call.
	var nilCache *dedupCache
	if nilCache.seenBefore("abc", t0) {
		t.Error("nil dedup cache must never report a duplicate")
	}
}

func TestDedupEvictionStaysUnderControl(t *testing.T) {
	c := newDedupCache(time.Hour, 8)
	t0 := time.Now()
	// Insert well past the cap, all within the window; eviction should keep
	// the map from growing without bound (expired sweep + wholesale clear).
	for i := 0; i < 100; i++ {
		c.seenBefore("id-"+strconv.Itoa(i), t0)
	}
	c.mu.Lock()
	n := len(c.seen)
	c.mu.Unlock()
	if n > 8 {
		t.Errorf("dedup map = %d entries, expected <= cap (8) after eviction", n)
	}
}
