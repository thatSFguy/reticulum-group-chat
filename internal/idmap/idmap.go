// Package idmap is a TTL'd in-memory store that maps LXMF message_ids
// to the per-recipient views computed during fan-out forwarding. It
// exists to make tap-back reactions, comments, continuations and
// reply-to fields (fields[0x40]/[0x41]/[0x42] inner 0x00 /
// fields[0x30]) bind on receiving clients in a rebroadcast-model relay.
//
// The fundamental problem: LXMF message_id is SHA-256(dest||source||
// payload). When fwdsvc re-emits a relayed bubble under its own
// identity, every recipient computes a DIFFERENT message_id because
// dest_hash differs per recipient (and the timestamp inside the payload
// differs per Send). A reactor's idea of the original message_id
// therefore cannot bind on any other recipient's local store.
//
// Cache lifecycle:
//
//   - At fan-out time, the forwarder creates a Bubble for each original
//     inbound message. As each per-recipient Send succeeds, the
//     forwarder calls AddView(recipient, msgID) on the bubble and
//     Index(msgID, bubble) on the cache.
//   - On inbound reactions/replies, the forwarder looks up the
//     bubble by reaction_to / reply-to message_id, then rewrites the
//     field per receiving recipient using bubble.ViewFor(recipient).
//   - Entries expire after TTL. The cache is in-memory only — a service
//     restart drops the table and pre-restart messages can no longer
//     bind reactions or replies (acceptable; bounded by TTL anyway).
package idmap

import (
	"container/list"
	"sync"
	"time"
)

// Bubble is one relayed inbound message, with the per-recipient
// message_ids that fwdsvc handed to each fan-out recipient. The
// bubble lives in the Cache.byMsgID index under every recipient's
// view of its id, plus a single LRU list entry for eviction.
//
// Bubbles are mutable until their TTL expires — reactions arriving
// after fan-out add no new views, but a slow late Send (queued behind
// other recipients) may still register its view here.
type Bubble struct {
	// views maps a recipient's destination_hash (hex, lowercase) to
	// the LXMF message_id (hex, lowercase) that recipient will compute
	// when they parse the body we sent them.
	views map[string]string

	expiresAt time.Time

	// lru holds this bubble's element in the cache's eviction list,
	// or nil before the first Index call.
	lru *list.Element
}

// NewBubble returns an empty bubble with no recipient views recorded
// yet. Add views via Cache.RegisterView once a per-recipient Send
// succeeds and we know the message_id that recipient will compute.
func NewBubble(ttl time.Duration, now time.Time) *Bubble {
	return &Bubble{
		views:     make(map[string]string, 4),
		expiresAt: now.Add(ttl),
	}
}

// ViewFor returns the message_id (hex) recipient_hex will compute for
// this bubble, and true if we registered it. If the recipient was not
// among the fan-out targets we have no view to give and the second
// return is false — the caller should skip the rewrite (or skip the
// recipient entirely, depending on its semantics).
func (b *Bubble) ViewFor(recipientHex string) (msgIDHex string, ok bool) {
	v, ok := b.views[recipientHex]
	return v, ok
}

// Cache is an LRU+TTL store: every Bubble lives under each of its
// registered recipient-view message_ids, evicted whichever-first by
// expiry or hard size cap. The zero value is not usable — call New.
type Cache struct {
	ttl     time.Duration
	maxSize int

	mu        sync.Mutex
	byMsgID   map[string]*Bubble // msg_id_hex (any recipient's view) → bubble
	lru       *list.List         // front = newest; back = oldest
	now       func() time.Time
}

// New returns a Cache with the given TTL and maximum entry count.
//
// maxSize counts ENTRIES (distinct msg_id keys), not bubbles —
// fan-out to 64 recipients creates 64 entries pointing at one bubble.
// Set maxSize so it can hold (typical roster size) × (expected per-TTL
// message rate). 0 disables the cap (only TTL evicts); negative is
// treated as 0.
//
// TTL must be > 0; otherwise New returns a Cache that immediately
// expires every entry.
func New(ttl time.Duration, maxSize int) *Cache {
	if maxSize < 0 {
		maxSize = 0
	}
	return &Cache{
		ttl:     ttl,
		maxSize: maxSize,
		byMsgID: make(map[string]*Bubble),
		lru:     list.New(),
		now:     time.Now,
	}
}

// RegisterView records a single fan-out outcome: "the bubble we
// stored as `b` was sent to recipient recipientHex and the recipient
// will compute msgIDHex as its message_id." Indexes the bubble under
// msgIDHex and refreshes its position in the LRU.
//
// Safe to call concurrently from multiple OutboundQueue workers.
func (c *Cache) RegisterView(b *Bubble, recipientHex, msgIDHex string) {
	if b == nil || msgIDHex == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictExpiredLocked()

	b.views[recipientHex] = msgIDHex
	c.byMsgID[msgIDHex] = b

	if b.lru == nil {
		b.lru = c.lru.PushFront(b)
	} else {
		c.lru.MoveToFront(b.lru)
	}

	c.enforceCapLocked()
}

// Lookup returns the bubble registered under msgIDHex (any recipient's
// view of an originally-relayed message), or nil if no entry exists or
// the entry has expired. Reads touch the LRU so a heavily-referenced
// bubble stays warm.
func (c *Cache) Lookup(msgIDHex string) *Bubble {
	c.mu.Lock()
	defer c.mu.Unlock()

	b, ok := c.byMsgID[msgIDHex]
	if !ok {
		return nil
	}
	if c.now().After(b.expiresAt) {
		c.removeBubbleLocked(b)
		return nil
	}
	if b.lru != nil {
		c.lru.MoveToFront(b.lru)
	}
	return b
}

// Len returns the current number of indexed message_id keys. Sum of
// (views per bubble) across all live bubbles; not the bubble count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byMsgID)
}

// evictExpiredLocked walks the LRU from oldest to newest and drops
// any bubble whose TTL has lapsed. Cheap on a healthy cache (the
// oldest entry is either expired or close to it, and we stop at the
// first survivor); pathological skew toward never-evicted live
// bubbles could in theory keep expired siblings around, but in
// practice fwdsvc's TTL is uniform so the LRU and expiry orders
// align closely.
func (c *Cache) evictExpiredLocked() {
	now := c.now()
	for el := c.lru.Back(); el != nil; el = c.lru.Back() {
		b := el.Value.(*Bubble)
		if !now.After(b.expiresAt) {
			return
		}
		c.removeBubbleLocked(b)
	}
}

// enforceCapLocked drops oldest bubbles until len(byMsgID) <= maxSize.
// No-op when maxSize == 0.
func (c *Cache) enforceCapLocked() {
	if c.maxSize <= 0 {
		return
	}
	for len(c.byMsgID) > c.maxSize {
		el := c.lru.Back()
		if el == nil {
			return
		}
		c.removeBubbleLocked(el.Value.(*Bubble))
	}
}

// removeBubbleLocked unlinks a bubble from every map key + the LRU.
// Caller holds c.mu.
func (c *Cache) removeBubbleLocked(b *Bubble) {
	for _, msgID := range b.views {
		delete(c.byMsgID, msgID)
	}
	if b.lru != nil {
		c.lru.Remove(b.lru)
		b.lru = nil
	}
}
