package idmap

import (
	"strconv"
	"testing"
	"time"
)

func TestLookupAfterRegisterView(t *testing.T) {
	c := New(time.Hour, 100)
	b := NewBubble(time.Hour, time.Now())

	c.RegisterView(b, "recipientA", "msgID-A-view")
	c.RegisterView(b, "recipientB", "msgID-B-view")

	if got := c.Lookup("msgID-A-view"); got != b {
		t.Errorf("Lookup msgID-A-view = %v, want bubble", got)
	}
	if got := c.Lookup("msgID-B-view"); got != b {
		t.Errorf("Lookup msgID-B-view = %v, want bubble", got)
	}
	if got, _ := b.ViewFor("recipientA"); got != "msgID-A-view" {
		t.Errorf("ViewFor recipientA = %q, want msgID-A-view", got)
	}
}

func TestLookupMissing(t *testing.T) {
	c := New(time.Hour, 100)
	if got := c.Lookup("nope"); got != nil {
		t.Errorf("Lookup missing = %v, want nil", got)
	}
}

func TestTTLExpiry(t *testing.T) {
	c := New(50*time.Millisecond, 100)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	b := NewBubble(50*time.Millisecond, now)
	c.RegisterView(b, "r", "msgID-1")

	// Just before TTL — still there.
	c.now = func() time.Time { return now.Add(49 * time.Millisecond) }
	if got := c.Lookup("msgID-1"); got == nil {
		t.Error("Lookup before TTL = nil, want bubble")
	}

	// Past TTL — gone.
	c.now = func() time.Time { return now.Add(60 * time.Millisecond) }
	if got := c.Lookup("msgID-1"); got != nil {
		t.Errorf("Lookup past TTL = %v, want nil", got)
	}
}

func TestLRUEvictionRespectsCap(t *testing.T) {
	// Cap of 3 ENTRIES (not bubbles). Register 4 distinct bubbles,
	// each with one view — the oldest should be evicted.
	c := New(time.Hour, 3)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	bubbles := make([]*Bubble, 4)
	for i := range bubbles {
		b := NewBubble(time.Hour, now)
		bubbles[i] = b
		c.RegisterView(b, "r", "msg-"+strconv.Itoa(i))
	}

	if c.Lookup("msg-0") != nil {
		t.Error("oldest entry should have been evicted by cap")
	}
	for i := 1; i < 4; i++ {
		if got := c.Lookup("msg-" + strconv.Itoa(i)); got != bubbles[i] {
			t.Errorf("msg-%d Lookup = %v, want bubble", i, got)
		}
	}
}

func TestLookupTouchesLRU(t *testing.T) {
	// 3-entry cap. Insert A, B, C; touch A; then insert D. A should
	// survive (just-used), B should be evicted.
	c := New(time.Hour, 3)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	a := NewBubble(time.Hour, now)
	b := NewBubble(time.Hour, now)
	ce := NewBubble(time.Hour, now)
	d := NewBubble(time.Hour, now)
	c.RegisterView(a, "r", "A")
	c.RegisterView(b, "r", "B")
	c.RegisterView(ce, "r", "C")

	// Touch A.
	if c.Lookup("A") != a {
		t.Fatal("Lookup A failed before D inserted")
	}
	c.RegisterView(d, "r", "D")

	if c.Lookup("A") != a {
		t.Error("recently-touched A should not have been evicted")
	}
	if c.Lookup("B") != nil {
		t.Error("oldest B should have been evicted, not survived")
	}
}

func TestRegisterViewWithNilOrEmptyIsNoop(t *testing.T) {
	c := New(time.Hour, 100)
	c.RegisterView(nil, "r", "msg")
	c.RegisterView(NewBubble(time.Hour, time.Now()), "r", "")
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0 after no-op RegisterView calls", c.Len())
	}
}

func TestRegisterViewCapZeroDisablesCap(t *testing.T) {
	c := New(time.Hour, 0)
	for i := 0; i < 1000; i++ {
		b := NewBubble(time.Hour, time.Now())
		c.RegisterView(b, "r", "msg-"+strconv.Itoa(i))
	}
	if got := c.Len(); got != 1000 {
		t.Errorf("Len with cap=0 = %d, want 1000", got)
	}
}

func TestViewForReturnsOkFalseForUnknownRecipient(t *testing.T) {
	c := New(time.Hour, 100)
	b := NewBubble(time.Hour, time.Now())
	c.RegisterView(b, "alice", "msgID")

	if _, ok := b.ViewFor("alice"); !ok {
		t.Error("ViewFor(alice) ok=false, want true")
	}
	if _, ok := b.ViewFor("bob"); ok {
		t.Error("ViewFor(bob) ok=true, want false (bob wasn't a fan-out target)")
	}
}
