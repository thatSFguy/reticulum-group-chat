package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/groupinfo"
	"github.com/thatSFguy/reticulum-group-chat/internal/history"
)

// enqueuedBodies snapshots the outbound queue in enqueue order. The queue's
// Run loop is never started in these tests, so nothing drains and `pending`
// is exactly what sendJoinCatchup put there. That is enqueue order, NOT
// delivery order — the queue sends in parallel and retries out of order —
// so the delivery-order guarantee is tested separately, by
// TestJoinCatchupPinsWaitForTheReplayToDrain.
func enqueuedBodies(t *testing.T, svc *Service, recipient []byte) []string {
	t.Helper()
	svc.outbound.mu.Lock()
	defer svc.outbound.mu.Unlock()
	var out []string
	for _, m := range svc.outbound.pending {
		if bytes.Equal(m.Recipient, recipient) {
			out = append(out, string(m.Body))
		}
	}
	return out
}

func seedHistory(t *testing.T, svc *Service, now time.Time, texts ...string) {
	t.Helper()
	for i, txt := range texts {
		err := svc.history.Append(history.Entry{
			At:         now.Add(-time.Duration(len(texts)-i) * time.Minute),
			SenderHash: "00112233445566778899aabbccddeeff",
			SenderNick: "kim",
			Content:    txt,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestJoinCatchupSendsPinsAfterTheReplay is the ordering requirement.
//
// A joiner's catch-up is a burst of separate messages, so whatever is queued
// first is the first thing to scroll off their screen. The pins block has to
// be the LAST thing enqueued or it is the one part of the burst nobody sees
// — which would defeat the reason it is played back on join at all.
func TestJoinCatchupSendsPinsAfterTheReplay(t *testing.T) {
	svc := newTestService(t, "")
	now := svc.now()
	seedHistory(t, svc, now, "first message", "second message", "third message")
	if err := svc.info.AddPin(groupinfo.Pin{At: now.Add(-2 * time.Hour), ByNick: "kim", Text: "net at 20:00"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.info.AddPin(groupinfo.Pin{At: now.Add(-time.Hour), ByNick: "kim", Text: "repeater is on 2m"}); err != nil {
		t.Fatal(err)
	}

	joiner := bytes.Repeat([]byte{0xAB}, 16)
	svc.sendJoinCatchup(joiner, now)

	bodies := enqueuedBodies(t, svc, joiner)
	if len(bodies) != 4 {
		t.Fatalf("enqueued %d messages, want 3 replay + 1 pins block:\n%s",
			len(bodies), strings.Join(bodies, "\n---\n"))
	}
	for i, b := range bodies[:3] {
		if !strings.HasPrefix(b, "[replay ") {
			t.Errorf("message %d is not a replay entry: %q", i, b)
		}
	}
	last := bodies[3]
	if !strings.HasPrefix(last, "Pinned (2):") {
		t.Fatalf("last message is not the pins block: %q", last)
	}
	// One message for the whole list, not one per pin — a per-pin fan-out
	// would multiply the /join amplifier the replay cooldown bounds.
	for _, want := range []string{"1. [kim, 2h] net at 20:00", "2. [kim, 1h] repeater is on 2m"} {
		if !strings.Contains(last, want) {
			t.Errorf("pins block missing %q:\n%s", want, last)
		}
	}
}

// TestJoinCatchupSendsPinsWithReplayDisabled: the old gate on the caller
// side was `if Replay.Count > 0`, which would have skipped pins entirely for
// a group that runs with replay off.
func TestJoinCatchupSendsPinsWithReplayDisabled(t *testing.T) {
	svc := newTestService(t, "\n[replay]\ncount = 0\n")
	now := svc.now()
	seedHistory(t, svc, now, "should not be replayed")
	if err := svc.info.AddPin(groupinfo.Pin{At: now, Text: "read the rules"}); err != nil {
		t.Fatal(err)
	}

	joiner := bytes.Repeat([]byte{0xAC}, 16)
	svc.sendJoinCatchup(joiner, now)

	bodies := enqueuedBodies(t, svc, joiner)
	if len(bodies) != 1 {
		t.Fatalf("enqueued %d messages with replay off, want just the pins block:\n%s",
			len(bodies), strings.Join(bodies, "\n---\n"))
	}
	if !strings.HasPrefix(bodies[0], "Pinned (1):") {
		t.Errorf("only message is not the pins block: %q", bodies[0])
	}
}

func TestJoinCatchupHonoursPinsOnJoinFalse(t *testing.T) {
	svc := newTestService(t, "\n[replay]\npins_on_join = false\n")
	now := svc.now()
	seedHistory(t, svc, now, "a message")
	if err := svc.info.AddPin(groupinfo.Pin{At: now, Text: "read the rules"}); err != nil {
		t.Fatal(err)
	}

	joiner := bytes.Repeat([]byte{0xAD}, 16)
	svc.sendJoinCatchup(joiner, now)

	for _, b := range enqueuedBodies(t, svc, joiner) {
		if strings.Contains(b, "Pinned") || strings.Contains(b, "read the rules") {
			t.Errorf("pins_on_join = false still sent the pins block: %q", b)
		}
	}
}

// TestJoinCatchupWithNothingToSendKeepsTheCooldown guards the ordering of
// the two guards inside sendJoinCatchup. Consuming the per-destination
// cooldown for a catch-up that sent nothing would silently withhold the
// first pin a mod adds from anyone who joined in the preceding ten minutes.
func TestJoinCatchupWithNothingToSendKeepsTheCooldown(t *testing.T) {
	svc := newTestService(t, "\n[replay]\ncount = 0\n")
	now := svc.now()
	joiner := bytes.Repeat([]byte{0xAE}, 16)

	svc.sendJoinCatchup(joiner, now) // nothing set: no replay, no pins
	if got := enqueuedBodies(t, svc, joiner); len(got) != 0 {
		t.Fatalf("empty catch-up enqueued %d messages", len(got))
	}

	if err := svc.info.AddPin(groupinfo.Pin{At: now, Text: "read the rules"}); err != nil {
		t.Fatal(err)
	}
	svc.sendJoinCatchup(joiner, now.Add(time.Second))
	if got := enqueuedBodies(t, svc, joiner); len(got) != 1 {
		t.Fatalf("after a pin was added, catch-up enqueued %d messages, want 1", len(got))
	}
}

// TestJoinCatchupCooldownCoversPins: a /leave + /join cycle must not
// re-trigger the pins block any more than it re-triggers the replay. Both
// halves ride the same limiter.
func TestJoinCatchupCooldownCoversPins(t *testing.T) {
	svc := newTestService(t, "")
	now := svc.now()
	seedHistory(t, svc, now, "a message")
	if err := svc.info.AddPin(groupinfo.Pin{At: now, Text: "read the rules"}); err != nil {
		t.Fatal(err)
	}

	joiner := bytes.Repeat([]byte{0xAF}, 16)
	svc.sendJoinCatchup(joiner, now)
	first := len(enqueuedBodies(t, svc, joiner))
	if first != 2 {
		t.Fatalf("first catch-up enqueued %d messages, want 2", first)
	}

	svc.sendJoinCatchup(joiner, now.Add(replayCooldown/2))
	if got := len(enqueuedBodies(t, svc, joiner)); got != first {
		t.Errorf("a catch-up inside the cooldown enqueued %d more messages", got-first)
	}

	svc.sendJoinCatchup(joiner, now.Add(replayCooldown+time.Second))
	if got := len(enqueuedBodies(t, svc, joiner)); got != first*2 {
		t.Errorf("after the cooldown, total enqueued = %d, want %d", got, first*2)
	}
}

// TestJoinCatchupPinsWaitForTheReplayToDrain is the ordering requirement as
// the joiner experiences it, which enqueue order alone does not give: the
// queue drains on parallel workers and a failed message retries behind
// later ones. Here the first replay message fails and is rescheduled, and
// the pins must still not go out until it has been delivered.
func TestJoinCatchupPinsWaitForTheReplayToDrain(t *testing.T) {
	svc := newTestService(t, "")
	now := svc.now()
	seedHistory(t, svc, now, "first message", "second message")
	if err := svc.info.AddPin(groupinfo.Pin{At: now, ByNick: "kim", Text: "net at 20:00"}); err != nil {
		t.Fatal(err)
	}

	sender := &fakeSender{sendErrs: []error{errors.New("link timeout")}}
	q := newTestQueue(t, sender, nil)
	q.retryWait = 20 * time.Millisecond
	svc.outbound = q

	joiner := bytes.Repeat([]byte{0xAB}, 16)
	svc.sendJoinCatchup(joiner, now)

	// Drain until idle, the way the worker pool would: each pass sends
	// whatever pickDue offers. The failed first replay message is not due
	// again until retryWait has passed, and in the old behaviour the pins
	// went out in that gap.
	deadline := time.Now().Add(2 * time.Second)
	for q.pendingCount() > 0 && time.Now().Before(deadline) {
		q.processOnce(context.Background())
		time.Sleep(5 * time.Millisecond)
	}
	if n := q.pendingCount(); n != 0 {
		t.Fatalf("queue did not drain: %d pending", n)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	var sent []string
	for _, b := range sender.sendCalls {
		sent = append(sent, string(b))
	}
	last := sent[len(sent)-1]
	if !strings.HasPrefix(last, "Pinned (1):") {
		t.Fatalf("pins were not the last delivery; send order:\n%s", strings.Join(sent, "\n---\n"))
	}
	if strings.Count(strings.Join(sent, "\n"), "Pinned (1):") != 1 {
		t.Errorf("pins sent more than once:\n%s", strings.Join(sent, "\n---\n"))
	}
}
