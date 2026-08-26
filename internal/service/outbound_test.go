package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/lxmf"
)

// fakeSender records every Send/RequestPath call and lets a test inject
// per-call return values. Sufficient for exercising the queue's retry,
// path-request, and persistence logic without standing up a real
// transport.
type fakeSender struct {
	mu sync.Mutex

	sendErrs       []error // pop from front per Send call
	sendCalls      [][]byte
	sendRecipients [][]byte
	sendFields     []map[any]any
	sendDelay      time.Duration // sleep inside SendLXMF, for parallelism tests
	pathErr        error
	pathRequests   int32

	// recency populates LastAnnounceFor responses keyed by the first
	// byte of the recipient hash (a tiny hack — every test recipient
	// in this file uses bytes.Repeat so byte 0 is unique per recipient).
	recency map[byte]time.Time

	// Propagation knobs. hasPropNode gates the fallback re-route;
	// propErrs/propCalls mirror sendErrs/sendCalls for the propagated
	// path so tests can distinguish which method each attempt used.
	hasPropNode    bool
	propErrs       []error
	propCalls      [][]byte
	propRecipients [][]byte
}

func (f *fakeSender) SendLXMFPropagated(recipient, body []byte, fields map[any]any) ([]byte, error) {
	f.mu.Lock()
	f.propCalls = append(f.propCalls, append([]byte(nil), body...))
	f.propRecipients = append(f.propRecipients, append([]byte(nil), recipient...))
	var err error
	if len(f.propErrs) > 0 {
		err = f.propErrs[0]
		f.propErrs = f.propErrs[1:]
	}
	msgID := make([]byte, 32)
	if len(recipient) > 0 {
		msgID[0] = recipient[0]
	}
	msgID[1] = byte(len(f.propCalls))
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return msgID, nil
}

func (f *fakeSender) HasPropagationNode() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hasPropNode
}

func (f *fakeSender) SendLXMF(recipient, body []byte, fields map[any]any) ([]byte, error) {
	f.mu.Lock()
	f.sendCalls = append(f.sendCalls, append([]byte(nil), body...))
	f.sendRecipients = append(f.sendRecipients, append([]byte(nil), recipient...))
	f.sendFields = append(f.sendFields, fields)
	delay := f.sendDelay
	var err error
	if len(f.sendErrs) > 0 {
		err = f.sendErrs[0]
		f.sendErrs = f.sendErrs[1:]
	}
	// Deterministic synthetic msg_id so registration tests can assert
	// on it: first byte of recipient + monotonic counter. The byte slice
	// is 32 bytes (length of SHA-256) so it matches real LXMF.
	msgID := make([]byte, 32)
	if len(recipient) > 0 {
		msgID[0] = recipient[0]
	}
	msgID[1] = byte(len(f.sendCalls))
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	return msgID, nil
}

func (f *fakeSender) RequestPath(recipient []byte) error {
	atomic.AddInt32(&f.pathRequests, 1)
	return f.pathErr
}

func (f *fakeSender) LastAnnounceFor(recipient []byte) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recency == nil || len(recipient) == 0 {
		return time.Time{}, false
	}
	t, ok := f.recency[recipient[0]]
	return t, ok
}

func (f *fakeSender) sendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sendCalls)
}

func newTestQueue(t *testing.T, sender outboundSender, store *outboundStore) *OutboundQueue {
	t.Helper()
	q := newOutboundQueue(sender, store, log.New(io.Discard, "", 0))
	q.now = time.Now
	return q
}

func TestEnqueueAndDrainSuccess(t *testing.T) {
	sender := &fakeSender{}
	q := newTestQueue(t, sender, nil)

	q.Enqueue(make([]byte, 16), []byte("hello"))
	if got := q.pendingCount(); got != 1 {
		t.Fatalf("pendingCount after enqueue = %d, want 1", got)
	}

	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 1 {
		t.Fatalf("sendCount = %d, want 1", got)
	}
	if got := q.pendingCount(); got != 0 {
		t.Fatalf("pendingCount after success = %d, want 0", got)
	}
}

func TestDrainRetriesAfterTransientError(t *testing.T) {
	sender := &fakeSender{
		sendErrs: []error{errors.New("link timeout"), nil},
	}
	q := newTestQueue(t, sender, nil)
	// Tighten the retry wait so the test stays fast.
	q.retryWait = 5 * time.Millisecond

	q.Enqueue(make([]byte, 16), []byte("hi"))
	q.processOnce(context.Background())

	// First attempt failed; message should still be queued with a
	// scheduled NextAttempt in the future.
	if got := q.pendingCount(); got != 1 {
		t.Fatalf("pendingCount after first failure = %d, want 1", got)
	}
	if got := sender.sendCount(); got != 1 {
		t.Fatalf("sendCount after first failure = %d, want 1", got)
	}

	// Wait past the retryWait, drain again — should succeed and clear.
	time.Sleep(10 * time.Millisecond)
	q.processOnce(context.Background())

	if got := q.pendingCount(); got != 0 {
		t.Fatalf("pendingCount after retry success = %d, want 0", got)
	}
	if got := sender.sendCount(); got != 2 {
		t.Fatalf("sendCount after retry = %d, want 2", got)
	}
}

func TestDrainGivesUpAfterMaxAttempts(t *testing.T) {
	// Always-fail sender. With maxAttempts=3, expect exactly 3 Send
	// calls and the message removed (failed).
	sender := &fakeSender{}
	for i := 0; i < 10; i++ {
		sender.sendErrs = append(sender.sendErrs, errors.New("never delivers"))
	}
	q := newTestQueue(t, sender, nil)
	q.maxAttempts = 3
	q.retryWait = 0 // due immediately on every tick

	q.Enqueue(make([]byte, 16), []byte("doomed"))

	// Drain repeatedly — each processOnce should consume one attempt
	// (the message is due immediately because retryWait=0).
	for i := 0; i < 5; i++ {
		q.processOnce(context.Background())
	}

	if got := sender.sendCount(); got != 3 {
		t.Errorf("sendCount = %d, want 3 (maxAttempts)", got)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount after fail = %d, want 0", got)
	}
}

func TestRecipientUnknownTriggersPathRequest(t *testing.T) {
	// First two attempts fail with ErrRecipientUnknown; third succeeds.
	// Path request should fire on attempt 2 (after pathlessTries=1) and
	// the backoff should be the longer pathRequestWait.
	sender := &fakeSender{
		sendErrs: []error{
			lxmf.ErrRecipientUnknown,
			lxmf.ErrRecipientUnknown,
			nil,
		},
	}
	q := newTestQueue(t, sender, nil)
	q.retryWait = time.Millisecond
	q.pathRequestWait = time.Millisecond

	q.Enqueue(make([]byte, 16), []byte("path-request test"))

	for i := 0; i < 3; i++ {
		q.processOnce(context.Background())
		time.Sleep(2 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&sender.pathRequests); got < 1 {
		t.Errorf("pathRequests = %d, want >= 1", got)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount after success = %d, want 0", got)
	}
}

func TestNotYetDueMessageIsSkipped(t *testing.T) {
	sender := &fakeSender{}
	q := newTestQueue(t, sender, nil)

	q.Enqueue(make([]byte, 16), []byte("future"))
	// Hand-set NextAttempt to the far future.
	q.mu.Lock()
	q.pending[0].NextAttempt = time.Now().Add(time.Hour)
	q.mu.Unlock()

	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 0 {
		t.Errorf("sendCount = %d, want 0 (message not due)", got)
	}
	if got := q.pendingCount(); got != 1 {
		t.Errorf("pendingCount = %d, want 1", got)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "outbound.json")
	store := newOutboundStore(storePath)

	sender1 := &fakeSender{}
	q1 := newTestQueue(t, sender1, store)

	body := []byte("survive a restart")
	recipient := bytes.Repeat([]byte{0xab}, 16)
	q1.Enqueue(recipient, body)
	q1.Flush() // persistence is coalesced; force the write

	// Brand-new queue, same store: it should pick up the persisted
	// message on Load and drain it on processOnce.
	sender2 := &fakeSender{}
	q2 := newTestQueue(t, sender2, store)
	if err := q2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := q2.pendingCount(); got != 1 {
		t.Fatalf("pendingCount after Load = %d, want 1", got)
	}

	q2.processOnce(context.Background())
	if got := sender2.sendCount(); got != 1 {
		t.Fatalf("sendCount = %d, want 1", got)
	}
	if !bytes.Equal(sender2.sendCalls[0], body) {
		t.Errorf("sendCalls[0] = %q, want %q", sender2.sendCalls[0], body)
	}
}

func TestDrainOrderIsFIFO(t *testing.T) {
	sender := &fakeSender{}
	q := newTestQueue(t, sender, nil)

	for i := byte(0); i < 5; i++ {
		q.Enqueue(make([]byte, 16), []byte{i})
	}

	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 5 {
		t.Fatalf("sendCount = %d, want 5", got)
	}
	for i, body := range sender.sendCalls {
		if len(body) != 1 || body[0] != byte(i) {
			t.Errorf("sendCalls[%d] = %v, want [%d]", i, body, i)
		}
	}
}

func TestPickDuePrioritisesMostRecentlyAnnouncedRecipient(t *testing.T) {
	now := time.Now()
	sender := &fakeSender{
		recency: map[byte]time.Time{
			0x01: now.Add(-1 * time.Hour),    // older
			0x02: now.Add(-10 * time.Minute), // newest
			0x03: now.Add(-30 * time.Minute), // middle
		},
	}
	q := newTestQueue(t, sender, nil)

	q.Enqueue(bytes.Repeat([]byte{0x01}, 16), []byte("oldest"))
	q.Enqueue(bytes.Repeat([]byte{0x02}, 16), []byte("newest"))
	q.Enqueue(bytes.Repeat([]byte{0x03}, 16), []byte("middle"))

	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 3 {
		t.Fatalf("sendCount = %d, want 3", got)
	}
	// Recipients should drain newest-first regardless of enqueue order.
	wantOrder := []byte{0x02, 0x03, 0x01}
	for i, want := range wantOrder {
		if sender.sendRecipients[i][0] != want {
			t.Errorf("sendRecipients[%d][0] = 0x%02x, want 0x%02x",
				i, sender.sendRecipients[i][0], want)
		}
	}
}

func TestPickDueDeprioritisesUnknownRecipients(t *testing.T) {
	now := time.Now()
	sender := &fakeSender{
		recency: map[byte]time.Time{
			0xAA: now.Add(-2 * time.Hour),
			// 0xBB unknown
		},
	}
	q := newTestQueue(t, sender, nil)

	// Enqueue unknown FIRST, then known. Known should still drain first
	// because any recency beats unknown.
	q.Enqueue(bytes.Repeat([]byte{0xBB}, 16), []byte("unknown"))
	q.Enqueue(bytes.Repeat([]byte{0xAA}, 16), []byte("known"))

	q.processOnce(context.Background())

	if sender.sendRecipients[0][0] != 0xAA {
		t.Errorf("first send was 0x%02x, want 0xAA (known recipient)",
			sender.sendRecipients[0][0])
	}
}

func TestPickDueFIFOAmongUnknownRecipients(t *testing.T) {
	// All recipients unknown — should fall back to enqueue order.
	sender := &fakeSender{}
	q := newTestQueue(t, sender, nil)

	for _, b := range []byte{0x10, 0x20, 0x30} {
		q.Enqueue(bytes.Repeat([]byte{b}, 16), []byte{b})
	}
	q.processOnce(context.Background())

	for i, want := range []byte{0x10, 0x20, 0x30} {
		if sender.sendRecipients[i][0] != want {
			t.Errorf("FIFO broken: sendRecipients[%d] = 0x%02x, want 0x%02x",
				i, sender.sendRecipients[i][0], want)
		}
	}
}

func TestWorkersRunInParallelToAvoidHeadOfLineBlocking(t *testing.T) {
	// One slow recipient + several fast ones. With workers=4, the
	// slow send must NOT block the fast sends — total wall time
	// should be roughly the slow send's duration, not the sum of
	// all sends.
	const slowDuration = 200 * time.Millisecond
	const fastSends = 5

	sender := &fakeSender{sendDelay: slowDuration}
	q := newTestQueue(t, sender, nil)
	q.workers = 4
	q.interval = 20 * time.Millisecond // workers idle quickly when nothing's due

	// Enqueue one "slow" + N "fast" — all the same delay, but the
	// point is N+1 messages should drain in roughly slowDuration if
	// workers run in parallel, vs (N+1)*slowDuration if serial.
	for i := 0; i < 1+fastSends; i++ {
		q.Enqueue(bytes.Repeat([]byte{byte(i + 1)}, 16), []byte{byte(i)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		q.Run(ctx)
		close(done)
	}()

	// Wait until all messages drain (or timeout).
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if q.pendingCount() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	elapsed := time.Since(start)
	cancel()
	<-done

	if q.pendingCount() != 0 {
		t.Fatalf("queue still has %d pending after deadline", q.pendingCount())
	}
	// With 4 workers and 6 sends each taking ~200ms, expect ~400ms
	// total (two batches of 4 → only 2 workers in second batch).
	// Allow generous slack for CI: anything under 800ms proves we
	// got real parallelism (serial would be 6 × 200 = 1200ms).
	if elapsed > 800*time.Millisecond {
		t.Errorf("drain took %v with workers=4 + delay=%v; expected < 800ms (serial would be 1200ms)",
			elapsed, slowDuration)
	}
}

func TestEnqueuePersistsOnFlush(t *testing.T) {
	// A crash between enqueue and the next drain tick must not lose the
	// message. Queue writes are coalesced (persistFlushInterval) rather
	// than synchronous, so the guarantee is "the enqueue is marked
	// dirty and the next flush writes it" — Run's persist loop flushes
	// within 250ms and again on shutdown.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "outbound.json")
	store := newOutboundStore(storePath)

	q := newTestQueue(t, &fakeSender{}, store)
	q.Enqueue(make([]byte, 16), []byte("durable"))
	q.Flush()

	loaded, err := store.load()
	if err != nil {
		t.Fatalf("store.load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d messages, want 1", len(loaded))
	}
	if string(loaded[0].Body) != "durable" {
		t.Errorf("loaded body = %q, want %q", loaded[0].Body, "durable")
	}
}

func TestFallbackReroutesViaPropagationNode(t *testing.T) {
	// Direct budget exhausts → message converts to propagated with a
	// fresh attempt budget instead of dropping, then delivers.
	sender := &fakeSender{
		hasPropNode: true,
		sendErrs:    []error{errors.New("x"), errors.New("x"), errors.New("x")},
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true /* fallback */, false, 0)
	q.maxAttempts = 3
	q.retryWait = 0

	q.Enqueue(make([]byte, 16), []byte("stubborn"))
	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 3 {
		t.Errorf("direct sendCount = %d, want 3 (full direct budget)", got)
	}
	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 1 {
		t.Errorf("propagated sendCount = %d, want 1", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (delivered via propagation)", got)
	}
}

func TestFallbackWithoutNodeFailsTerminally(t *testing.T) {
	// No propagation node known → the fallback must not convert; the
	// message drops after the direct budget like before.
	sender := &fakeSender{
		hasPropNode: false,
		sendErrs:    []error{errors.New("x"), errors.New("x"), errors.New("x")},
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true, false, 0)
	q.maxAttempts = 3
	q.retryWait = 0

	q.Enqueue(make([]byte, 16), []byte("doomed"))
	q.processOnce(context.Background())

	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 0 {
		t.Errorf("propagated sendCount = %d, want 0", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (terminal drop)", got)
	}
}

func TestAlwaysModeSendsPropagatedOnly(t *testing.T) {
	sender := &fakeSender{hasPropNode: true}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(false, true /* always */, 0)

	q.Enqueue(make([]byte, 16), []byte("via node"))
	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 0 {
		t.Errorf("direct sendCount = %d, want 0 in always mode", got)
	}
	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 1 {
		t.Errorf("propagated sendCount = %d, want 1", propCalls)
	}
}

func TestPropagatedTerminalFailureDrops(t *testing.T) {
	// An already-propagated message that exhausts its budget must fail
	// terminally, not convert again (no infinite re-route loop).
	sender := &fakeSender{
		hasPropNode: true,
		propErrs:    []error{errors.New("x"), errors.New("x"), errors.New("x")},
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true, true, 0)
	q.maxAttempts = 3
	q.retryWait = 0

	q.Enqueue(make([]byte, 16), []byte("dead end"))
	q.processOnce(context.Background())

	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 3 {
		t.Errorf("propagated attempts = %d, want 3", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (terminal drop)", got)
	}
}

func TestPropagatedFlagPersistsAcrossReload(t *testing.T) {
	// A message converted to propagated must stay propagated after a
	// service restart — otherwise a restart demotes it back to direct
	// and it burns a second direct budget.
	dir := t.TempDir()
	store := newOutboundStore(filepath.Join(dir, "outbound.json"))

	sender := &fakeSender{hasPropNode: true}
	q := newTestQueue(t, sender, store)
	q.SetPropagation(false, true, 0)
	q.Enqueue(make([]byte, 16), []byte("persist me"))
	q.Flush()

	loaded, err := store.load()
	if err != nil {
		t.Fatalf("store.load: %v", err)
	}
	if len(loaded) != 1 || !loaded[0].Propagated {
		t.Fatalf("loaded = %+v, want 1 message with Propagated=true", loaded)
	}
}

func TestNoPropagationNodeDefersWithoutBurningBudget(t *testing.T) {
	// "Always" mode with no node discovered yet: attempts must not
	// count toward the terminal budget — the message waits for a node
	// announce instead of dropping.
	sender := &fakeSender{
		propErrs: []error{errNoPropagationNode, errNoPropagationNode, nil},
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(false, true, 0)
	q.maxAttempts = 2 // tighter than the number of deferrals
	q.retryWait = time.Millisecond

	q.Enqueue(make([]byte, 16), []byte("waiting for a node"))

	for i := 0; i < 3; i++ {
		q.processOnce(context.Background())
		time.Sleep(2 * time.Millisecond)
	}

	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 3 {
		t.Errorf("propagated attempts = %d, want 3 (2 deferrals + success)", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (delivered once a node appeared)", got)
	}
}

func TestRetryBackoffGrowsExponentially(t *testing.T) {
	// Each failed attempt doubles the wait before the next one, so a
	// persistently offline recipient occupies a worker progressively
	// less often instead of re-taking one every retryWait.
	sender := &fakeSender{}
	for i := 0; i < 4; i++ {
		sender.sendErrs = append(sender.sendErrs, errors.New("offline"))
	}
	q := newTestQueue(t, sender, nil)
	q.retryWait = 10 * time.Millisecond
	clock := time.Unix(1700000000, 0)
	q.now = func() time.Time { return clock }

	q.Enqueue(make([]byte, 16), []byte("m"))

	for i, want := range []time.Duration{
		10 * time.Millisecond, // after attempt 1
		20 * time.Millisecond, // after attempt 2
		40 * time.Millisecond, // after attempt 3
	} {
		q.processOnce(context.Background())
		q.mu.Lock()
		next := q.pending[0].NextAttempt
		q.mu.Unlock()
		if got := next.Sub(clock); got != want {
			t.Fatalf("backoff after attempt %d = %v, want %v", i+1, got, want)
		}
		clock = next // advance the fake clock to the due time
	}
}

func TestBackoffWaitCapped(t *testing.T) {
	q := newTestQueue(t, &fakeSender{}, nil)
	q.retryWait = 40 * time.Second
	if got := q.backoffWait(1); got != 40*time.Second {
		t.Errorf("backoffWait(1) = %v, want 40s", got)
	}
	// 40s doubled once = 80s → capped at maxRetryBackoff.
	if got := q.backoffWait(2); got != maxRetryBackoff {
		t.Errorf("backoffWait(2) = %v, want cap %v", got, maxRetryBackoff)
	}
	if got := q.backoffWait(10); got != maxRetryBackoff {
		t.Errorf("backoffWait(10) = %v, want cap %v", got, maxRetryBackoff)
	}
}

func TestShortDirectBudgetConvertsEarlyWhenNodeAvailable(t *testing.T) {
	// direct_attempts=3 with a node available: convert after 3 direct
	// attempts even though maxAttempts is 5.
	sender := &fakeSender{hasPropNode: true}
	for i := 0; i < 5; i++ {
		sender.sendErrs = append(sender.sendErrs, errors.New("offline"))
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true, false, 3)
	q.maxAttempts = 5
	q.retryWait = 0

	q.Enqueue(make([]byte, 16), []byte("fail fast into the net"))
	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 3 {
		t.Errorf("direct attempts = %d, want 3 (shortened budget)", got)
	}
	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 1 {
		t.Errorf("propagated sendCount = %d, want 1", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0", got)
	}
}

func TestShortDirectBudgetIgnoredWithoutNode(t *testing.T) {
	// direct_attempts=3 but NO node available: the message keeps its
	// full 5-attempt budget before dropping — the shortened budget only
	// applies when there is actually a net to fall into.
	sender := &fakeSender{hasPropNode: false}
	for i := 0; i < 6; i++ {
		sender.sendErrs = append(sender.sendErrs, errors.New("offline"))
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true, false, 3)
	q.maxAttempts = 5
	q.retryWait = 0

	q.Enqueue(make([]byte, 16), []byte("no net"))
	q.processOnce(context.Background())

	if got := sender.sendCount(); got != 5 {
		t.Errorf("direct attempts = %d, want full 5 without a node", got)
	}
	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 0 {
		t.Errorf("propagated sendCount = %d, want 0", propCalls)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (terminal drop)", got)
	}
}

func TestDirectBudgetAtLeastMaxAttemptsDisablesShortening(t *testing.T) {
	q := newTestQueue(t, &fakeSender{}, nil)
	q.maxAttempts = 5
	q.SetPropagation(true, false, 5)
	q.mu.Lock()
	got := q.directBudgetLocked()
	q.mu.Unlock()
	if got != 5 {
		t.Errorf("directBudgetLocked() = %d, want 5 (>=maxAttempts disables shortening)", got)
	}
}

func TestQueueRefusesPastCap(t *testing.T) {
	// Without a cap, queue depth is driven by remote input: fan-out
	// enqueues one entry per member per message, so memory and
	// outbound.json grow without bound under a flood.
	q := newTestQueue(t, &fakeSender{}, nil)

	for i := 0; i < maxPendingMessages; i++ {
		if id := q.Enqueue(make([]byte, 16), []byte("x")); id == "" {
			t.Fatalf("enqueue %d refused before the cap", i)
		}
	}
	if got := q.pendingCount(); got != maxPendingMessages {
		t.Fatalf("pendingCount = %d, want %d", got, maxPendingMessages)
	}
	if id := q.Enqueue(make([]byte, 16), []byte("over")); id != "" {
		t.Error("enqueue past the cap returned an ID; want refusal")
	}
	if got := q.pendingCount(); got != maxPendingMessages {
		t.Errorf("pendingCount grew past the cap to %d", got)
	}
}

func TestPersistenceIsCoalesced(t *testing.T) {
	// The point of coalescing: a fan-out of N messages must produce ONE
	// write, not N full-file rewrites (which was quadratic disk I/O per
	// inbound message).
	dir := t.TempDir()
	store := newOutboundStore(filepath.Join(dir, "outbound.json"))
	q := newTestQueue(t, &fakeSender{}, store)

	for i := 0; i < 50; i++ {
		q.Enqueue(bytes.Repeat([]byte{byte(i)}, 16), []byte("fan-out"))
	}
	// Nothing written yet — the enqueues only marked the queue dirty.
	if _, err := os.Stat(store.path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("store written synchronously during enqueue (err=%v)", err)
	}

	q.Flush()
	loaded, err := store.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 50 {
		t.Errorf("one flush persisted %d messages, want all 50", len(loaded))
	}

	// A second flush with no changes must not rewrite.
	before, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	q.Flush()
	after, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("clean flush rewrote the file; dirty tracking is not working")
	}
}

func TestRunFlushesOnShutdown(t *testing.T) {
	// A graceful stop must not lose queued messages — that is what
	// bounds the coalescing trade-off to hard kills only.
	dir := t.TempDir()
	store := newOutboundStore(filepath.Join(dir, "outbound.json"))
	q := newTestQueue(t, &fakeSender{sendErrs: []error{errors.New("hold")}}, store)
	q.flushEvery = time.Hour // never fires on its own

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()

	q.Enqueue(make([]byte, 16), []byte("graceful"))
	cancel()
	<-done

	loaded, err := store.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("shutdown flush persisted %d messages, want 1", len(loaded))
	}
}

func TestStampCostRefusalDropsImmediately(t *testing.T) {
	// A recipient demanding more proof-of-work than delivery.MaxStampCost
	// allows is a deterministic refusal, not a transient failure: the cost
	// is re-read from the same cached announce on every attempt. Burning
	// the whole budget against it costs ~2 minutes of backoff per message
	// and logs the cause as an exhausted budget. Expect exactly ONE send
	// and an immediate drop.
	sender := &fakeSender{
		hasPropNode: true,
		sendErrs: []error{
			// Wrapped, as the real send path wraps it.
			fmt.Errorf("pack: %w", lxmf.ErrStampCostTooHigh),
			errors.New("must not be reached"),
		},
	}
	q := newTestQueue(t, sender, nil)
	q.SetPropagation(true /* fallback */, false, 0)
	q.maxAttempts = 5
	q.retryWait = 0 // due immediately, so a retry would show up at once

	q.Enqueue(make([]byte, 16), []byte("too expensive"))

	// Drain several times — a correctly-dropped message stays dropped.
	for i := 0; i < 3; i++ {
		q.processOnce(context.Background())
	}

	if got := sender.sendCount(); got != 1 {
		t.Errorf("sendCount = %d, want 1 (refusal must not be retried)", got)
	}
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount = %d, want 0 (message must be dropped)", got)
	}
	// The propagation route grinds the SAME recipient stamp, so the
	// fallback re-route would hit the identical refusal a budget later.
	sender.mu.Lock()
	propCalls := len(sender.propCalls)
	sender.mu.Unlock()
	if propCalls != 0 {
		t.Errorf("propagated sendCount = %d, want 0 (re-route hits the same refusal)", propCalls)
	}
}

// TestStampWorkersBusyDefersWithoutSpendingAnAttempt asserts the grind
// semaphore's back-pressure signal is treated as "try again shortly",
// not as a delivery failure. Getting this wrong would be worse than
// having no semaphore: a busy spell would burn a message's five attempts
// without ever putting it on the wire.
func TestStampWorkersBusyDefersWithoutSpendingAnAttempt(t *testing.T) {
	sender := &fakeSender{
		sendErrs: []error{fmt.Errorf("send: %w", errStampWorkersBusy), nil},
	}
	q := newTestQueue(t, sender, nil)
	q.maxAttempts = 5
	// Non-zero: processOnce drains everything due, so a zero wait would
	// make the deferral due again inside the same call and retry it
	// immediately, hiding whether it parked at all.
	q.retryWait = 30 * time.Millisecond

	q.Enqueue(make([]byte, 16), []byte("stamped recipient"))
	q.processOnce(context.Background())

	// Deferred, still queued, and — the point — no attempt consumed.
	if got := q.pendingCount(); got != 1 {
		t.Fatalf("pendingCount = %d, want 1 (deferred, not dropped)", got)
	}
	q.mu.Lock()
	attempts := q.pending[0].Attempts
	q.mu.Unlock()
	if attempts != 0 {
		t.Errorf("Attempts = %d, want 0 — back-pressure must not spend the budget", attempts)
	}

	// A slot frees; the retry goes through.
	time.Sleep(40 * time.Millisecond)
	q.processOnce(context.Background())
	if got := q.pendingCount(); got != 0 {
		t.Errorf("pendingCount after slot freed = %d, want 0", got)
	}
}
