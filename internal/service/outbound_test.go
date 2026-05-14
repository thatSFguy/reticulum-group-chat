package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
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
}

func (f *fakeSender) SendLXMF(recipient, body []byte, fields map[any]any) error {
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
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return err
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
			0x01: now.Add(-1 * time.Hour),  // older
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

func TestEnqueuePersistsImmediately(t *testing.T) {
	// A crash between enqueue and the next drain tick must not lose
	// the message — this verifies the file is written from inside
	// Enqueue, not lazily on first drain.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "outbound.json")
	store := newOutboundStore(storePath)

	q := newTestQueue(t, &fakeSender{}, store)
	q.Enqueue(make([]byte, 16), []byte("durable"))

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
