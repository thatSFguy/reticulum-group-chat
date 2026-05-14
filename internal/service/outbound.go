package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/idmap"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

// Constants mirror LXMF 0.9.7's LXMRouter.process_outbound retry policy.
// See thatSFguy/reticulum-specifications flows/lxmf-outbound-retry.md for
// the source-cited rationale. Equivalent values keep our delivery
// semantics aligned with Sideband on a half-duplex LoRa segment, where
// a single packet collision shouldn't lose the message.
const (
	maxDeliveryAttempts = 5                // LXMRouter.MAX_DELIVERY_ATTEMPTS
	deliveryRetryWait   = 10 * time.Second // LXMRouter.DELIVERY_RETRY_WAIT
	pathRequestWait     = 7 * time.Second  // LXMRouter.PATH_REQUEST_WAIT
	maxPathlessTries    = 1                // LXMRouter.MAX_PATHLESS_TRIES
	processingInterval  = 4 * time.Second  // LXMRouter.PROCESSING_INTERVAL

	// outboundWorkers caps the number of concurrent in-flight Send
	// calls. Higher values let a fast command reply to user A skip
	// past a slow link send to user B (head-of-line avoidance), at
	// the cost of more parallel work on the underlying interface.
	// Four matches the typical LXMF/Sideband fan-out for small
	// rosters; bump it if your roster is large and your interface
	// can absorb the parallelism (a TCP-attached rnsd handles the
	// per-radio scheduling for us).
	outboundWorkers = 4
)

// outboundMessage is one queued LXMF message awaiting delivery. The drain
// loop attempts it on each tick until either Delivery.Send returns nil
// (success → removed from queue) or Attempts > maxDeliveryAttempts
// (terminal fail_message). Persisted as-is to outbound.json so a service
// restart resumes pending sends instead of dropping them.
//
// Fields is in-memory only (json:"-") — attachment payloads aren't
// persisted across restart. A crash between Enqueue and Send loses the
// attachment but keeps the text body; the sender can always resend.
// Keeps the on-disk format JSON-friendly without a custom marshaller for
// the msgpack-typed values inside Fields.
type outboundMessage struct {
	ID          string         `json:"id"`
	Recipient   []byte         `json:"recipient"`    // 16-byte lxmf.delivery dest_hash
	Body        []byte         `json:"body"`         // pre-formatted UTF-8 chat body or command reply
	Fields      map[any]any    `json:"-"`            // LXMF fields (FIELD_IMAGE, etc.); not persisted
	Bubble      *idmap.Bubble  `json:"-"`            // optional; when set, the queue registers the recipient view in the cache on send success
	Attempts    int            `json:"attempts"`     // 0..maxDeliveryAttempts
	NextAttempt time.Time      `json:"next_attempt"` // zero = ready now
	EnqueuedAt  time.Time      `json:"enqueued_at"`
}

// outboundSender is the subset of *lxmf.Delivery + *rns.Transport the
// queue calls into. Defined as an interface so tests can inject a fake
// without standing up a real transport. SendLXMF returns the recipient-
// view LXMF message_id (32 bytes) on success — the queue registers it in
// the idmap cache so cross-client reactions and reply-tos can be
// rewritten per recipient.
type outboundSender interface {
	SendLXMF(recipient, body []byte, fields map[any]any) (msgID []byte, err error)
	RequestPath(recipient []byte) error
	// LastAnnounceFor returns when the recipient most recently
	// announced (verified inbound), or zero+false if we've never
	// heard them. The drain loop uses this to send to the most
	// recently-seen recipient first — they're most likely to be
	// reachable, and prioritising them shrinks the latency for users
	// who are actually online while a slow send to a possibly-offline
	// peer can wait.
	LastAnnounceFor(recipient []byte) (time.Time, bool)
}

// OutboundQueue runs outbound LXMF deliveries through Delivery.Send with
// retry semantics matching LXMF 0.9.7's LXMRouter.process_outbound.
//
// Sends run on a small worker pool (outboundWorkers, default 4) so a
// slow link send to one recipient doesn't block command replies or
// forwards to others — head-of-line avoidance is the main reason for
// concurrency here. Each worker independently picks the next due
// message via pickDue, which orders by recipient recency so a
// recently-announced peer (most likely reachable) goes first; ties
// fall back to FIFO. The queue mutex is the only serialisation point;
// nothing else coordinates between workers.
type OutboundQueue struct {
	sender outboundSender
	store  *outboundStore
	idmap  *idmap.Cache // optional — when set, successful sends register the per-recipient message_id view here for reaction/reply rewriting
	logger *log.Logger

	mu       sync.Mutex
	pending  []*outboundMessage
	inFlight map[string]bool // message ID → currently being sent

	// Tunables exposed for tests; production uses the package constants.
	interval        time.Duration
	retryWait       time.Duration
	pathRequestWait time.Duration
	maxAttempts     int
	pathlessTries   int
	workers         int

	now func() time.Time
}

func newOutboundQueue(sender outboundSender, store *outboundStore, logger *log.Logger) *OutboundQueue {
	return &OutboundQueue{
		sender:          sender,
		store:           store,
		logger:          logger,
		inFlight:        map[string]bool{},
		interval:        processingInterval,
		retryWait:       deliveryRetryWait,
		pathRequestWait: pathRequestWait,
		maxAttempts:     maxDeliveryAttempts,
		pathlessTries:   maxPathlessTries,
		workers:         outboundWorkers,
		now:             time.Now,
	}
}

// SetIDMap attaches a Cache so successful per-recipient sends register
// their message_id view. Optional; nil disables cross-client reaction
// and reply-to rewriting (the legacy behavior).
func (q *OutboundQueue) SetIDMap(c *idmap.Cache) {
	q.mu.Lock()
	q.idmap = c
	q.mu.Unlock()
}

// Load reads any persisted queue state into memory. Call once at
// startup, before Run.
func (q *OutboundQueue) Load() error {
	if q.store == nil {
		return nil
	}
	msgs, err := q.store.load()
	if err != nil {
		return err
	}
	q.mu.Lock()
	q.pending = msgs
	q.mu.Unlock()
	return nil
}

// Enqueue appends a message to the queue and persists immediately, so a
// crash between enqueue and the next drain tick doesn't lose the
// message. Returns the message ID for telemetry.
func (q *OutboundQueue) Enqueue(recipient, body []byte) string {
	return q.EnqueueWithFields(recipient, body, nil)
}

// EnqueueWithFields is Enqueue with an attached LXMF fields map (e.g.
// FIELD_IMAGE = 6). Fields are passed straight to Delivery.Send and not
// persisted to outbound.json — a crash between enqueue and send loses
// the attachment but keeps the text body. See outboundMessage docs.
func (q *OutboundQueue) EnqueueWithFields(recipient, body []byte, fields map[any]any) string {
	return q.EnqueueBubble(recipient, body, fields, nil)
}

// EnqueueBubble is EnqueueWithFields with an optional bubble that the
// queue will populate with the recipient's message_id view once Send
// succeeds. Used by forwardToRoster so cross-client reactions and
// reply-tos can later be rewritten per recipient. Bubble is in-memory
// only — not persisted.
func (q *OutboundQueue) EnqueueBubble(recipient, body []byte, fields map[any]any, bubble *idmap.Bubble) string {
	msg := &outboundMessage{
		ID:         newMessageID(),
		Recipient:  append([]byte(nil), recipient...),
		Body:       append([]byte(nil), body...),
		Fields:     fields,
		Bubble:     bubble,
		EnqueuedAt: q.now(),
	}
	q.mu.Lock()
	q.pending = append(q.pending, msg)
	q.persistLocked()
	q.mu.Unlock()
	return msg.ID
}

// Run drives the drain loop until ctx is cancelled. Spawns
// q.workers goroutines that independently pick due messages and call
// Send. Each worker idles for q.interval when there's nothing due,
// so a freshly enqueued message is picked up within at most one
// interval (4s default).
func (q *OutboundQueue) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < q.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.workerLoop(ctx)
		}()
	}
	wg.Wait()
}

func (q *OutboundQueue) workerLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		msg := q.pickDue()
		if msg == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(q.interval):
				continue
			}
		}
		q.attempt(msg)
	}
}

// pendingCount returns the queue depth. For tests + future telemetry.
func (q *OutboundQueue) pendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// processOnce drains every currently-due message synchronously in the
// caller's goroutine. Used by tests so assertions don't have to race
// the worker pool. Production uses Run/workerLoop.
func (q *OutboundQueue) processOnce(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		msg := q.pickDue()
		if msg == nil {
			return
		}
		q.attempt(msg)
	}
}

// pickDue returns the next message ready to send and marks it
// in-flight, or nil if nothing's due. Selection rules:
//
//   - skip messages currently in-flight on another worker
//   - skip messages whose NextAttempt is in the future
//   - among due+available messages, pick the one whose recipient most
//     recently announced (recipients we just heard from are most
//     likely to ack, so prioritising them shrinks effective latency
//     for users who are actually online)
//   - tie-break with FIFO so two equally-recent recipients drain in
//     enqueue order
//   - recipients with no announce on record are deprioritised — they'd
//     ride retries anyway, so giving live recipients a head start
//     doesn't penalise them
func (q *OutboundQueue) pickDue() *outboundMessage {
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()

	var best *outboundMessage
	var bestSeen time.Time
	var bestKnown bool

	for _, m := range q.pending {
		if q.inFlight[m.ID] {
			continue
		}
		if !m.NextAttempt.IsZero() && m.NextAttempt.After(now) {
			continue
		}
		seen, known := q.sender.LastAnnounceFor(m.Recipient)
		switch {
		case best == nil:
			best, bestSeen, bestKnown = m, seen, known
		case known && !bestKnown:
			// Any known recency beats unknown.
			best, bestSeen, bestKnown = m, seen, known
		case known && bestKnown && seen.After(bestSeen):
			// More recent wins among known.
			best, bestSeen, bestKnown = m, seen, known
		}
		// Other cases keep the current best (FIFO tie-break: first
		// match in the iteration order is the older enqueue).
	}
	if best != nil {
		q.inFlight[best.ID] = true
	}
	return best
}

// attempt fires one Send for msg and updates state from the outcome.
// Holds no lock across Send — Delivery.Send blocks for the link DATA
// proof on the link path, up to lxmf.LinkSendTimeout (30s default).
// Clears the in-flight marker before returning, regardless of outcome.
func (q *OutboundQueue) attempt(msg *outboundMessage) {
	q.mu.Lock()
	msg.Attempts++
	attempts := msg.Attempts
	q.mu.Unlock()

	msgID, err := q.sender.SendLXMF(msg.Recipient, msg.Body, msg.Fields)

	if err == nil && msg.Bubble != nil && q.idmap != nil && len(msgID) > 0 {
		// Register the recipient's view of this bubble's message_id so
		// inbound reactions/replies referencing it can be looked up and
		// rewritten on fan-out. Outside the queue mutex — the cache has
		// its own lock and the registration is a leaf operation.
		recipientHex := hex.EncodeToString(msg.Recipient)
		msgIDHex := hex.EncodeToString(msgID)
		q.idmap.RegisterView(msg.Bubble, recipientHex, msgIDHex)
		q.logger.Printf("idmap: registered view to=%s msgid=%s (cache size=%d)",
			recipientHex[:8], msgIDHex[:8], q.idmap.Len())
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	defer delete(q.inFlight, msg.ID)
	if err == nil {
		q.removeLocked(msg)
		q.persistLocked()
		return
	}
	if attempts >= q.maxAttempts {
		q.failLocked(msg, err)
		return
	}
	// Unknown recipient → ask for a path and back off the longer
	// PATH_REQUEST_WAIT. The first MAX_PATHLESS_TRIES attempts skip the
	// explicit path request — the inbound announce that originally
	// taught us about the destination may simply not have arrived yet,
	// and Delivery.Send already short-circuits if Recall is empty.
	if isRecipientUnknown(err) && attempts > q.pathlessTries {
		if rerr := q.sender.RequestPath(msg.Recipient); rerr != nil {
			q.logger.Printf("outbound: path? for %x: %v", msg.Recipient[:4], rerr)
		}
		msg.NextAttempt = q.now().Add(q.pathRequestWait)
	} else {
		msg.NextAttempt = q.now().Add(q.retryWait)
	}
	q.persistLocked()
	q.logger.Printf("outbound: attempt %d/%d to %x failed: %v",
		attempts, q.maxAttempts, msg.Recipient[:4], err)
}

func (q *OutboundQueue) removeLocked(msg *outboundMessage) {
	for i, m := range q.pending {
		if m == msg {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			return
		}
	}
}

// failLocked is the terminal transition: max attempts exhausted, drop the
// message and log. Mirrors LXMRouter.fail_message — no automatic re-route
// to a different delivery method (we only have opportunistic+link).
func (q *OutboundQueue) failLocked(msg *outboundMessage, err error) {
	q.removeLocked(msg)
	q.persistLocked()
	q.logger.Printf("outbound: failing message id=%s to %x after %d attempts: %v",
		msg.ID, msg.Recipient[:4], q.maxAttempts, err)
}

func (q *OutboundQueue) persistLocked() {
	if q.store == nil {
		return
	}
	if err := q.store.save(q.pending); err != nil {
		q.logger.Printf("outbound: persist failed: %v", err)
	}
}

// newMessageID returns a short random hex string used purely as a log
// correlation handle. Not security-sensitive; collisions are harmless
// because we never look messages up by ID.
func newMessageID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func isRecipientUnknown(err error) bool {
	return errors.Is(err, lxmf.ErrRecipientUnknown) || errors.Is(err, rns.ErrLinkPeerUnknown)
}

// deliverySender adapts *lxmf.Delivery + *rns.Transport to the queue's
// outboundSender interface. Single-purpose; not exported.
type deliverySender struct {
	delivery  *lxmf.Delivery
	transport *rns.Transport
}

func (d *deliverySender) SendLXMF(recipient, body []byte, fields map[any]any) ([]byte, error) {
	return d.delivery.SendWithID(recipient, nil, body, fields)
}

func (d *deliverySender) RequestPath(recipient []byte) error {
	return d.transport.RequestPath(recipient)
}

func (d *deliverySender) LastAnnounceFor(recipient []byte) (time.Time, bool) {
	known := d.transport.Recall(recipient)
	if known == nil {
		return time.Time{}, false
	}
	return known.LastSeen, true
}

// outboundStore is the on-disk backing for OutboundQueue. JSON file
// alongside state.json. Atomic-rename write so a crash mid-save can't
// leave a partial file.
type outboundStore struct {
	path string
	mu   sync.Mutex
}

const outboundStoreVersion = 1

type outboundFile struct {
	Version  int                `json:"version"`
	Messages []*outboundMessage `json:"messages"`
}

func newOutboundStore(path string) *outboundStore { return &outboundStore{path: path} }

func (s *outboundStore) load() ([]*outboundMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var f outboundFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse outbound store: %w", err)
	}
	return f.Messages, nil
}

func (s *outboundStore) save(messages []*outboundMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(outboundFile{
		Version:  outboundStoreVersion,
		Messages: messages,
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data, 0o600)
}

// atomicWrite renames a tempfile in the same directory so a crash
// mid-write can never leave a partial file behind. Same pattern used by
// roster.Store and history.Log; intentionally duplicated rather than
// pulled into a shared helper since each owner gets its own permissions
// and lifecycle.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// outboundStorePath derives the queue's storage path from the configured
// state path. Sibling file in the same directory keeps it simple — no
// extra config knob the operator has to know about.
func outboundStorePath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "outbound.json")
}
