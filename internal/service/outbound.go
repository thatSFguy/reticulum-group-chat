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
)

// outboundMessage is one queued LXMF message awaiting delivery. The drain
// loop attempts it on each tick until either Delivery.Send returns nil
// (success → removed from queue) or Attempts > maxDeliveryAttempts
// (terminal fail_message). Persisted as-is to outbound.json so a service
// restart resumes pending sends instead of dropping them.
type outboundMessage struct {
	ID          string    `json:"id"`
	Recipient   []byte    `json:"recipient"`    // 16-byte lxmf.delivery dest_hash
	Body        []byte    `json:"body"`         // pre-formatted UTF-8 chat body or command reply
	Attempts    int       `json:"attempts"`     // 0..maxDeliveryAttempts
	NextAttempt time.Time `json:"next_attempt"` // zero = ready now
	EnqueuedAt  time.Time `json:"enqueued_at"`
}

// outboundSender is the subset of *lxmf.Delivery + *rns.Transport the
// queue calls into. Defined as an interface so tests can inject a fake
// without standing up a real transport.
type outboundSender interface {
	SendLXMF(recipient, body []byte) error
	RequestPath(recipient []byte) error
}

// OutboundQueue serializes outbound LXMF deliveries through Delivery.Send
// with retry semantics matching LXMF 0.9.7's LXMRouter.process_outbound.
//
// One drain goroutine runs sequentially — half-duplex LoRa interfaces
// collide if multiple sends race, so parallel delivery would defeat the
// retry resilience the queue exists to provide. Multiple due messages
// drain per tick, but each Send blocks until proof or timeout.
type OutboundQueue struct {
	sender outboundSender
	store  *outboundStore
	logger *log.Logger

	mu      sync.Mutex
	pending []*outboundMessage

	// Tunables exposed for tests; production uses the package constants.
	interval        time.Duration
	retryWait       time.Duration
	pathRequestWait time.Duration
	maxAttempts     int
	pathlessTries   int

	now func() time.Time
}

func newOutboundQueue(sender outboundSender, store *outboundStore, logger *log.Logger) *OutboundQueue {
	return &OutboundQueue{
		sender:          sender,
		store:           store,
		logger:          logger,
		interval:        processingInterval,
		retryWait:       deliveryRetryWait,
		pathRequestWait: pathRequestWait,
		maxAttempts:     maxDeliveryAttempts,
		pathlessTries:   maxPathlessTries,
		now:             time.Now,
	}
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
	msg := &outboundMessage{
		ID:         newMessageID(),
		Recipient:  append([]byte(nil), recipient...),
		Body:       append([]byte(nil), body...),
		EnqueuedAt: q.now(),
	}
	q.mu.Lock()
	q.pending = append(q.pending, msg)
	q.persistLocked()
	q.mu.Unlock()
	return msg.ID
}

// Run drives the drain loop until ctx is cancelled. Sends are sequential.
func (q *OutboundQueue) Run(ctx context.Context) {
	ticker := time.NewTicker(q.interval)
	defer ticker.Stop()
	q.processOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.processOnce(ctx)
		}
	}
}

// pendingCount returns the queue depth. For tests + future telemetry.
func (q *OutboundQueue) pendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

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

func (q *OutboundQueue) pickDue() *outboundMessage {
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, m := range q.pending {
		if m.NextAttempt.IsZero() || !m.NextAttempt.After(now) {
			return m
		}
	}
	return nil
}

// attempt fires one Send for msg and updates state from the outcome.
// Holds no lock across Send — Delivery.Send blocks for the link DATA
// proof on the link path, up to lxmf.LinkSendTimeout (30s default).
func (q *OutboundQueue) attempt(msg *outboundMessage) {
	q.mu.Lock()
	msg.Attempts++
	attempts := msg.Attempts
	q.mu.Unlock()

	err := q.sender.SendLXMF(msg.Recipient, msg.Body)

	q.mu.Lock()
	defer q.mu.Unlock()
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

func (d *deliverySender) SendLXMF(recipient, body []byte) error {
	return d.delivery.Send(recipient, nil, body, nil)
}

func (d *deliverySender) RequestPath(recipient []byte) error {
	return d.transport.RequestPath(recipient)
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
