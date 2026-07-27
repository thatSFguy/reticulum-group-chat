package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// announceStoreMaxAge bounds how stale a persisted announce can be at
// load time — older entries are dropped rather than restored. Mirrors
// upstream Reticulum's default-mode path-table TTL of 30 days. A daemon
// that's been off longer than this should re-discover peers via
// announces, not trust a cache that may name long-gone identities.
const announceStoreMaxAge = 30 * 24 * time.Hour

const announceStoreVersion = 1

// announceFile is the on-disk shape. KnownIdentity has JSON tags, so it
// embeds directly — no parallel struct needed.
type announceFile struct {
	Version int                  `json:"version"`
	Entries []*rns.KnownIdentity `json:"entries"`
}

// announceStore persists Transport.known to disk so a service restart
// doesn't have to wait for every peer to re-announce. File lives next
// to state.json with the same atomic-rename pattern.
type announceStore struct {
	path string
	mu   sync.Mutex
}

func newAnnounceStore(path string) *announceStore { return &announceStore{path: path} }

// announceStorePath derives the announce-cache path from the configured
// state path (sibling file). No new config knob.
func announceStorePath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "announces.json")
}

// load reads the persisted entries, dropping anything older than
// announceStoreMaxAge so a long-offline daemon doesn't resurrect
// peers that have probably gone away.
func (s *announceStore) load(now time.Time) ([]*rns.KnownIdentity, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	if len(data) == 0 {
		return nil, 0, nil
	}
	var f announceFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("parse announce store: %w", err)
	}
	cutoff := now.Add(-announceStoreMaxAge)
	kept := make([]*rns.KnownIdentity, 0, len(f.Entries))
	dropped := 0
	for _, e := range f.Entries {
		if e == nil {
			continue
		}
		if e.LastSeen.Before(cutoff) {
			dropped++
			continue
		}
		kept = append(kept, e)
	}
	return kept, dropped, nil
}

func (s *announceStore) save(entries []*rns.KnownIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(announceFile{
		Version: announceStoreVersion,
		Entries: entries,
	}, "", "  ")
	if err != nil {
		// One unmarshalable entry must not cost us the whole cache.
		// Entry contents derive from peer-supplied announce fields, so
		// a single hostile or broken peer could otherwise stop the
		// cache persisting entirely — which is not a visible failure,
		// it just means every peer has to be re-learned after each
		// restart. Drop the offenders and save the rest.
		kept := make([]*rns.KnownIdentity, 0, len(entries))
		skipped := 0
		for _, e := range entries {
			if _, mErr := json.Marshal(e); mErr != nil {
				skipped++
				continue
			}
			kept = append(kept, e)
		}
		if skipped == 0 {
			return err // not an per-entry problem; surface it
		}
		data, err = json.MarshalIndent(announceFile{
			Version: announceStoreVersion,
			Entries: kept,
		}, "", "  ")
		if err != nil {
			return err
		}
	}
	return atomicWrite(s.path, data, 0o600)
}

// announcePersistDebounce is how long the persist goroutine waits after
// the first kick before snapshotting, so a testnet announce burst
// (several per second) coalesces into one write instead of N.
const announcePersistDebounce = 2 * time.Second

// announcePersistTap is an AnnounceHandler that keeps announces.json in
// sync with the Transport's known map. Matches every aspect (returns
// true unconditionally from AspectMatch) so we cache identities for any
// aspect we may want to reach in the future, not just lxmf.delivery.
//
// Persistence is asynchronous: OnAnnounce only sets a non-blocking kick
// flag, and the run goroutine (started from Service.Run) debounces and
// writes off the dispatcher. This used to save synchronously per
// announce, which was fine when the cache was a few KB — but the known
// map grows with every peer ever heard (2000+ entries, ~1 MB JSON on a
// long-lived testnet deployment), and a ~1 MB marshal+write inside the
// dispatcher goroutine per announce delays every inbound DATA packet
// and outbound delivery proof queued behind it.
type announcePersistTap struct {
	transport *rns.Transport
	store     *announceStore
	logger    *log.Logger

	// kick is buffered(1): OnAnnounce sets it without blocking; the run
	// loop drains it. Multiple announces between saves collapse into
	// one pending kick.
	kick chan struct{}

	// debounce defaults to announcePersistDebounce; overridable in tests.
	debounce time.Duration
}

func newAnnouncePersistTap(transport *rns.Transport, store *announceStore, logger *log.Logger) *announcePersistTap {
	return &announcePersistTap{
		transport: transport,
		store:     store,
		logger:    logger,
		kick:      make(chan struct{}, 1),
		debounce:  announcePersistDebounce,
	}
}

func (t *announcePersistTap) AspectMatch(_ []byte) bool { return true }

func (t *announcePersistTap) OnAnnounce(_ *rns.Announce) {
	select {
	case t.kick <- struct{}{}:
	default: // a save is already pending; it will cover this announce
	}
}

// run is the persist loop. Call as a goroutine from Service.Run; exits
// on ctx cancel after one final save so the freshest announces survive
// a graceful shutdown.
func (t *announcePersistTap) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			t.saveNow()
			return
		case <-t.kick:
			// Coalesce the burst that typically follows the first
			// announce, then drain any kick that arrived while we
			// waited — the snapshot below covers those announces too.
			select {
			case <-time.After(t.debounce):
			case <-ctx.Done():
				t.saveNow()
				return
			}
			select {
			case <-t.kick:
			default:
			}
			t.saveNow()
		}
	}
}

func (t *announcePersistTap) saveNow() {
	if err := t.store.save(t.transport.KnownSnapshot()); err != nil {
		t.logger.Printf("announce cache save: %v", err)
	}
}
