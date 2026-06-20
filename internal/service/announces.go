package service

import (
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
		return err
	}
	return atomicWrite(s.path, data, 0o600)
}

// announcePersistTap is an AnnounceHandler that re-snapshots the
// Transport's known map and saves it after every verified announce.
// Matches every aspect (returns true unconditionally from AspectMatch)
// so we cache identities for any aspect we may want to reach in the
// future, not just lxmf.delivery.
//
// Snapshot-on-every-announce keeps the on-disk file consistent with
// in-memory state but does mean we write to disk from the Transport
// dispatcher goroutine. This is the same pattern the existing
// announceTap uses to update the roster's last_announce timestamp,
// so it's already on the dispatcher's hot path; the marginal cost
// of the announce-cache write is one additional ~few-KB JSON
// serialize per inbound announce.
type announcePersistTap struct {
	transport *rns.Transport
	store     *announceStore
	logger    *log.Logger
}

func (t *announcePersistTap) AspectMatch(_ []byte) bool { return true }

func (t *announcePersistTap) OnAnnounce(_ *rns.Announce) {
	if err := t.store.save(t.transport.KnownSnapshot()); err != nil {
		t.logger.Printf("announce cache save: %v", err)
	}
}
