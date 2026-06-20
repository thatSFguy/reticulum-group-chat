package service

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// makeKnownIdentity returns a syntactically-valid KnownIdentity for
// store round-trip tests. DestHash and PublicKey are the only length-
// validated fields in Transport.Restore; everything else is opaque
// bytes the store treats as data.
func makeKnownIdentity(seed byte, lastSeen time.Time) *rns.KnownIdentity {
	return &rns.KnownIdentity{
		DestHash:    bytes.Repeat([]byte{seed}, rns.IdentityHashLen),
		PublicKey:   bytes.Repeat([]byte{seed ^ 0x80}, rns.PublicKeyLen),
		NameHash:    bytes.Repeat([]byte{seed ^ 0x40}, 10),
		AppData:     []byte{seed, 'a', 'p', 'p'},
		LastSeen:    lastSeen,
		LastRandom:  bytes.Repeat([]byte{seed ^ 0x20}, 10),
		Hops:        seed % 8,
		TransportID: bytes.Repeat([]byte{seed ^ 0x10}, rns.IdentityHashLen),
	}
}

func TestAnnounceStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)

	original := []*rns.KnownIdentity{
		makeKnownIdentity(0xAA, now.Add(-1*time.Hour)),
		makeKnownIdentity(0xBB, now.Add(-12*time.Hour)),
	}
	if err := store.save(original); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, dropped, err := store.load(now)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	if len(loaded) != len(original) {
		t.Fatalf("loaded len = %d, want %d", len(loaded), len(original))
	}

	// Match by DestHash regardless of order — JSON map iteration is
	// non-deterministic in our save path (we snapshot a map).
	byHash := map[string]*rns.KnownIdentity{}
	for _, e := range loaded {
		byHash[string(e.DestHash)] = e
	}
	for _, want := range original {
		got := byHash[string(want.DestHash)]
		if got == nil {
			t.Errorf("missing entry for %x", want.DestHash[:4])
			continue
		}
		if !bytes.Equal(got.PublicKey, want.PublicKey) {
			t.Errorf("PublicKey mismatch for %x", want.DestHash[:4])
		}
		if !bytes.Equal(got.TransportID, want.TransportID) {
			t.Errorf("TransportID mismatch for %x", want.DestHash[:4])
		}
		if !got.LastSeen.Equal(want.LastSeen) {
			t.Errorf("LastSeen mismatch for %x: got %v want %v",
				want.DestHash[:4], got.LastSeen, want.LastSeen)
		}
		if got.Hops != want.Hops {
			t.Errorf("Hops mismatch for %x: got %d want %d",
				want.DestHash[:4], got.Hops, want.Hops)
		}
	}
}

func TestAnnounceStoreDropsStaleEntries(t *testing.T) {
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))
	now := time.Now()

	fresh := makeKnownIdentity(0x01, now.Add(-1*time.Hour))
	stale := makeKnownIdentity(0x02, now.Add(-(announceStoreMaxAge + time.Hour)))

	if err := store.save([]*rns.KnownIdentity{fresh, stale}); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, dropped, err := store.load(now)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (stale entry)", dropped)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded len = %d, want 1", len(loaded))
	}
	if !bytes.Equal(loaded[0].DestHash, fresh.DestHash) {
		t.Errorf("kept entry = %x, want fresh %x", loaded[0].DestHash[:4], fresh.DestHash[:4])
	}
}

func TestAnnounceStoreNoFileMeansEmpty(t *testing.T) {
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))

	loaded, dropped, err := store.load(time.Now())
	if err != nil {
		t.Fatalf("load on missing file: %v", err)
	}
	if loaded != nil {
		t.Errorf("loaded = %v, want nil", loaded)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestTransportRestoreRoundTripsThroughRecall(t *testing.T) {
	transport := rns.NewTransport(nil)
	now := time.Now()
	original := makeKnownIdentity(0xCC, now)

	transport.Restore(original)

	got := transport.Recall(original.DestHash)
	if got == nil {
		t.Fatalf("Recall returned nil after Restore")
	}
	if !bytes.Equal(got.PublicKey, original.PublicKey) {
		t.Errorf("PublicKey not preserved by Restore")
	}
	if !bytes.Equal(got.TransportID, original.TransportID) {
		t.Errorf("TransportID not preserved by Restore")
	}

	// Mutate the original to verify Restore deep-copied — the cached
	// entry must not change.
	original.PublicKey[0] = 0xFF
	got2 := transport.Recall(original.DestHash)
	if got2.PublicKey[0] == 0xFF {
		t.Errorf("Restore did not deep-copy PublicKey")
	}
}

func TestTransportRestoreRejectsInvalidLengths(t *testing.T) {
	transport := rns.NewTransport(nil)
	bad := &rns.KnownIdentity{
		DestHash:  []byte{1, 2, 3},                              // wrong length
		PublicKey: bytes.Repeat([]byte{0xAA}, rns.PublicKeyLen), // valid
	}
	transport.Restore(bad)

	if got := transport.Recall(bad.DestHash); got != nil {
		t.Errorf("Recall returned non-nil for invalid-length entry")
	}
}

func TestTransportKnownSnapshotIsDeepCopy(t *testing.T) {
	transport := rns.NewTransport(nil)
	transport.Restore(makeKnownIdentity(0x11, time.Now()))
	transport.Restore(makeKnownIdentity(0x22, time.Now()))

	snap := transport.KnownSnapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}

	// Mutating a snapshot entry must not affect future Recall results.
	snap[0].PublicKey[0] = 0xFF
	got := transport.Recall(snap[0].DestHash)
	if got != nil && got.PublicKey[0] == 0xFF {
		t.Errorf("KnownSnapshot did not deep-copy PublicKey")
	}
}
