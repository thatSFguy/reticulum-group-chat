package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
)

// makeKnownIdentity returns a syntactically-valid KnownIdentity for
// store round-trip tests. DestHash and PublicKey are the only length-
// validated fields in Transport.Restore; everything else is opaque
// bytes the store treats as data.
func makeKnownIdentity(seed byte, lastSeen time.Time) *rns.KnownIdentity {
	// DestHash must genuinely derive from PublicKey + NameHash:
	// Transport.Restore re-checks that binding (a stored pairing is
	// otherwise a way to bind a victim's destination to an attacker
	// key), so a synthetic mismatched fixture would be rejected.
	pub := bytes.Repeat([]byte{seed ^ 0x80}, rns.PublicKeyLen)
	nameHash := bytes.Repeat([]byte{seed ^ 0x40}, 10)
	idHash := sha256.Sum256(pub)
	return &rns.KnownIdentity{
		DestHash:    rns.DestinationHash(nameHash, idHash[:rns.IdentityHashLen]),
		PublicKey:   pub,
		NameHash:    nameHash,
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

func TestPersistTapWritesAsyncAndCoalesces(t *testing.T) {
	// OnAnnounce must never write from the caller's (dispatcher's)
	// goroutine — it only kicks the run loop, which debounces a burst
	// of announces into one snapshot.
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))
	transport := rns.NewTransport(nil)
	transport.Restore(makeKnownIdentity(0x01, time.Now()))

	tap := newAnnouncePersistTap(transport, store, log.New(io.Discard, "", 0))
	tap.debounce = 20 * time.Millisecond

	// Stop the run loop and WAIT for it to exit before the test
	// returns. run performs a final flush on ctx.Done, so without the
	// wait that write races t.TempDir()'s cleanup — the directory gets
	// a file back after removal starts and cleanup fails with
	// "directory not empty". Registered after t.TempDir() so it runs
	// BEFORE the tempdir cleanup (t.Cleanup is LIFO).
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-runDone
	})
	go func() {
		defer close(runDone)
		tap.run(ctx)
	}()

	// A burst of announces.
	for i := 0; i < 10; i++ {
		tap.OnAnnounce(nil)
	}

	// Nothing on disk yet (still inside the debounce window) — proves
	// OnAnnounce itself didn't write synchronously.
	if _, err := os.Stat(store.path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("store written before debounce elapsed (err=%v)", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if entries, _, err := store.load(time.Now()); err == nil && len(entries) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("debounced save never landed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPersistTapFinalSaveOnShutdown(t *testing.T) {
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))
	transport := rns.NewTransport(nil)
	transport.Restore(makeKnownIdentity(0x02, time.Now()))

	tap := newAnnouncePersistTap(transport, store, log.New(io.Discard, "", 0))
	tap.debounce = time.Hour // never fires on its own

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tap.run(ctx)
		close(done)
	}()
	tap.OnAnnounce(nil)
	cancel()
	<-done

	entries, _, err := store.load(time.Now())
	if err != nil {
		t.Fatalf("load after shutdown: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("final save wrote %d entries, want 1", len(entries))
	}
}

// TestAnnounceStoreSkipsUnmarshalableEntry covers the second half of the
// v1.14.2 fix — the one the plausibility bound is a backstop for.
//
// Entry contents derive from peer-supplied announce fields. Before this,
// a single entry that json.Marshal rejected failed the WHOLE cache save,
// and the failure is invisible in normal operation: the service runs on,
// but nothing persists, so every peer must be re-learned after a restart
// (and until they re-announce, their messages cannot be verified and are
// dropped). One bad peer therefore degraded delivery for all of them.
func TestAnnounceStoreSkipsUnmarshalableEntry(t *testing.T) {
	dir := t.TempDir()
	store := newAnnounceStore(filepath.Join(dir, "announces.json"))

	good1 := makeKnownIdentity(0x01, time.Now())
	good2 := makeKnownIdentity(0x02, time.Now())

	// Year 36812 — the top of EmittedAt's 40-bit range. time.Time
	// refuses to marshal any year outside [0,9999].
	poisoned := makeKnownIdentity(0x03, time.Now())
	poisoned.EmittedAt = time.Unix(1<<40-1, 0).UTC()
	if _, err := json.Marshal(poisoned); err == nil {
		t.Fatal("premise broken: poisoned entry should not marshal")
	}

	if err := store.save([]*rns.KnownIdentity{good1, poisoned, good2}); err != nil {
		t.Fatalf("save failed on one bad entry instead of skipping it: %v", err)
	}

	entries, _, err := store.load(time.Now())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("persisted %d entries, want the 2 good ones", len(entries))
	}
	for _, e := range entries {
		if bytes.Equal(e.DestHash, poisoned.DestHash) {
			t.Error("poisoned entry was persisted")
		}
	}

	// A save with no bad entries must still work normally.
	if err := store.save([]*rns.KnownIdentity{good1}); err != nil {
		t.Fatalf("clean save failed: %v", err)
	}
	if entries, _, _ := store.load(time.Now()); len(entries) != 1 {
		t.Errorf("clean save persisted %d entries, want 1", len(entries))
	}
}
