package service

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/roster"
)

// newTestTap builds the smallest *Service skeleton announceTap reads: a
// roster backed by a tempfile store, a discard logger, and a fixed now.
// No transport, no delivery — announceTap.OnAnnounce only touches
// roster + logger + now.
func newTestTap(t *testing.T) (*announceTap, *roster.Roster) {
	t.Helper()
	r, err := roster.New(roster.NewStore(filepath.Join(t.TempDir(), "state.json")))
	if err != nil {
		t.Fatalf("roster.New: %v", err)
	}
	svc := &Service{
		roster: r,
		logger: log.New(io.Discard, "", 0),
		now:    func() time.Time { return time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC) },
	}
	return &announceTap{svc: svc}, r
}

func makeAnnounce(destHash []byte, displayName string) *rns.Announce {
	appData, _ := rns.EncodeLXMFAppData([]byte(displayName), nil)
	return &rns.Announce{DestHash: append([]byte(nil), destHash...), AppData: appData}
}

// makeAnnounceAt builds an announce whose signed random_hash encodes the
// given emission time, so EmittedAt() decodes back to `emitted`. The first
// 5 bytes (entropy) are left zero — only the timestamp half matters here.
func makeAnnounceAt(destHash []byte, emitted time.Time) *rns.Announce {
	rh := make([]byte, 10)
	ts := rns.BigEndianUint40(uint64(emitted.Unix()))
	copy(rh[5:], ts[:])
	return &rns.Announce{DestHash: append([]byte(nil), destHash...), RandomHash: rh}
}

// A replayed announce carries an OLD emission time (its original signed
// random_hash), even though we receive it now. The tap must record that old
// time, not our receive time — otherwise a long-gone identity whose cached
// announce gets re-emitted by a transport node looks perpetually fresh and
// dodges Prune.
func TestAnnounceStampsEmittedTimeNotReceiveTime(t *testing.T) {
	tap, r := newTestTap(t)
	now := tap.svc.now()
	dest := bytes.Repeat([]byte{0x11}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, now.Add(-7*24*time.Hour)); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}

	emitted := now.Add(-30 * 24 * time.Hour) // a month-old replayed announce
	tap.OnAnnounce(makeAnnounceAt(dest, emitted))

	u, _ := r.Get(hex.EncodeToString(dest))
	if !u.LastAnnounceAt.Equal(emitted) {
		t.Errorf("LastAnnounceAt = %v, want emission time %v (not receive time %v)", u.LastAnnounceAt, emitted, now)
	}
}

// A future-dated announce (clock skew, or a malformed/missing timestamp)
// must not push last_announce_at past real time.
func TestAnnounceClampsFutureEmissionToNow(t *testing.T) {
	tap, r := newTestTap(t)
	now := tap.svc.now()
	dest := bytes.Repeat([]byte{0x22}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, now.Add(-7*24*time.Hour)); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}

	tap.OnAnnounce(makeAnnounceAt(dest, now.Add(48*time.Hour)))

	u, _ := r.Get(hex.EncodeToString(dest))
	if u.LastAnnounceAt.After(now) {
		t.Errorf("LastAnnounceAt = %v, must be clamped to now %v or earlier", u.LastAnnounceAt, now)
	}
}

func TestAnnounceAdoptsNicknameWhenUnset(t *testing.T) {
	tap, r := newTestTap(t)
	dest := bytes.Repeat([]byte{0xAA}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, time.Now()); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}

	tap.OnAnnounce(makeAnnounce(dest, "Hello World"))

	u, ok := r.Get(hex.EncodeToString(dest))
	if !ok {
		t.Fatalf("user vanished from roster")
	}
	if u.Nickname != "Hello_World" {
		t.Errorf("Nickname = %q, want %q (sanitized announce display name)", u.Nickname, "Hello_World")
	}
}

func TestAnnounceDoesNotOverwriteExistingNickname(t *testing.T) {
	tap, r := newTestTap(t)
	dest := bytes.Repeat([]byte{0xBB}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, time.Now()); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}
	if err := r.SetNickname(hex.EncodeToString(dest), "Chosen"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}

	tap.OnAnnounce(makeAnnounce(dest, "Different Name"))

	u, _ := r.Get(hex.EncodeToString(dest))
	if u.Nickname != "Chosen" {
		t.Errorf("Nickname = %q, want %q (user-set nick must not be overwritten)", u.Nickname, "Chosen")
	}
}

func TestAnnounceIgnoresNonMembers(t *testing.T) {
	tap, r := newTestTap(t)
	dest := bytes.Repeat([]byte{0xCC}, rns.IdentityHashLen)

	// User is NOT in the roster.
	tap.OnAnnounce(makeAnnounce(dest, "Drifter"))

	if _, ok := r.Get(hex.EncodeToString(dest)); ok {
		t.Errorf("non-member should not be auto-added by announce; got user in roster")
	}
}

func TestAnnounceWithUnusableNameLeavesNicknameEmpty(t *testing.T) {
	tap, r := newTestTap(t)
	dest := bytes.Repeat([]byte{0xDD}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, time.Now()); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}

	// All-emoji display name sanitizes to "" — must NOT set a blank nick.
	tap.OnAnnounce(makeAnnounce(dest, "🦆🦆🦆"))

	u, _ := r.Get(hex.EncodeToString(dest))
	if u.Nickname != "" {
		t.Errorf("Nickname = %q, want empty (sanitization yielded nothing usable)", u.Nickname)
	}
}

func TestAnnounceWithEmptyAppDataLeavesNicknameEmpty(t *testing.T) {
	tap, r := newTestTap(t)
	dest := bytes.Repeat([]byte{0xEE}, rns.IdentityHashLen)
	if _, err := r.AddOrUpdate(dest, time.Now()); err != nil {
		t.Fatalf("AddOrUpdate: %v", err)
	}

	tap.OnAnnounce(&rns.Announce{DestHash: append([]byte(nil), dest...)})

	u, _ := r.Get(hex.EncodeToString(dest))
	if u.Nickname != "" {
		t.Errorf("Nickname = %q, want empty (no app_data, no name to adopt)", u.Nickname)
	}
}
