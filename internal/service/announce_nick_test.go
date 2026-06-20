package service

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
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
