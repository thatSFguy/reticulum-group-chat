package service

import (
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/roster"
)

func newEnrollRoster(t *testing.T) *roster.Roster {
	t.Helper()
	store := roster.NewStore(filepath.Join(t.TempDir(), "state.json"))
	r, err := roster.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	enrollAdmin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	enrollMod   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestEnrollConfigRolesAddsAdminsAndMods(t *testing.T) {
	r := newEnrollRoster(t)
	cfg := &config.Config{Admins: []string{enrollAdmin}, Mods: []string{enrollMod}}

	n := enrollConfigRoles(r, cfg, time.Now())
	if n != 2 {
		t.Fatalf("enrolled = %d, want 2", n)
	}
	for _, h := range []string{enrollAdmin, enrollMod} {
		if !r.Has(mustBytes(t, h)) {
			t.Errorf("%s should be a roster member after enroll", h[:8])
		}
		u, ok := r.Get(h)
		if !ok || !u.Invited {
			t.Errorf("%s should be marked Invited (prune-exempt until seen), got %+v", h[:8], u)
		}
	}
}

// TestEnrollConfigRolesIdempotent: an admin who's already a full member
// (nickname, not invited) must not be clobbered or re-marked invited, and
// must not be double-counted.
func TestEnrollConfigRolesIdempotent(t *testing.T) {
	r := newEnrollRoster(t)
	// Admin is already a real, joined member with a nickname.
	if _, err := r.AddOrUpdate(mustBytes(t, enrollAdmin), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.SetNickname(enrollAdmin, "boss"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Admins: []string{enrollAdmin}, Mods: []string{enrollMod}}

	n := enrollConfigRoles(r, cfg, time.Now())
	if n != 1 { // only the mod is new
		t.Fatalf("enrolled = %d, want 1 (admin already present)", n)
	}
	u, _ := r.Get(enrollAdmin)
	if u.Nickname != "boss" {
		t.Errorf("existing admin nickname clobbered: %q", u.Nickname)
	}
	if u.Invited {
		t.Error("existing full member must not be flipped back to Invited")
	}
}

func TestEnrollConfigRolesNoneConfigured(t *testing.T) {
	r := newEnrollRoster(t)
	if n := enrollConfigRoles(r, &config.Config{}, time.Now()); n != 0 {
		t.Errorf("enrolled = %d, want 0 with no admins/mods", n)
	}
}
