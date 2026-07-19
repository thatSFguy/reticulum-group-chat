package commands

import (
	"encoding/hex"
	"strings"
	"testing"
)

// lockedDispatcher is newDispatcher with the group set to invite-only.
func lockedDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	d := newDispatcher(t)
	d.Cfg.Service.Locked = true
	return d
}

func TestLockedJoinRefusedForRegularUser(t *testing.T) {
	d := lockedDispatcher(t)
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "closed group") {
		t.Errorf("expected closed-group bounce, got %q", out)
	}
	// Bounce must echo the user their own hash so they can hand it to an admin.
	if !strings.Contains(out, userHash) {
		t.Errorf("bounce should echo the user's hash %s, got %q", userHash, out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user must NOT be in roster after a refused locked /join")
	}
}

func TestLockedJoinBypassedByConfigAdminAndMod(t *testing.T) {
	for _, h := range []string{adminHash, modHash} {
		d := lockedDispatcher(t)
		out := d.Dispatch(h, Parse("/join"))
		if strings.Contains(strings.ToLower(out), "closed group") {
			t.Errorf("config privileged user %s should bypass the lock, got %q", h[:8], out)
		}
		if !d.Roster.Has(mustBytes(t, h)) {
			t.Errorf("%s should be in roster after /join", h[:8])
		}
	}
}

func TestUnlockedJoinStillWorks(t *testing.T) {
	d := newDispatcher(t) // not locked
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "joined") {
		t.Errorf("open chat should admit a regular /join, got %q", out)
	}
}

func TestAddUserRequiresMod(t *testing.T) {
	d := lockedDispatcher(t)
	out := d.Dispatch(userHash, Parse("/adduser "+userHash))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial for regular user, got %q", out)
	}
}

func TestAddUserAddsInvitedMemberAndFiresHook(t *testing.T) {
	d := lockedDispatcher(t)
	var added string
	d.OnAdminAdd = func(h string) { added = h }

	out := d.Dispatch(adminHash, Parse("/adduser "+userHash))
	if !strings.Contains(strings.ToLower(out), "added") {
		t.Errorf("expected add confirmation, got %q", out)
	}
	if !d.Roster.Has(mustBytes(t, userHash)) {
		t.Fatal("added user should be in roster")
	}
	u, ok := d.Roster.Get(userHash)
	if !ok || !u.Invited {
		t.Errorf("added user should be marked Invited, got %+v", u)
	}
	if added != userHash {
		t.Errorf("OnAdminAdd called with %q, want %q", added, userHash)
	}
}

func TestAddUserRejectsBadHash(t *testing.T) {
	d := lockedDispatcher(t)
	out := d.Dispatch(adminHash, Parse("/adduser not-a-hash"))
	if !strings.Contains(strings.ToLower(out), "valid address") {
		t.Errorf("expected bad-hash message, got %q", out)
	}
}

func TestAddUserRejectsBanned(t *testing.T) {
	d := lockedDispatcher(t)
	if err := d.Roster.Ban(userHash); err != nil {
		t.Fatal(err)
	}
	out := d.Dispatch(adminHash, Parse("/adduser "+userHash))
	if !strings.Contains(strings.ToLower(out), "banned") {
		t.Errorf("expected banned refusal, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("banned user must not be added")
	}
}

func TestAddUserAlreadyMember(t *testing.T) {
	d := lockedDispatcher(t)
	_ = d.Dispatch(adminHash, Parse("/adduser "+userHash))
	var secondFired bool
	d.OnAdminAdd = func(string) { secondFired = true }
	out := d.Dispatch(adminHash, Parse("/adduser "+userHash))
	if !strings.Contains(strings.ToLower(out), "already in the group") {
		t.Errorf("expected already-member message, got %q", out)
	}
	if secondFired {
		t.Error("OnAdminAdd should not fire for an already-present member")
	}
}

func TestAddUserRespectsMaxMembers(t *testing.T) {
	d := lockedDispatcher(t)
	d.Cfg.Service.MaxMembers = 1
	_ = d.Dispatch(adminHash, Parse("/adduser "+userHash)) // fills the single slot
	other := "dddddddddddddddddddddddddddddddd"
	out := d.Dispatch(adminHash, Parse("/adduser "+other))
	if !strings.Contains(strings.ToLower(out), "full") {
		t.Errorf("expected full-group refusal, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, other)) {
		t.Error("over-cap add must not land in roster")
	}
}

// TestAddUserUnknownVsKnownReply pins the two operator-reply variants:
// a peer we've never heard from is welcomed "once we hear from them",
// while a peer with a known path is welcomed immediately.
func TestAddUserUnknownVsKnownReply(t *testing.T) {
	d := lockedDispatcher(t)
	d.PathLookup = func(h string) PathInfo {
		if h == userHash {
			return PathInfo{Known: true}
		}
		return PathInfo{Known: false}
	}
	known := d.Dispatch(adminHash, Parse("/adduser "+userHash))
	if !strings.Contains(strings.ToLower(known), "sent them a welcome") {
		t.Errorf("known peer: expected immediate-welcome reply, got %q", known)
	}
	other := "dddddddddddddddddddddddddddddddd"
	unknown := d.Dispatch(adminHash, Parse("/adduser "+other))
	if !strings.Contains(strings.ToLower(unknown), "once we hear from them") {
		t.Errorf("unknown peer: expected deferred-welcome reply, got %q", unknown)
	}
}

func TestAddUserDefaultsNicknameFromAnnounce(t *testing.T) {
	d := lockedDispatcher(t)
	d.LookupAnnouncedName = func(h []byte) string {
		if hex.EncodeToString(h) == userHash {
			return "Radio Ray"
		}
		return ""
	}
	_ = d.Dispatch(adminHash, Parse("/adduser "+userHash))
	u, ok := d.Roster.Get(userHash)
	if !ok {
		t.Fatal("user not in roster")
	}
	if u.Nickname != "Radio_Ray" {
		t.Errorf("default nick = %q, want %q", u.Nickname, "Radio_Ray")
	}
}

func TestRemoveUserRequiresMod(t *testing.T) {
	d := lockedDispatcher(t)
	out := d.Dispatch(userHash, Parse("/removeuser "+userHash))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial, got %q", out)
	}
}

func TestRemoveUserRemovesAndReportsLocked(t *testing.T) {
	d := lockedDispatcher(t)
	_ = d.Dispatch(adminHash, Parse("/adduser "+userHash))
	out := d.Dispatch(adminHash, Parse("/removeuser "+userHash))
	if !strings.Contains(strings.ToLower(out), "removed") {
		t.Errorf("expected removal confirmation, got %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "adduser") {
		t.Errorf("locked removal should mention re-add via /adduser, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be gone from roster after /removeuser")
	}
}

func TestRemoveUserUnlockedMentionsRejoin(t *testing.T) {
	d := newDispatcher(t) // unlocked
	_ = d.Dispatch(userHash, Parse("/join"))
	out := d.Dispatch(adminHash, Parse("/removeuser "+userHash))
	if !strings.Contains(strings.ToLower(out), "rejoin with /join") {
		t.Errorf("unlocked removal should point at /join, got %q", out)
	}
}

func TestRemoveUserNotAMember(t *testing.T) {
	d := lockedDispatcher(t)
	out := d.Dispatch(adminHash, Parse("/removeuser "+userHash))
	if !strings.Contains(strings.ToLower(out), "no user matches") &&
		!strings.Contains(strings.ToLower(out), "not in the group") {
		t.Errorf("expected not-a-member message, got %q", out)
	}
}
