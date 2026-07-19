package roster

import (
	"testing"
	"time"
)

func TestAddInvitedMarksAndIsNew(t *testing.T) {
	r, _ := newTestRoster(t)
	now := time.Now()
	isNew, err := r.AddInvited(mustHash(t, hashA), now)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first AddInvited should report new")
	}
	u, ok := r.Get(hashA)
	if !ok {
		t.Fatal("invited user not in roster")
	}
	if !u.Invited {
		t.Error("user should be marked Invited")
	}
	// An invitee has not spoken: LastMessageAt must be zero so they aren't
	// credited with activity they never produced.
	if !u.LastMessageAt.IsZero() {
		t.Errorf("invited user should have zero LastMessageAt, got %v", u.LastMessageAt)
	}
}

func TestAddInvitedDoesNotClobberExisting(t *testing.T) {
	r, _ := newTestRoster(t)
	now := time.Now()
	if _, err := r.AddOrUpdate(mustHash(t, hashA), now); err != nil {
		t.Fatal(err)
	}
	isNew, err := r.AddInvited(mustHash(t, hashA), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("AddInvited on an existing member should report not-new")
	}
	u, _ := r.Get(hashA)
	if u.Invited {
		t.Error("an already-present member must not be flipped to Invited")
	}
}

// TestPruneSkipsInvited: an invitee who has never been heard from is
// exempt even when their JoinedAt is ancient — otherwise a locked-group
// invite that sits unopened for weeks would be swept before the user
// ever comes online.
func TestPruneSkipsInvited(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Now()
	if _, err := r.AddInvited(mustHash(t, hashA), t0.Add(-10*7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 6*7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("invited member should be prune-exempt, got pruned %v", pruned)
	}
	if !r.Has(mustHash(t, hashA)) {
		t.Error("invited member should still be present after prune")
	}
}

// TestInvitedClearedByFirstContact: once the invitee is heard from, the
// exemption lifts and normal prune rules apply again.
func TestInvitedClearedByFirstContact(t *testing.T) {
	cases := []struct {
		name    string
		contact func(r *Roster, at time.Time)
	}{
		{"message", func(r *Roster, at time.Time) { _, _ = r.MarkMessage(mustHash(t, hashA), at) }},
		{"command", func(r *Roster, at time.Time) { _, _ = r.Touch(mustHash(t, hashA), at) }},
		{"announce", func(r *Roster, at time.Time) { _ = r.UpdateLastAnnounce(mustHash(t, hashA), at) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestRoster(t)
			t0 := time.Now()
			if _, err := r.AddInvited(mustHash(t, hashA), t0); err != nil {
				t.Fatal(err)
			}
			tc.contact(r, t0)
			u, ok := r.Get(hashA)
			if !ok {
				t.Fatal("user vanished")
			}
			if u.Invited {
				t.Errorf("Invited flag should clear after first %s", tc.name)
			}
		})
	}
}

// TestInvitedExemptionSurvivesReload confirms the flag round-trips through
// the persisted state file (it rides on the User record).
func TestInvitedExemptionSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir + "/state.json")
	r, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddInvited(mustHash(t, hashA), time.Now()); err != nil {
		t.Fatal(err)
	}

	r2, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := r2.Get(hashA)
	if !ok {
		t.Fatal("invited user missing after reload")
	}
	if !u.Invited {
		t.Error("Invited flag should survive a state reload")
	}
}
