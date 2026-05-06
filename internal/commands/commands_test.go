package commands

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

const (
	adminHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	modHash   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	userHash  = "cccccccccccccccccccccccccccccccc"
)

func TestIsCommand(t *testing.T) {
	cases := map[string]bool{
		"/?":         true,
		"  /help ":   true,
		"/users":     true,
		"hello":      false,
		"":           false,
		"  no slash": false,
	}
	for in, want := range cases {
		if got := IsCommand(in); got != want {
			t.Errorf("IsCommand(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSplitsArgs(t *testing.T) {
	p := Parse("/nick   alice   ")
	if p.Name != "nick" {
		t.Errorf("Name=%q", p.Name)
	}
	if len(p.Args) != 1 || p.Args[0] != "alice" {
		t.Errorf("Args=%v", p.Args)
	}
	p = Parse("/kick alice bob")
	if len(p.Args) != 2 {
		t.Errorf("/kick alice bob: Args=%v", p.Args)
	}
}

func newDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	dir := t.TempDir()
	store := roster.NewStore(filepath.Join(dir, "state.json"))
	r, err := roster.New(store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Admins: []string{adminHash},
		Mods:   []string{modHash},
	}
	return &Dispatcher{Cfg: cfg, Roster: r}
}

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	b := mustHexBytes(s)
	if b == nil {
		t.Fatalf("bad hex: %s", s)
	}
	return b
}

func TestHelpListsAllCommands(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/?"))
	for _, want := range []string{"/users", "/mods", "/admin", "/nick", "/kick", "/ban", "/unban"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q\n%s", want, out)
		}
	}
}

func TestKickRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/kick "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial, got %q", out)
	}
	if !d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should still be present after denied kick")
	}
}

func TestKickByMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(modHash, Parse("/kick "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "kicked") {
		t.Errorf("expected success, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be gone after kick")
	}
}

func TestBanByAdmin(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(adminHash, Parse("/ban "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "banned") {
		t.Errorf("expected success, got %q", out)
	}
	if !d.Roster.IsBanned(mustBytes(t, userHash)) {
		t.Error("user should be on banlist after ban")
	}
}

func TestNickSelfChange(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/nick alice"))
	if !strings.Contains(out, "alice") {
		t.Errorf("expected nickname-set ack, got %q", out)
	}
	u, _ := d.Roster.Get(userHash)
	if u.Nickname != "alice" {
		t.Errorf("expected nickname=alice, got %q", u.Nickname)
	}
}

func TestNickOthersRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	other := "dddddddddddddddddddddddddddddddd"
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), now)
	_ = d.Roster.SetNickname(other, "bob")

	out := d.Dispatch(userHash, Parse("/nick bob carol"))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected denial, got %q", out)
	}
	u, _ := d.Roster.Get(other)
	if u.Nickname != "bob" {
		t.Errorf("nickname should not have changed, got %q", u.Nickname)
	}
}

func TestNickValidation(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/nick !!!bad"))
	if !strings.Contains(strings.ToLower(out), "1-24") {
		t.Errorf("expected validation error, got %q", out)
	}
	out = d.Dispatch(userHash, Parse("/nick "+strings.Repeat("a", 25)))
	if !strings.Contains(strings.ToLower(out), "1-24") {
		t.Errorf("expected length validation error, got %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/foobar"))
	if !strings.Contains(strings.ToLower(out), "unknown") {
		t.Errorf("expected unknown-command response, got %q", out)
	}
}

func TestListUsers(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)
	_ = d.Roster.SetNickname(userHash, "alice")

	out := d.Dispatch(userHash, Parse("/users"))
	if !strings.Contains(out, "alice") {
		t.Errorf("expected alice in list, got %q", out)
	}
}

func TestListAdminsAndMods(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/admin"))
	if !strings.Contains(out, adminHash[:8]) {
		t.Errorf("expected admin hash in /admin, got %q", out)
	}
	out = d.Dispatch(userHash, Parse("/mods"))
	if !strings.Contains(out, modHash[:8]) {
		t.Errorf("expected mod hash in /mods, got %q", out)
	}
}
