package commands

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/version"
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

// helpTextMsgpackPayload mirrors the wire format SignAndPackOpportunistic
// produces — float64 timestamp + empty title + content + empty fixmap —
// so the test can assert size without taking a circular import on lxmf.
func helpTextMsgpackPayload(t *testing.T, c *Caller) []byte {
	t.Helper()
	payload, err := msgpack.Marshal([]any{
		0.0,
		[]byte{},
		[]byte(helpText(c)),
		map[any]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestHelpTextFitsOpportunisticPacket guards against ANY caller state
// producing a help text that exceeds the single-packet opportunistic
// LXMF cap (upstream LXMessage.ENCRYPTED_PACKET_MAX_CONTENT = 295). All
// four states need to fit because /? is dispatched without knowing in
// advance which the caller is.
func TestHelpTextFitsOpportunisticPacket(t *testing.T) {
	const maxOpportunisticPayload = 295
	cases := []struct {
		name string
		c    *Caller
	}{
		{"non-member, regular user", &Caller{Member: false, Role: RoleUser}},
		{"member, regular user", &Caller{Member: true, Role: RoleUser}},
		{"non-member, mod", &Caller{Member: false, Role: RoleMod}},
		{"member, admin", &Caller{Member: true, Role: RoleAdmin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := helpTextMsgpackPayload(t, tc.c)
			if len(payload) > maxOpportunisticPayload {
				t.Errorf("helpText for %s = %d bytes msgpack, must be <= %d (single-packet cap)\n--- text:\n%s",
					tc.name, len(payload), maxOpportunisticPayload, helpText(tc.c))
			}
		})
	}
}

func TestHelpForNonMemberShowsJoinNotLeave(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/?"))
	for _, want := range []string{"/?", "/users", "/join"} {
		if !strings.Contains(out, want) {
			t.Errorf("non-member help missing %q\n%s", want, out)
		}
	}
	for _, missing := range []string{"/leave", "/pause", "/resume", "/kick", "/ban"} {
		if strings.Contains(out, missing) {
			t.Errorf("non-member help should not show %q\n%s", missing, out)
		}
	}
}

func TestHelpForMemberShowsLeavePauseNotKickBan(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/?"))
	for _, want := range []string{"/leave", "/pause", "/resume", "/nick"} {
		if !strings.Contains(out, want) {
			t.Errorf("member help missing %q\n%s", want, out)
		}
	}
	for _, missing := range []string{"/join", "/kick", "/ban", "/unban", "/announce"} {
		if strings.Contains(out, missing) {
			t.Errorf("member help should not show %q\n%s", missing, out)
		}
	}
}

func TestHelpForModShowsAllCommands(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, modHash), time.Now())
	out := d.Dispatch(modHash, Parse("/?"))
	for _, want := range []string{"/users", "/mods", "/admin", "/nick", "/kick", "/ban", "/unban", "/announce", "/path", "/leave", "/pause", "/resume"} {
		if !strings.Contains(out, want) {
			t.Errorf("mod help missing %q\n%s", want, out)
		}
	}
}

func TestJoinAddsToRosterAndCallsOnJoin(t *testing.T) {
	d := newDispatcher(t)
	var joined string
	d.OnJoin = func(h string) { joined = h }

	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "joined") {
		t.Errorf("expected join confirmation, got %q", out)
	}
	if !d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be in roster after /join")
	}
	if joined != userHash {
		t.Errorf("OnJoin called with %q, want %q", joined, userHash)
	}
}

func TestJoinIdempotent(t *testing.T) {
	d := newDispatcher(t)
	_ = d.Dispatch(userHash, Parse("/join"))
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "already") {
		t.Errorf("second /join should be idempotent, got %q", out)
	}
}

func TestJoinRespectsMaxMembers(t *testing.T) {
	d := newDispatcher(t)
	d.Cfg.Service.MaxMembers = 2

	// Pre-fill 2 members.
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, modHash), time.Now())
	other := "1111111111111111111111111111111111111111111111111111111111111111"[:32]
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), time.Now())

	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "full") {
		t.Errorf("expected chat-full denial, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should NOT have been added when chat is full")
	}
}

func TestPathRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/path some-nick"))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("non-mod /path should be denied, got %q", out)
	}
}

func TestPathRejectsBadArgCount(t *testing.T) {
	d := newDispatcher(t)
	d.PathLookup = func(string) PathInfo { return PathInfo{} }
	out := d.Dispatch(modHash, Parse("/path"))
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Errorf("/path with no args should show usage, got %q", out)
	}
}

func TestPathReportsUnwiredLookup(t *testing.T) {
	d := newDispatcher(t)
	// PathLookup deliberately nil to simulate forgotten wiring.
	out := d.Dispatch(adminHash, Parse("/path "+userHash))
	if !strings.Contains(strings.ToLower(out), "not wired") {
		t.Errorf("missing PathLookup should report server bug, got %q", out)
	}
}

func TestPathReportsUnknownDestination(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	d.PathLookup = func(string) PathInfo { return PathInfo{Known: false} }
	out := d.Dispatch(modHash, Parse("/path "+userHash))
	if !strings.Contains(out, "no announce cached") {
		t.Errorf("unknown dest should say so, got %q", out)
	}
}

func TestPathReportsKnownDirectWithLink(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetNickname(userHash, "alice")
	d.PathLookup = func(hex string) PathInfo {
		if hex != userHash {
			t.Errorf("PathLookup called with %q, want %q", hex, userHash)
		}
		return PathInfo{
			Known:      true,
			LastSeen:   time.Now().Add(-3 * time.Minute),
			Hops:       2,
			LinkActive: true,
		}
	}
	out := d.Dispatch(modHash, Parse("/path alice"))
	for _, want := range []string{"alice", userHash[:8], "hops: 2", "direct", "link: active"} {
		if !strings.Contains(out, want) {
			t.Errorf("/path output missing %q\n%s", want, out)
		}
	}
}

func TestPathReportsMultihop(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	transportID := strings.Repeat("ab", 16)
	d.PathLookup = func(string) PathInfo {
		return PathInfo{
			Known:      true,
			LastSeen:   time.Now(),
			Hops:       4,
			NextHopHex: transportID,
		}
	}
	out := d.Dispatch(modHash, Parse("/path "+userHash))
	if !strings.Contains(out, "multi-hop") {
		t.Errorf("multi-hop /path should mark it as such, got %q", out)
	}
	if !strings.Contains(out, transportID[:8]) {
		t.Errorf("multi-hop /path should show next-hop short hash %q, got %q", transportID[:8], out)
	}
}

func TestJoinUnlimitedWhenMaxMembersZero(t *testing.T) {
	d := newDispatcher(t)
	d.Cfg.Service.MaxMembers = 0
	for i := 0; i < 5; i++ {
		hash := strings.Repeat(string(rune('0'+byte(i))), 32)
		_, _ = d.Roster.AddOrUpdate(mustBytes(t, hash), time.Now())
	}
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "joined") {
		t.Errorf("max_members=0 should be unlimited, got %q", out)
	}
}

func TestJoinRejectsBanned(t *testing.T) {
	d := newDispatcher(t)
	_ = d.Roster.Ban(userHash)
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "banned") {
		t.Errorf("/join should refuse banned user, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("/join shouldn't have added a banned user to the roster")
	}
}

func TestLeaveRemovesFromRoster(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/leave"))
	if !strings.Contains(strings.ToLower(out), "left") {
		t.Errorf("expected leave ack, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be gone from roster after /leave")
	}
}

func TestLeaveByNonMember(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/leave"))
	if !strings.Contains(strings.ToLower(out), "not in the chat") {
		t.Errorf("expected non-member denial, got %q", out)
	}
}

func TestPauseSetsFlag(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())

	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "paused") {
		t.Errorf("expected pause ack, got %q", out)
	}
	if !d.Roster.IsPaused(userHash) {
		t.Error("user should be marked paused")
	}
}

func TestPauseTwiceIsIdempotent(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())

	_ = d.Dispatch(userHash, Parse("/pause"))
	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "already paused") {
		t.Errorf("expected already-paused ack, got %q", out)
	}
}

func TestPauseRequiresMembership(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "not in the chat") {
		t.Errorf("expected non-member denial, got %q", out)
	}
}

func TestResumeClearsFlag(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetPaused(userHash, true)

	out := d.Dispatch(userHash, Parse("/resume"))
	if !strings.Contains(strings.ToLower(out), "resumed") {
		t.Errorf("expected resume ack, got %q", out)
	}
	if d.Roster.IsPaused(userHash) {
		t.Error("user should no longer be paused")
	}
}

func TestResumeWithoutPause(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/resume"))
	if !strings.Contains(strings.ToLower(out), "not paused") {
		t.Errorf("expected not-paused message, got %q", out)
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

func TestNickSelfRequiresMembership(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/nick alice"))
	if !strings.Contains(strings.ToLower(out), "join first") {
		t.Errorf("expected join-first message for non-member /nick, got %q", out)
	}
}

// TestNickRejectsSpacesForRegularUser confirms that a non-mod typing
// `/nick FIRST LAST` gets a clear "no spaces" error rather than the old
// misleading "only mods or admins can change someone else's nickname"
// reply (the parser splits on whitespace, so the call landed in the
// 2-arg mod-only branch). Reported by an operator: users couldn't tell
// why their multi-word nick wasn't accepted.
func TestNickRejectsSpacesForRegularUser(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	other := "dddddddddddddddddddddddddddddddd"
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), now)
	_ = d.Roster.SetNickname(other, "bob")

	out := d.Dispatch(userHash, Parse("/nick bob carol"))
	if !strings.Contains(strings.ToLower(out), "spaces") {
		t.Errorf("expected no-spaces guidance, got %q", out)
	}
	if strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("should not show the old mod-only error to regular users, got %q", out)
	}
	u, _ := d.Roster.Get(other)
	if u.Nickname != "bob" {
		t.Errorf("nickname should not have changed, got %q", u.Nickname)
	}

	// Three-word attempt should also yield the spaces guidance.
	out = d.Dispatch(userHash, Parse("/nick first middle last"))
	if !strings.Contains(strings.ToLower(out), "spaces") {
		t.Errorf("expected no-spaces guidance for 3-word /nick, got %q", out)
	}
}

// TestNickOthersByMod still works correctly when called by a mod.
func TestNickOthersByMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, modHash), now)
	other := "dddddddddddddddddddddddddddddddd"
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), now)
	_ = d.Roster.SetNickname(other, "bob")

	out := d.Dispatch(modHash, Parse("/nick bob carol"))
	if !strings.Contains(strings.ToLower(out), "carol") {
		t.Errorf("mod should be able to rename other; got %q", out)
	}
	u, _ := d.Roster.Get(other)
	if u.Nickname != "carol" {
		t.Errorf("expected nickname=carol, got %q", u.Nickname)
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

// TestUnknownCommandScrubsControlBytes ensures that a sender who puts an
// ESC/CSI sequence in their command name doesn't get those bytes echoed
// back into the reply (which would let them inject ANSI escapes into
// their own terminal — minor — and into the operator log line that
// records the reply, which is what we actually care about).
func TestUnknownCommandScrubsControlBytes(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/\x1b[31mevil\x1b[0m"))
	for _, c := range []byte(out) {
		if c == 0x1B {
			t.Errorf("ESC byte leaked into reply: %q", out)
		}
	}
	if !strings.Contains(out, "?") {
		t.Errorf("expected control bytes replaced with '?', got %q", out)
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

// TestListUsersTruncatesWhenOverBudget reproduces the bug where /users
// stopped working in production: with enough roster members, the reply
// payload exceeded lxmf.MaxOpportunisticPayload (295 bytes) and Send
// returned ErrPayloadTooLarge silently. Now the dispatcher truncates
// the visible reply to fit the budget and logs the full list to the
// operator log via OverflowLog.
func TestListUsersTruncatesWhenOverBudget(t *testing.T) {
	d := newDispatcher(t)
	d.MaxReplyContentBytes = 200 // forces truncation with the names below
	var overflow string
	d.OverflowLog = func(format string, args ...any) {
		overflow = fmt.Sprintf(format, args...)
	}

	for i := 0; i < 30; i++ {
		hash := strings.Repeat(string(rune('a'+byte(i%6))), 32)
		// avoid hash collisions across the loop by varying char
		hash = fmt.Sprintf("%02x%s", i, hash[:30])
		_, _ = d.Roster.AddOrUpdate(mustBytes(t, hash), time.Now())
		_ = d.Roster.SetNickname(hash, fmt.Sprintf("user%02d", i))
	}

	out := d.Dispatch(userHash, Parse("/users"))
	if len(out) > d.MaxReplyContentBytes {
		t.Errorf("truncated /users reply is %d bytes, must be <= %d\n%s",
			len(out), d.MaxReplyContentBytes, out)
	}
	if !strings.Contains(out, "...and") || !strings.Contains(out, "more") {
		t.Errorf("expected truncation footer, got %q", out)
	}
	if overflow == "" {
		t.Errorf("expected OverflowLog to be invoked")
	}
	if !strings.Contains(overflow, "/users reply truncated") {
		t.Errorf("OverflowLog should mention /users reply truncated, got %q", overflow)
	}
}

// TestListUsersUnlimitedByDefault confirms that with the dispatcher in
// its default config (MaxReplyContentBytes == 0), a roster of any size
// produces a complete /users reply with no truncation footer. This is
// the post-v1.1.0 behavior: the wire-size cap was lifted because
// Delivery.Send auto-routes oversize replies through a Reticulum Link.
//
// Production wiring in service.New leaves MaxReplyContentBytes at 0
// for exactly this reason — the truncation helper is still available
// for callers that want a per-command cap, but /users in production
// returns the full list.
func TestListUsersUnlimitedByDefault(t *testing.T) {
	d := newDispatcher(t)
	// Don't set MaxReplyContentBytes — leave at zero-value 0.
	overflowCalled := false
	d.OverflowLog = func(format string, args ...any) { overflowCalled = true }

	for i := 0; i < 100; i++ {
		hash := fmt.Sprintf("%02x%s", i, strings.Repeat("a", 30))
		_, _ = d.Roster.AddOrUpdate(mustBytes(t, hash), time.Now())
		_ = d.Roster.SetNickname(hash, fmt.Sprintf("user%03d", i))
	}

	out := d.Dispatch(userHash, Parse("/users"))
	if strings.Contains(out, "...and") {
		t.Errorf("expected no truncation footer with default config, got %q", out)
	}
	if overflowCalled {
		t.Errorf("OverflowLog should not fire when MaxReplyContentBytes is 0")
	}
	// Sanity: the reply must contain the LAST user we added (would be
	// missing if a phantom truncation snuck in).
	if !strings.Contains(out, "user099") {
		t.Errorf("expected last roster entry user099 in /users reply (length=%d)", len(out))
	}
	// And every roster entry should be present.
	for i := 0; i < 100; i++ {
		want := fmt.Sprintf("user%03d", i)
		if !strings.Contains(out, want) {
			t.Errorf("missing %s from /users reply", want)
			break
		}
	}
}

// TestListUsersFitsWithinBudget confirms that when the roster is small
// enough, no truncation footer appears and OverflowLog is not invoked.
func TestListUsersFitsWithinBudget(t *testing.T) {
	d := newDispatcher(t)
	d.MaxReplyContentBytes = 280
	overflowCalled := false
	d.OverflowLog = func(format string, args ...any) { overflowCalled = true }

	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetNickname(userHash, "alice")

	out := d.Dispatch(userHash, Parse("/users"))
	if strings.Contains(out, "...and") {
		t.Errorf("did not expect truncation footer for small roster, got %q", out)
	}
	if overflowCalled {
		t.Errorf("OverflowLog should not have been invoked")
	}
}

func TestListUsersMarksPaused(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetNickname(userHash, "alice")
	_ = d.Roster.SetPaused(userHash, true)

	out := d.Dispatch(userHash, Parse("/users"))
	if !strings.Contains(out, "[paused]") {
		t.Errorf("expected paused users to be marked, got %q", out)
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

func TestAnnounceRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/announce"))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial, got %q", out)
	}
}

func TestAnnounceCallsHook(t *testing.T) {
	d := newDispatcher(t)
	called := false
	d.Announce = func() error {
		called = true
		return nil
	}
	out := d.Dispatch(modHash, Parse("/announce"))
	if !strings.Contains(strings.ToLower(out), "announced") {
		t.Errorf("expected success ack, got %q", out)
	}
	if !called {
		t.Error("Announce hook was not called")
	}
}

// TestAboutCommandReturnsVersionAndRepo pins the /about reply shape:
// the running Version constant and the canonical RepoURL must both
// appear so users running an unfamiliar deployment can identify it
// and find the source. /version is a documented alias.
func TestAboutCommandReturnsVersionAndRepo(t *testing.T) {
	d := newDispatcher(t)
	caller := "0011223344556677" + "8899aabbccddeeff"

	for _, alias := range []string{"/about", "/version"} {
		out := d.Dispatch(caller, Parse(alias))
		if !strings.Contains(out, version.Version) {
			t.Errorf("%s reply missing Version %q: %q", alias, version.Version, out)
		}
		if !strings.Contains(out, version.RepoURL) {
			t.Errorf("%s reply missing RepoURL %q: %q", alias, version.RepoURL, out)
		}
	}
}

// TestAboutTextFitsOpportunisticPacket pins that /about always ships
// in a single opportunistic packet — like /? it's a fire-and-forget
// reply with no link-delivery fallback path on small clients.
func TestAboutTextFitsOpportunisticPacket(t *testing.T) {
	const maxOpportunisticPayload = 295
	payload := aboutText()
	if len(payload) > maxOpportunisticPayload {
		t.Errorf("aboutText = %d bytes, must be <= %d:\n%s",
			len(payload), maxOpportunisticPayload, payload)
	}
}
