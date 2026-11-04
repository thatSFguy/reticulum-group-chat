package commands

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/groupinfo"
	"github.com/thatSFguy/reticulum-group-chat/internal/roster"
)

// newInfoDispatcher is newDispatcher plus a wired groupinfo store and a
// display name, which /info puts on its first line.
func newInfoDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	dir := t.TempDir()
	r, err := roster.New(roster.NewStore(filepath.Join(dir, "state.json")))
	if err != nil {
		t.Fatal(err)
	}
	info, err := groupinfo.New(filepath.Join(dir, "groupinfo.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Service: config.ServiceConfig{DisplayName: "Bay Mesh"},
		Admins:  []string{adminHash},
		Mods:    []string{modHash},
	}
	return &Dispatcher{Cfg: cfg, Roster: r, Info: info}
}

// TestInfoAnswersNonMembers is the point of the feature: a passer-by who has
// heard our announce and is not in the roster can ask what this is. If this
// ever starts requiring membership the way /users does, the feature is gone.
func TestInfoAnswersNonMembers(t *testing.T) {
	d := newInfoDispatcher(t)
	if err := d.Info.SetInfo("Mesh net for the east bay."); err != nil {
		t.Fatal(err)
	}
	got := d.Dispatch(userHash, Parse("/info"))
	if !strings.Contains(got, "Bay Mesh") {
		t.Errorf("/info omitted the display name: %q", got)
	}
	if !strings.Contains(got, "Mesh net for the east bay.") {
		t.Errorf("/info omitted the description: %q", got)
	}
	if !strings.Contains(got, "/join") {
		t.Errorf("/info to a non-member of an open group should say how to join: %q", got)
	}
}

// TestInfoOnLockedGroupEchoesTheirAddress mirrors what /join tells a stranger
// on a locked group — they need their own hash to hand to an admin, and it
// is already in the envelope they sent us.
func TestInfoOnLockedGroupEchoesTheirAddress(t *testing.T) {
	d := newInfoDispatcher(t)
	d.Cfg.Service.Locked = true
	got := d.Dispatch(userHash, Parse("/info"))
	if !strings.Contains(got, "Invite-only") {
		t.Errorf("/info on a locked group should say so: %q", got)
	}
	if !strings.Contains(got, userHash) {
		t.Errorf("/info on a locked group should echo the caller's address: %q", got)
	}
}

func TestInfoPointsMembersAtPins(t *testing.T) {
	d := newInfoDispatcher(t)
	if _, err := d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := d.Dispatch(userHash, Parse("/info")); strings.Contains(got, "pinned") {
		t.Errorf("/info mentioned pins when there are none: %q", got)
	}
	if err := d.Info.AddPin(groupinfo.Pin{Text: "net at 20:00"}); err != nil {
		t.Fatal(err)
	}
	got := d.Dispatch(userHash, Parse("/info"))
	if !strings.Contains(got, "1 pinned") {
		t.Errorf("/info should point a member at /pins once pins exist: %q", got)
	}
	if strings.Contains(got, "/join") {
		t.Errorf("/info told an existing member to /join: %q", got)
	}
}

func TestSetInfoIsAdminOnly(t *testing.T) {
	d := newInfoDispatcher(t)
	for _, h := range []string{userHash, modHash} {
		if got := d.Dispatch(h, Parse("/setinfo hello")); !strings.Contains(got, "Only admins") {
			t.Errorf("/setinfo as %s = %q, want refusal", h[:8], got)
		}
	}
	if d.Info.Info() != "" {
		t.Errorf("a refused /setinfo still wrote %q", d.Info.Info())
	}
	if got := d.Dispatch(adminHash, Parse("/setinfo hello there")); !strings.Contains(got, "set") {
		t.Errorf("/setinfo as admin = %q", got)
	}
	if d.Info.Info() != "hello there" {
		t.Errorf("stored description = %q, want %q", d.Info.Info(), "hello there")
	}
}

// TestSetInfoPreservesInteriorSpacing is why Parsed carries Rest: rebuilding
// the text from Fields-split Args would silently rewrite the operator's
// description.
func TestSetInfoPreservesInteriorSpacing(t *testing.T) {
	d := newInfoDispatcher(t)
	d.Dispatch(adminHash, Parse("/setinfo Net:  Thursdays   20:00"))
	if got := d.Info.Info(); got != "Net:  Thursdays   20:00" {
		t.Errorf("stored description = %q, spacing was rewritten", got)
	}
}

func TestSetInfoEnforcesTheByteCap(t *testing.T) {
	d := newInfoDispatcher(t)
	long := strings.Repeat("x", groupinfo.MaxInfoBytes+1)
	got := d.Dispatch(adminHash, Parse("/setinfo "+long))
	if !strings.Contains(got, "limit") {
		t.Errorf("over-cap /setinfo = %q, want a refusal naming the limit", got)
	}
	if d.Info.Info() != "" {
		t.Error("an over-cap /setinfo was stored anyway")
	}
}

func TestSetInfoWithNoArgsClears(t *testing.T) {
	d := newInfoDispatcher(t)
	if got := d.Dispatch(adminHash, Parse("/setinfo")); !strings.Contains(got, "Usage") {
		t.Errorf("/setinfo with nothing set = %q, want usage", got)
	}
	d.Dispatch(adminHash, Parse("/setinfo something"))
	if got := d.Dispatch(adminHash, Parse("/setinfo")); !strings.Contains(got, "Cleared") {
		t.Errorf("/setinfo with a description set = %q, want a clear", got)
	}
	if d.Info.Info() != "" {
		t.Errorf("description after clear = %q", d.Info.Info())
	}
}

// TestPinsIsMembersOnly follows the /users precedent — the pin list is
// group-internal content and the reply is O(pins) with a retry budget
// behind it, so it is not a surface for unauthenticated callers. /info is.
func TestPinsIsMembersOnly(t *testing.T) {
	d := newInfoDispatcher(t)
	if err := d.Info.AddPin(groupinfo.Pin{Text: "net at 20:00"}); err != nil {
		t.Fatal(err)
	}
	got := d.Dispatch(userHash, Parse("/pins"))
	if !strings.Contains(got, "Only members") {
		t.Errorf("/pins as a non-member = %q, want refusal", got)
	}
	if strings.Contains(got, "net at 20:00") {
		t.Errorf("/pins leaked pin text to a non-member: %q", got)
	}
	if _, err := d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := d.Dispatch(userHash, Parse("/pins")); !strings.Contains(got, "net at 20:00") {
		t.Errorf("/pins as a member = %q", got)
	}
}

func TestPinIsModOnly(t *testing.T) {
	d := newInfoDispatcher(t)
	if _, err := d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := d.Dispatch(userHash, Parse("/pin sneaky")); !strings.Contains(got, "Only mods") {
		t.Errorf("/pin as a regular member = %q, want refusal", got)
	}
	if d.Info.PinCount() != 0 {
		t.Error("a refused /pin was stored anyway")
	}
	if got := d.Dispatch(modHash, Parse("/pin Net Thursdays 20:00")); !strings.Contains(got, "#1") {
		t.Errorf("/pin as a mod = %q", got)
	}
	pins := d.Info.Pins()
	if len(pins) != 1 || pins[0].Text != "Net Thursdays 20:00" {
		t.Fatalf("stored pins = %+v", pins)
	}
	if pins[0].By != modHash {
		t.Errorf("pin attributed to %q, want %q", pins[0].By, modHash)
	}
}

// TestPinCollapsesLineBreaks keeps the numbered list readable: a newline
// inside a pin would make line 3 of the reply stop being pin 3, and /unpin
// takes the number the mod read off that list.
func TestPinCollapsesLineBreaks(t *testing.T) {
	d := newInfoDispatcher(t)
	d.Dispatch(modHash, Parse("/pin first line\nsecond line"))
	pins := d.Info.Pins()
	if len(pins) != 1 {
		t.Fatalf("pins = %+v", pins)
	}
	if pins[0].Text != "first line second line" {
		t.Errorf("stored pin = %q, want line breaks collapsed", pins[0].Text)
	}
}

func TestPinEnforcesTheByteCap(t *testing.T) {
	d := newInfoDispatcher(t)
	got := d.Dispatch(modHash, Parse("/pin "+strings.Repeat("x", groupinfo.MaxPinBytes+1)))
	if !strings.Contains(got, "limit") {
		t.Errorf("over-cap /pin = %q, want a refusal naming the limit", got)
	}
	if d.Info.PinCount() != 0 {
		t.Error("an over-cap /pin was stored anyway")
	}
}

func TestPinRefusesWhenFull(t *testing.T) {
	d := newInfoDispatcher(t)
	for i := 0; i < groupinfo.MaxPins; i++ {
		d.Dispatch(modHash, Parse("/pin something"))
	}
	if got := d.Dispatch(modHash, Parse("/pin one more")); !strings.Contains(got, "full") {
		t.Errorf("/pin past the cap = %q, want a full-list refusal", got)
	}
	if d.Info.PinCount() != groupinfo.MaxPins {
		t.Errorf("PinCount = %d, want %d", d.Info.PinCount(), groupinfo.MaxPins)
	}
}

func TestUnpinUsesTheDisplayedNumber(t *testing.T) {
	d := newInfoDispatcher(t)
	for _, txt := range []string{"first", "second", "third"} {
		d.Dispatch(modHash, Parse("/pin "+txt))
	}
	if got := d.Dispatch(userHash, Parse("/unpin 1")); !strings.Contains(got, "Only mods") {
		t.Errorf("/unpin as a non-mod = %q, want refusal", got)
	}
	if got := d.Dispatch(modHash, Parse("/unpin 2")); !strings.Contains(got, "second") {
		t.Errorf("/unpin 2 = %q, want the removed text echoed", got)
	}
	pins := d.Info.Pins()
	if len(pins) != 2 || pins[0].Text != "first" || pins[1].Text != "third" {
		t.Errorf("pins after /unpin 2 = %+v", pins)
	}
	if got := d.Dispatch(modHash, Parse("/unpin 9")); !strings.Contains(got, "1-2") {
		t.Errorf("/unpin out of range = %q, want the valid range", got)
	}
	if got := d.Dispatch(modHash, Parse("/unpin two")); !strings.Contains(got, "number") {
		t.Errorf("/unpin with a non-number = %q", got)
	}
}

// TestInfoCommandsSurviveAnUnwiredStore covers the unit-test wiring in this
// package (and any future caller that builds a Dispatcher by hand): a nil
// store must report itself, not panic on the inbox goroutine.
func TestInfoCommandsSurviveAnUnwiredStore(t *testing.T) {
	d := newDispatcher(t) // no Info
	for _, cmd := range []string{"/info", "/pins", "/setinfo x", "/pin x", "/unpin 1"} {
		sender := adminHash
		if got := d.Dispatch(sender, Parse(cmd)); got == "" {
			t.Errorf("%s with no store returned an empty reply", cmd)
		}
	}
}

// infoRoom is the largest description /setinfo accepts under the current
// config, found the way an admin would: by asking for more until refused.
func infoRoom(t *testing.T, d *Dispatcher) int {
	t.Helper()
	for n := groupinfo.MaxInfoBytes; n > 0; n-- {
		if d.InfoOverflow(strings.Repeat("x", n)) <= 0 {
			return n
		}
	}
	return 0
}

// assertOnePacket checks the reply against the library's own size rule, so
// the test fails if /info and the send path ever disagree about "fits".
func assertOnePacket(t *testing.T, label, reply string) {
	t.Helper()
	if err := lxmf.CheckOpportunisticSize(nil, []byte(reply), nil); err != nil {
		t.Errorf("%s /info reply (%d bytes) does not fit one packet: %v", label, len(reply), err)
	}
}

// TestSetInfoKeepsInfoToOnePacket reproduces the case that motivated sizing
// against the wire instead of a constant: a 32-byte display name (a real
// operator's) plus a 256-byte description overflowed even a single Link
// packet. /setinfo must refuse that, accept exactly what fits, and every
// reply shape — open-group stranger, locked-group stranger, member — must
// then pass the same check Delivery.Send makes.
func TestSetInfoKeepsInfoToOnePacket(t *testing.T) {
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprintf("locked=%v", locked), func(t *testing.T) {
			d := newInfoDispatcher(t)
			d.Cfg.Service.DisplayName = "MichMesh Group chat - send /join"
			d.Cfg.Service.Locked = locked

			got := d.Dispatch(adminHash, Parse("/setinfo "+strings.Repeat("x", groupinfo.MaxInfoBytes)))
			if !strings.Contains(got, "one packet") || d.Info.Info() != "" {
				t.Fatalf("256-byte description under a 32-byte name was not refused: %q", got)
			}

			room := infoRoom(t, d)
			if room <= 0 || room >= groupinfo.MaxInfoBytes {
				t.Fatalf("room = %d, want a budget tighter than the %d-byte store cap", room, groupinfo.MaxInfoBytes)
			}
			if want := fmt.Sprintf("room for %d", room); !strings.Contains(got, want) {
				t.Errorf("refusal should tell the admin the real room (%q): %q", want, got)
			}

			got = d.Dispatch(adminHash, Parse("/setinfo "+strings.Repeat("y", room+1)))
			if d.Info.Info() != "" {
				t.Fatalf("description one byte over the room was stored: %q", got)
			}
			got = d.Dispatch(adminHash, Parse("/setinfo "+strings.Repeat("y", room)))
			if d.Info.Info() == "" {
				t.Fatalf("description of exactly the room was refused: %q", got)
			}

			assertOnePacket(t, "stranger", d.Dispatch(userHash, Parse("/info")))
			for i := 0; i < groupinfo.MaxPins; i++ {
				d.Dispatch(modHash, Parse("/pin p"))
			}
			if d.Info.PinCount() != groupinfo.MaxPins {
				t.Fatalf("pin list has %d, want a full %d for the member case", d.Info.PinCount(), groupinfo.MaxPins)
			}
			if _, err := d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now()); err != nil {
				t.Fatal(err)
			}
			assertOnePacket(t, "member", d.Dispatch(userHash, Parse("/info")))
		})
	}
}

// TestSetInfoWithNoRoomLeft: a display name that already fills the packet
// leaves no room for any description, and /setinfo should say the display
// name is the thing to change rather than quoting a nonsense negative room.
func TestSetInfoWithNoRoomLeft(t *testing.T) {
	d := newInfoDispatcher(t)
	d.Cfg.Service.DisplayName = strings.Repeat("N", 300)
	got := d.Dispatch(adminHash, Parse("/setinfo hello"))
	if !strings.Contains(got, "display_name") || d.Info.Info() != "" {
		t.Errorf("/setinfo with an overfull display name = %q, want a pointer at display_name", got)
	}
}
