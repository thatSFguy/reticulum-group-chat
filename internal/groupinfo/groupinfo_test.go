package groupinfo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "groupinfo.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

// TestMissingFileIsNotAnError covers the state every group starts in: no
// file on disk, nothing set, and New must not create one until a write.
func TestMissingFileIsNotAnError(t *testing.T) {
	s, path := newStore(t)
	if got := s.Info(); got != "" {
		t.Errorf("Info() on a fresh store = %q, want empty", got)
	}
	if got := s.PinCount(); got != 0 {
		t.Errorf("PinCount() on a fresh store = %d, want 0", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("New created %s before any write (err=%v)", path, err)
	}
}

func TestInfoAndPinsRoundTrip(t *testing.T) {
	s, path := newStore(t)
	if err := s.SetInfo("Weekly net, Thursdays 20:00 local."); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 19, 1, 34, 0, 0, time.UTC)
	if err := s.AddPin(Pin{At: at, By: "00112233445566778899aabbccddeeff", ByNick: "kim", Text: "Repeater is on 2m"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Info(); got != "Weekly net, Thursdays 20:00 local." {
		t.Errorf("info after reopen = %q", got)
	}
	pins := reopened.Pins()
	if len(pins) != 1 {
		t.Fatalf("pins after reopen = %d, want 1", len(pins))
	}
	if pins[0].Text != "Repeater is on 2m" || pins[0].ByNick != "kim" {
		t.Errorf("pin after reopen = %+v", pins[0])
	}
	if !pins[0].At.Equal(at) {
		t.Errorf("pin time after reopen = %v, want %v", pins[0].At, at)
	}
}

// TestPinsReturnsACopy guards the store against a caller mutating the pin
// list under it — Pins() feeds Render on the join path, which runs in its
// own goroutine while commands may be adding pins.
func TestPinsReturnsACopy(t *testing.T) {
	s, _ := newStore(t)
	if err := s.AddPin(Pin{Text: "original"}); err != nil {
		t.Fatal(err)
	}
	got := s.Pins()
	got[0].Text = "mutated"
	if s.Pins()[0].Text != "original" {
		t.Error("mutating the slice returned by Pins() changed the store")
	}
}

func TestAddPinRefusesWhenFull(t *testing.T) {
	s, _ := newStore(t)
	for i := 0; i < MaxPins; i++ {
		if err := s.AddPin(Pin{Text: "pin"}); err != nil {
			t.Fatalf("AddPin %d: %v", i, err)
		}
	}
	err := s.AddPin(Pin{Text: "one too many"})
	if !errors.Is(err, ErrPinsFull) {
		t.Fatalf("AddPin past MaxPins = %v, want ErrPinsFull", err)
	}
	if got := s.PinCount(); got != MaxPins {
		t.Errorf("PinCount after a refused add = %d, want %d", got, MaxPins)
	}
	// The refusal must not have evicted the oldest pin to make room —
	// dropping someone else's pin silently is exactly what ErrPinsFull
	// exists to avoid.
	if s.Pins()[0].Text != "pin" {
		t.Error("a full-list refusal evicted the oldest pin")
	}
}

// TestRemovePinIsOneBased pins the index convention: /pins prints 1..N and
// /unpin takes the number the mod just read, so an off-by-one here unpins
// the wrong message.
func TestRemovePinIsOneBased(t *testing.T) {
	s, _ := newStore(t)
	for _, txt := range []string{"first", "second", "third"} {
		if err := s.AddPin(Pin{Text: txt}); err != nil {
			t.Fatal(err)
		}
	}
	removed, ok, err := s.RemovePin(2)
	if err != nil || !ok {
		t.Fatalf("RemovePin(2) = %v, %v, %v", removed, ok, err)
	}
	if removed.Text != "second" {
		t.Errorf("RemovePin(2) removed %q, want %q", removed.Text, "second")
	}
	pins := s.Pins()
	if len(pins) != 2 || pins[0].Text != "first" || pins[1].Text != "third" {
		t.Errorf("after RemovePin(2), pins = %+v", pins)
	}

	for _, n := range []int{0, -1, 3, 99} {
		if _, ok, err := s.RemovePin(n); ok || err != nil {
			t.Errorf("RemovePin(%d) = ok %v, err %v; want out-of-range", n, ok, err)
		}
	}
}

// TestLoadReappliesLimits covers the hand-edited / hand-seeded file. The
// JSON is operator-editable by design, so limits are enforced on the way in
// as well as on the way out.
func TestLoadReappliesLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groupinfo.json")
	var b strings.Builder
	b.WriteString(`{"info":"` + strings.Repeat("x", MaxInfoBytes*2) + `","pins":[`)
	for i := 0; i < MaxPins+5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"text":"` + strings.Repeat("y", MaxPinBytes*2) + `"}`)
	}
	b.WriteString(`]}`)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.Info()); got != MaxInfoBytes {
		t.Errorf("loaded info = %d bytes, want truncated to %d", got, MaxInfoBytes)
	}
	pins := s.Pins()
	if len(pins) != MaxPins {
		t.Fatalf("loaded pins = %d, want trimmed to %d", len(pins), MaxPins)
	}
	if got := len(pins[0].Text); got != MaxPinBytes {
		t.Errorf("loaded pin text = %d bytes, want truncated to %d", got, MaxPinBytes)
	}
}

func TestTruncateTextKeepsRunesWhole(t *testing.T) {
	// "é" is two bytes; cutting at 3 must drop it rather than leave a
	// dangling lead byte for the recipient's client to render as U+FFFD.
	if got := TruncateText("aaéb", 3); got != "aa" {
		t.Errorf("TruncateText(\"aaéb\", 3) = %q, want %q", got, "aa")
	}
	if got := TruncateText("abcd", 10); got != "abcd" {
		t.Errorf("TruncateText under the limit changed the string: %q", got)
	}
	if got := TruncateText("abcd", 0); got != "abcd" {
		t.Errorf("TruncateText with max 0 should be a no-op, got %q", got)
	}
}

func TestRenderNumbersAndScrubs(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	pins := []Pin{
		{At: now.Add(-3 * time.Hour), ByNick: "kim", Text: "net at 20:00"},
		{At: now.Add(-50 * time.Hour), By: "00112233445566778899aabbccddeeff", Text: "read the \x1b[31mrules"},
	}
	got := Render(pins, now)
	want := "Pinned (2):\n1. [kim, 3h] net at 20:00\n2. [00112233, 2d] read the ?[31mrules"
	if got != want {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want)
	}
	if Render(nil, now) != "" {
		t.Error("Render(nil) must be empty so callers can decide what to say instead")
	}
}
