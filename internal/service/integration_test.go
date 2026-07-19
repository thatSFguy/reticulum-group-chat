package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// newTestService builds a real Service via New() against a fresh temp-dir
// config — a full end-to-end wiring (identity, transport, delivery, roster,
// history, outbound queue) with no network interfaces, so New() constructs
// cleanly and nothing dials out. extraServiceTOML is appended inside the
// [service] table for per-test overrides (e.g. `dedup_window = "0"`).
func newTestService(t *testing.T, extraServiceTOML string) *Service {
	t.Helper()
	dir := t.TempDir()
	src := fmt.Sprintf("[service]\ndisplay_name = \"test\"\n"+
		"identity_path = %q\nstate_path = %q\nhistory_path = %q\n%s\n",
		filepath.Join(dir, "identity"),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "history.json"),
		extraServiceTOML)
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// newSender returns a fresh identity and its LXMF delivery destination hash.
func newSender(t *testing.T) (*rns.Identity, []byte) {
	t.Helper()
	id, err := rns.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id, id.DestinationHashFor(lxmf.FullName())
}

// inbound packs a real opportunistic LXMF message from sender to the service
// and parses it back into the *Message the delivery layer would hand to
// onLXMFReceived — so MessageID() is populated exactly as in production.
// Re-feeding the SAME returned *Message models a true redelivery (identical
// message_id); a fresh call with different content yields a distinct id.
func inbound(t *testing.T, svc *Service, senderID *rns.Identity, senderDest []byte, content string) *lxmf.Message {
	t.Helper()
	svcDest := svc.delivery.Hash()
	wire, _, err := lxmf.SignAndPackOpportunistic(senderID, senderDest, svcDest, nil, []byte(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := lxmf.ParseOpportunisticBody(wire, svcDest)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestServiceDropsDuplicateInbound drives the real inbound path end-to-end
// and asserts a redelivered message is forwarded (and recorded) only once,
// while a genuinely distinct message is not suppressed.
func TestServiceDropsDuplicateInbound(t *testing.T) {
	svc := newTestService(t, "") // dedup_window defaults to 1h

	senderID, senderDest := newSender(t)
	// Sender must be a member (members' messages forward; non-members get an
	// invite). A second member is the forward target, so history records the
	// message (Append only fires when at least one recipient is delivered to).
	if _, err := svc.roster.AddOrUpdate(senderDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.roster.AddOrUpdate(bytes.Repeat([]byte{0xBB}, 16), svc.now()); err != nil {
		t.Fatal(err)
	}

	before := svc.history.Len()

	msg := inbound(t, svc, senderID, senderDest, "hello world")
	svc.onLXMFReceived(msg) // first delivery — processed
	svc.onLXMFReceived(msg) // exact redelivery — must be dropped
	if got := svc.history.Len() - before; got != 1 {
		t.Fatalf("after a duplicate, history grew by %d, want 1", got)
	}

	// A genuinely different message (distinct payload → distinct message_id)
	// must still be processed.
	msg2 := inbound(t, svc, senderID, senderDest, "a different message")
	svc.onLXMFReceived(msg2)
	if got := svc.history.Len() - before; got != 2 {
		t.Fatalf("distinct message should be processed; history grew by %d, want 2", got)
	}
}

// TestServiceDedupDisabledForwardsDuplicates confirms dedup_window = 0 turns
// the guard off: the same message delivered twice is processed twice.
func TestServiceDedupDisabledForwardsDuplicates(t *testing.T) {
	svc := newTestService(t, `dedup_window = "0"`)
	if svc.dedup != nil {
		t.Fatal("dedup cache should be nil when dedup_window = 0")
	}

	senderID, senderDest := newSender(t)
	if _, err := svc.roster.AddOrUpdate(senderDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.roster.AddOrUpdate(bytes.Repeat([]byte{0xCC}, 16), svc.now()); err != nil {
		t.Fatal(err)
	}

	before := svc.history.Len()
	msg := inbound(t, svc, senderID, senderDest, "hello")
	svc.onLXMFReceived(msg)
	svc.onLXMFReceived(msg)
	if got := svc.history.Len() - before; got != 2 {
		t.Fatalf("with dedup disabled, both deliveries should process; history grew by %d, want 2", got)
	}
}
