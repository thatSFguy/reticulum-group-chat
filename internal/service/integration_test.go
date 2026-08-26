package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
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

// inboundWithFields is inbound() with an LXMF field map, for exercising
// the attachment policy on a real parsed message.
func inboundWithFields(t *testing.T, svc *Service, senderID *rns.Identity, senderDest []byte, content string, fields map[any]any) *lxmf.Message {
	t.Helper()
	svcDest := svc.delivery.Hash()
	wire, _, err := lxmf.SignAndPackOpportunistic(senderID, senderDest, svcDest, nil, []byte(content), fields)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := lxmf.ParseOpportunisticBody(wire, svcDest)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// queuedTo returns the bodies of everything currently queued for recipient.
func queuedTo(q *OutboundQueue, recipient []byte) []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []string
	for _, m := range q.pending {
		if bytes.Equal(m.Recipient, recipient) {
			out = append(out, string(m.Body))
		}
	}
	return out
}

// TestAudioOnlyMessageTellsSenderItWasRefused drives the real inbound path
// with a voice clip (FIELD_AUDIO 7, absent from the default allowlist) and
// no text. Before, that combination reassembled perfectly and then vanished:
// nothing forwarded, nothing logged to the sender, no signal anywhere.
func TestAudioOnlyMessageTellsSenderItWasRefused(t *testing.T) {
	svc := newTestService(t, "")

	senderID, senderDest := newSender(t)
	if _, err := svc.roster.AddOrUpdate(senderDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{0xBB}, 16)
	if _, err := svc.roster.AddOrUpdate(other, svc.now()); err != nil {
		t.Fatal(err)
	}

	beforeHistory := svc.history.Len()
	svc.onLXMFReceived(inboundWithFields(t, svc, senderID, senderDest, "", map[any]any{7: []byte("opus-bytes")}))

	// The sender is told why, in plain language naming the kind.
	replies := queuedTo(svc.outbound, senderDest)
	if len(replies) != 1 {
		t.Fatalf("queued %d replies to the sender, want 1: %v", len(replies), replies)
	}
	if !strings.Contains(replies[0], "audio") {
		t.Errorf("reply should name the refused kind, got %q", replies[0])
	}
	if !strings.Contains(replies[0], "Nothing was sent") {
		t.Errorf("audio-only message sends nothing; reply should say so, got %q", replies[0])
	}

	// ...and the group is untouched: no fan-out, no history entry.
	if got := queuedTo(svc.outbound, other); len(got) != 0 {
		t.Errorf("refused attachment must not fan out, got %v", got)
	}
	if got := svc.history.Len() - beforeHistory; got != 0 {
		t.Errorf("history grew by %d, want 0", got)
	}
}

// TestTextWithRefusedAudioStillForwardsTheText asserts the notice does not
// swallow the rest of the message: text rides on, the clip does not.
func TestTextWithRefusedAudioStillForwardsTheText(t *testing.T) {
	svc := newTestService(t, "")

	senderID, senderDest := newSender(t)
	if _, err := svc.roster.AddOrUpdate(senderDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{0xCC}, 16)
	if _, err := svc.roster.AddOrUpdate(other, svc.now()); err != nil {
		t.Fatal(err)
	}

	svc.onLXMFReceived(inboundWithFields(t, svc, senderID, senderDest, "listen to this", map[any]any{7: []byte("opus")}))

	replies := queuedTo(svc.outbound, senderDest)
	if len(replies) != 1 || !strings.Contains(replies[0], "The rest of your message was sent") {
		t.Fatalf("sender should be told the text still went; got %v", replies)
	}
	fanout := queuedTo(svc.outbound, other)
	if len(fanout) != 1 || !strings.Contains(fanout[0], "listen to this") {
		t.Fatalf("text must still reach the group, got %v", fanout)
	}
}

// knownPeerWithStampCost registers a peer in the transport whose announce
// app_data declares the given §4.3 stamp_cost, and returns its dest hash.
func knownPeerWithStampCost(t *testing.T, svc *Service, cost int) []byte {
	t.Helper()
	id, dest := newSender(t)
	appData, err := rns.EncodeLXMFAppData([]byte("peer"), &cost)
	if err != nil {
		t.Fatal(err)
	}
	svc.transport.Restore(&rns.KnownIdentity{
		DestHash:  dest,
		PublicKey: id.PublicKey(),
		AppData:   appData,
	})
	if svc.transport.Recall(dest) == nil {
		t.Fatalf("peer with cost %d was not restored into the transport", cost)
	}
	return dest
}

// TestWillGrindStampGatesOnlyRealGrinds checks which sends take a
// stamp-grind slot. Taking one unnecessarily would throttle sends that
// cost nothing, which is the opposite of the semaphore's purpose.
func TestWillGrindStampGatesOnlyRealGrinds(t *testing.T) {
	svc := newTestService(t, "")
	ds, ok := svc.outbound.sender.(*deliverySender)
	if !ok {
		t.Fatalf("outbound sender is %T, want *deliverySender", svc.outbound.sender)
	}
	if svc.delivery.MaxStampCost != 16 {
		t.Fatalf("MaxStampCost = %d, want 16", svc.delivery.MaxStampCost)
	}

	// cost 0 — 92% of the real network. Must never take a slot.
	if ds.willGrindStamp(knownPeerWithStampCost(t, svc, 0)) {
		t.Error("cost 0 must not take a grind slot")
	}
	// cost 8 — the live-network mode. This is a real grind.
	if !ds.willGrindStamp(knownPeerWithStampCost(t, svc, 8)) {
		t.Error("cost 8 is a real grind and must take a slot")
	}
	// At the cap, still ground.
	if !ds.willGrindStamp(knownPeerWithStampCost(t, svc, 16)) {
		t.Error("cost 16 is at the cap and must take a slot")
	}
	// Above the cap SendWithID refuses before building the workblock,
	// so holding a slot would block a send that never grinds.
	if ds.willGrindStamp(knownPeerWithStampCost(t, svc, 20)) {
		t.Error("cost above MaxStampCost is refused, not ground — no slot")
	}
	// Unknown recipient fails before any grind.
	if ds.willGrindStamp(bytes.Repeat([]byte{0xEE}, 16)) {
		t.Error("unknown recipient must not take a grind slot")
	}
}
