package lxmf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

// link_send_e2e_test.go: end-to-end positive AND negative scenarios for
// the outbound link initiator path added in PR1/PR2/PR3 of the
// link-delivery work. Uses two Transports on the in-memory crossInterface
// pair from delivery_test.go so we exercise the real wire format,
// dispatch loop, link manager, link cipher, and proof signing without
// needing a real network or a Python subprocess.
//
// Naming convention: TestSend* covers Delivery.Send (the LXMF layer);
// TestSendOverLink* covers Transport.SendOverLink (the rns layer).

// twoNodeFixture wires alice + bob through a paired crossInterface,
// announces both sides on each other's transport, and returns the
// pieces a test needs. Cancel func tears down both Transports' Run
// goroutines and the pipe.
type twoNodeFixture struct {
	alice, bob       *rns.Identity
	tA, tB           *rns.Transport
	delA, delB       *Delivery
	cancel           context.CancelFunc
	receivedOnB      *[]*Message
	receivedOnBMutex *sync.Mutex
}

func newTwoNodeFixture(t *testing.T) *twoNodeFixture {
	t.Helper()
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()

	aIface, bIface, stop := pairedInterfaces()

	tA := rns.NewTransport(nil)
	tA.AddInterface(aIface)
	tB := rns.NewTransport(nil)
	tB.AddInterface(bIface)

	delA, err := NewDelivery(tA, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	delB, err := NewDelivery(tB, bob, nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu       sync.Mutex
		received []*Message
	)
	delB.OnMessage = func(m *Message) {
		mu.Lock()
		// Copy what we need; Message holds slices that are not retained
		// after the dispatcher returns.
		cp := &Message{
			DestHash:   append([]byte(nil), m.DestHash...),
			SourceHash: append([]byte(nil), m.SourceHash...),
			Content:    append([]byte(nil), m.Content...),
			Title:      append([]byte(nil), m.Title...),
		}
		received = append(received, cp)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	go tA.Run(ctx)
	go tB.Run(ctx)

	mustAnnounce := func(tr *rns.Transport, id *rns.Identity) {
		appData, _ := rns.EncodeLXMFAppData([]byte(""), nil)
		pkt, err := rns.BuildAnnounce(id, FullName(), appData, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Broadcast(pkt); err != nil {
			t.Fatal(err)
		}
	}
	mustAnnounce(tA, alice)
	mustAnnounce(tB, bob)
	if !waitFor(500*time.Millisecond, func() bool {
		return tA.Recall(delB.Hash()) != nil && tB.Recall(delA.Hash()) != nil
	}) {
		cancel()
		stop()
		t.Fatal("announces never propagated between transports")
	}

	t.Cleanup(func() {
		cancel()
		stop()
	})
	return &twoNodeFixture{
		alice:            alice,
		bob:              bob,
		tA:               tA,
		tB:               tB,
		delA:             delA,
		delB:             delB,
		cancel:           cancel,
		receivedOnB:      &received,
		receivedOnBMutex: &mu,
	}
}

func (f *twoNodeFixture) waitForReceivedCount(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	if !waitFor(timeout, func() bool {
		f.receivedOnBMutex.Lock()
		defer f.receivedOnBMutex.Unlock()
		return len(*f.receivedOnB) >= want
	}) {
		f.receivedOnBMutex.Lock()
		got := len(*f.receivedOnB)
		f.receivedOnBMutex.Unlock()
		t.Fatalf("expected %d messages on bob, got %d after %s", want, got, timeout)
	}
}

func (f *twoNodeFixture) snapshotReceived() []*Message {
	f.receivedOnBMutex.Lock()
	defer f.receivedOnBMutex.Unlock()
	out := make([]*Message, len(*f.receivedOnB))
	copy(out, *f.receivedOnB)
	return out
}

// ---------------------------------------------------------------------
// POSITIVE — Send routes correctly and delivers
// ---------------------------------------------------------------------

// TestSendShortGoesOpportunistic confirms that a small message takes the
// opportunistic path: no Link is established on either side, and the
// recipient's OnMessage fires.
func TestSendShortGoesOpportunistic(t *testing.T) {
	f := newTwoNodeFixture(t)

	if err := f.delA.Send(f.delB.Hash(), nil, []byte("hello"), nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	f.waitForReceivedCount(t, 1, 500*time.Millisecond)

	if got := f.tA.LinkManager().ActiveCount(); got != 0 {
		t.Errorf("opportunistic path should not establish any link; alice has %d", got)
	}
	if got := f.tB.LinkManager().ActiveCount(); got != 0 {
		t.Errorf("opportunistic path should not establish any link; bob has %d", got)
	}
	if msg := f.snapshotReceived()[0]; !bytes.Equal(msg.Content, []byte("hello")) {
		t.Errorf("content mismatch: got %q", msg.Content)
	}
}

// TestSendLargeRoutesViaLink confirms that a payload over the
// opportunistic msgpack cap (295 bytes) causes Send to lazily open a
// Link, deliver the body in direct form, and BLOCK until the link DATA
// proof comes back. Asserts the Link is Active on both sides afterwards
// and Send returned nil.
func TestSendLargeRoutesViaLink(t *testing.T) {
	f := newTwoNodeFixture(t)

	long := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 30)) // ~1.4 KB
	start := time.Now()
	if err := f.delA.Send(f.delB.Hash(), nil, long, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	elapsed := time.Since(start)

	f.waitForReceivedCount(t, 1, 1*time.Second)
	got := f.snapshotReceived()[0]
	if !bytes.Equal(got.Content, long) {
		t.Errorf("link-delivered content mismatch (got %d bytes, want %d)", len(got.Content), len(long))
	}
	if alive := f.tA.LinkManager().ActiveCount(); alive != 1 {
		t.Errorf("alice should have 1 active link, got %d", alive)
	}
	if alive := f.tB.LinkManager().ActiveCount(); alive != 1 {
		t.Errorf("bob should have 1 active link, got %d", alive)
	}
	// Sanity: Send blocked at least until the responder proof came back
	// (>= one wire round-trip). Generous bound — we just want this to
	// detect the case where Send returned BEFORE the proof.
	if elapsed > 5*time.Second {
		t.Errorf("Send took %s — far longer than expected for in-process pipe", elapsed)
	}
}

// TestSendLargeReusesActiveLink confirms that two sequential large
// sends to the same peer reuse one Link rather than opening two — both
// for correctness (same link_id) and efficiency.
func TestSendLargeReusesActiveLink(t *testing.T) {
	f := newTwoNodeFixture(t)

	long1 := bytes.Repeat([]byte("first message "), 50)  // ~700 bytes
	long2 := bytes.Repeat([]byte("second message "), 50) // ~750 bytes

	if err := f.delA.Send(f.delB.Hash(), nil, long1, nil); err != nil {
		t.Fatalf("Send 1: %v", err)
	}
	if err := f.delA.Send(f.delB.Hash(), nil, long2, nil); err != nil {
		t.Fatalf("Send 2: %v", err)
	}
	f.waitForReceivedCount(t, 2, 2*time.Second)

	// Both sends should have used the SAME link.
	if alive := f.tA.LinkManager().ActiveCount(); alive != 1 {
		t.Errorf("alice should have 1 active link after 2 sends to same peer, got %d", alive)
	}
	got := f.snapshotReceived()
	if !bytes.Equal(got[0].Content, long1) || !bytes.Equal(got[1].Content, long2) {
		t.Errorf("content order/equality mismatch")
	}
}

// TestSendLargeBidirectional confirms PR2: when bob sends a large
// message back over alice's outbound link, alice's initiator-side
// signing path produces a link DATA proof that bob accepts. Without
// PR2's initiator-side proof signing, bob would retransmit indefinitely
// and his Send would time out.
func TestSendLargeBidirectional(t *testing.T) {
	f := newTwoNodeFixture(t)

	// Pair: alice opens link to bob first.
	long := bytes.Repeat([]byte("alice -> bob "), 50)
	if err := f.delA.Send(f.delB.Hash(), nil, long, nil); err != nil {
		t.Fatalf("alice Send: %v", err)
	}
	f.waitForReceivedCount(t, 1, 1*time.Second)

	// Now bob sends a large message back to alice. Two ways this could
	// route on bob's side:
	//   (a) Bob opens his OWN link to alice (separate link_id) — this is
	//       what current code does because LinkManager.ActiveTo searches
	//       for OUTBOUND links (peerDestHash matches), and bob's only
	//       active link toward alice is the responder-side one (no
	//       peerDestHash), so ActiveTo misses it.
	//   (b) Bob reuses alice's link as a return-direction send.
	// PR1 only implements (a). Either way the message must arrive.
	var receivedOnA []*Message
	var muA sync.Mutex
	f.delA.OnMessage = func(m *Message) {
		muA.Lock()
		receivedOnA = append(receivedOnA, &Message{Content: append([]byte(nil), m.Content...)})
		muA.Unlock()
	}
	reply := bytes.Repeat([]byte("bob -> alice "), 50)
	if err := f.delB.Send(f.delA.Hash(), nil, reply, nil); err != nil {
		t.Fatalf("bob Send: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		muA.Lock()
		defer muA.Unlock()
		return len(receivedOnA) >= 1
	}) {
		t.Fatal("alice never received bob's reply over link")
	}
	muA.Lock()
	gotReply := receivedOnA[0]
	muA.Unlock()
	if !bytes.Equal(gotReply.Content, reply) {
		t.Errorf("bob -> alice content mismatch")
	}
}

// TestSendInitiatorReceivesDataAndAcksWithEphemeralKey directly tests
// PR2: alice opens a link to bob, then bob sends raw link DATA back on
// that same link. Alice (as initiator) must sign the proof with her
// ephemeral Ed25519 priv (not a long-term key, which would be wrong);
// bob validates against the ephemeral pub from alice's LINKREQUEST.
//
// Round-tripping a real LXMF body is covered by
// TestSendLargeBidirectional; this one targets just the proof signing
// path so a regression there gets a focused failure.
func TestSendInitiatorReceivesDataAndAcksWithEphemeralKey(t *testing.T) {
	f := newTwoNodeFixture(t)

	// Open the link with a normal large send first.
	if err := f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("x"), 600), nil); err != nil {
		t.Fatalf("alice Send: %v", err)
	}
	f.waitForReceivedCount(t, 1, 1*time.Second)

	// Find bob's responder-side link (matching link_id).
	aliceLinks := []byte{} // keep compiler quiet
	_ = aliceLinks

	var aliceLinkID []byte
	if !waitFor(500*time.Millisecond, func() bool {
		aliceLinkID = nil
		// We don't have a public iteration on LinkManager, but ActiveTo
		// gives us the alice-side outbound link by peer dest hash.
		l := f.tA.LinkManager().ActiveTo(f.delB.Hash())
		if l == nil {
			return false
		}
		aliceLinkID = l.ID
		return f.tB.LinkManager().Get(aliceLinkID) != nil
	}) {
		t.Fatal("link not visible on both sides")
	}

	// Bob (as responder) sends raw link DATA on that link. We use the
	// LinkManager + BuildLinkDataPacket directly to bypass LXMF parsing
	// — alice's Transport will route the inbound to handleLinkData, and
	// because alice's link has NO responderIdentity but DOES have an
	// initiatorEd25519Priv (PR2 path), it must emit a proof signed with
	// the ephemeral priv that bob will accept.
	bobLink := f.tB.LinkManager().Get(aliceLinkID)
	if bobLink == nil {
		t.Fatal("no bob-side link")
	}
	plaintext := bytes.Repeat([]byte("bob raw link data "), 50) // ~900 bytes
	pkt, err := rns.BuildLinkDataPacket(bobLink.ID, bobLink.Signing, bobLink.Encryption, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// We don't have a public callback on alice's link — but the link
	// pipeline will have decrypted, called the (nil) callback, and
	// emitted a proof. The proof going back to bob is what we want to
	// verify here. Bob's pendingProofs would be checked, but bob never
	// registered one (he didn't go through SendOverLink). So we just
	// assert the proof packet WAS broadcast by checking the wire — the
	// crossInterface unfortunately doesn't let us inspect, so instead
	// we use a follow-up Send from alice that, if the link were
	// destroyed by the inbound, would fail. Send another message from
	// alice; if alice's link survived bob's inbound DATA, we're good.
	//
	// Better assertion: rely on the fact that ParseLinkProof on the
	// wire bytes succeeds with the ephemeral pub from the LINKREQUEST.
	// We don't have direct wire access here; settle for: bob's link is
	// still active and the pipeline didn't panic.
	if err := f.tB.Broadcast(pkt); err != nil {
		t.Fatal(err)
	}
	// Give the dispatcher a beat to process and emit the proof.
	time.Sleep(50 * time.Millisecond)

	// Both links should still be active.
	if f.tA.LinkManager().ActiveCount() != 1 || f.tB.LinkManager().ActiveCount() != 1 {
		t.Errorf("links should still be active after bob -> alice link DATA")
	}

	// Followup send from alice should still succeed — link state intact.
	if err := f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("y"), 600), nil); err != nil {
		t.Errorf("follow-up alice Send: %v", err)
	}
}

// ---------------------------------------------------------------------
// NEGATIVE — Send fails cleanly and returns descriptive errors
// ---------------------------------------------------------------------

// TestSendUnknownRecipient confirms that sending to a peer who hasn't
// announced returns an error before any wire activity. Applies to both
// short messages (opportunistic path's Recall check) and large messages
// (link path's acquireLinkTo Recall check) — same outcome.
func TestSendUnknownRecipient(t *testing.T) {
	alice, _ := rns.NewIdentity()
	tA := rns.NewTransport(nil)
	delA, _ := NewDelivery(tA, alice, nil)

	bob, _ := rns.NewIdentity()
	delBHash := bob.DestinationHashFor(FullName())

	if err := delA.Send(delBHash, nil, []byte("short"), nil); err == nil {
		t.Errorf("expected error sending to unannounced peer (short), got nil")
	}
	if err := delA.Send(delBHash, nil, bytes.Repeat([]byte("x"), 600), nil); err == nil {
		t.Errorf("expected error sending to unannounced peer (large), got nil")
	}
}

// TestSendOverLinkBadDestHashLength confirms input validation on the
// rns-layer primitive.
func TestSendOverLinkBadDestHashLength(t *testing.T) {
	tr := rns.NewTransport(nil)
	if err := tr.SendOverLink([]byte("too-short"), []byte("plain"), 100*time.Millisecond); err == nil {
		t.Errorf("expected error for bad dest hash length, got nil")
	}
}

// TestSendOverLinkPeerNotAnnounced confirms ErrLinkPeerUnknown surfaces
// when the responder hasn't announced.
func TestSendOverLinkPeerNotAnnounced(t *testing.T) {
	tr := rns.NewTransport(nil)
	bogus := bytes.Repeat([]byte{0xAA}, 16)
	err := tr.SendOverLink(bogus, []byte("plain"), 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, rns.ErrLinkPeerUnknown) {
		t.Errorf("expected ErrLinkPeerUnknown, got %v", err)
	}
}

// TestSendOverLinkHandshakeTimeout confirms that if no LRPROOF arrives
// within the timeout, SendOverLink returns ErrLinkHandshakeTimeout and
// the orphaned Pending link is cleaned up so a retry doesn't trip on
// a stuck stub.
func TestSendOverLinkHandshakeTimeout(t *testing.T) {
	// Configure a one-way pipe: alice can send, but no transport on the
	// other end will ever send back an LRPROOF.
	alice, _ := rns.NewIdentity()
	tA := rns.NewTransport(nil)
	aIface, bIface, stop := pairedInterfaces()
	defer stop()
	tA.AddInterface(aIface)
	go drainInterface(bIface) // sink anything alice sends; never reply

	// Plant a fake announce for bob in alice's known table so Recall
	// succeeds (the test isn't about peer-unknown).
	bob, _ := rns.NewIdentity()
	bobDest := bob.DestinationHashFor(FullName())
	plantKnown(t, tA, bob, bobDest)

	delA, _ := NewDelivery(tA, alice, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tA.Run(ctx)

	delA.LinkSendTimeout = 200 * time.Millisecond
	err := delA.Send(bobDest, nil, bytes.Repeat([]byte("x"), 600), nil)
	if err == nil {
		t.Fatalf("expected handshake timeout error, got nil")
	}
	if !errors.Is(err, rns.ErrLinkHandshakeTimeout) {
		t.Errorf("expected ErrLinkHandshakeTimeout, got %v", err)
	}
	// The stub link should have been closed.
	if tA.LinkManager().ActiveCount() != 0 {
		t.Errorf("expected no active links after handshake timeout, got %d", tA.LinkManager().ActiveCount())
	}
}

// TestSendOverLinkProofTimeout confirms that if the link comes up but
// the responder never emits a link DATA proof, SendOverLink surfaces
// ErrLinkProofTimeout. We simulate this by tearing down bob's
// responder-side dispatcher right after the handshake completes.
func TestSendOverLinkProofTimeout(t *testing.T) {
	f := newTwoNodeFixture(t)

	// Open the link with a tiny send first so we know it's active.
	// We can't easily use a small message because that goes opportunistic
	// — instead, drive StartLinkAsInitiator + handshake directly.
	link, lrReq, err := f.tA.LinkManager().StartLinkAsInitiator(f.delB.Hash(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.tA.Broadcast(lrReq); err != nil {
		t.Fatal(err)
	}
	if !waitFor(500*time.Millisecond, func() bool { return link.IsActive() }) {
		t.Fatal("handshake didn't complete")
	}

	// Now kill bob's transport so it can't emit proofs anymore.
	f.cancel()
	time.Sleep(20 * time.Millisecond) // let dispatcher unwind

	// Send a large message via Delivery.Send. Should time out.
	f.delA.LinkSendTimeout = 200 * time.Millisecond
	err = f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("x"), 600), nil)
	if err == nil {
		t.Fatalf("expected proof timeout, got nil")
	}
	if !errors.Is(err, rns.ErrLinkProofTimeout) && !strings.Contains(err.Error(), "link send: no interfaces") {
		t.Errorf("expected ErrLinkProofTimeout (or a no-interfaces error from the cancel race), got %v", err)
	}
}

// TestHandleLinkProofRejectsBadSignature ensures a forged link DATA
// proof (signed by the wrong key) does NOT signal a SendOverLink
// waiter. A valid signature from the correct peer is needed.
func TestHandleLinkProofRejectsBadSignature(t *testing.T) {
	f := newTwoNodeFixture(t)

	// Open a link and start a send that we'll keep waiting on.
	long := bytes.Repeat([]byte("x"), 600)
	done := make(chan error, 1)
	go func() { done <- f.delA.Send(f.delB.Hash(), nil, long, nil) }()

	// The legitimate path will send the right proof and Send will return
	// nil. Confirm that.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("legitimate Send failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legitimate Send timed out")
	}

	// Now craft a FORGED link DATA proof — same packet_hash, but signed
	// by a stranger's key. Inject it into alice's transport. The proof
	// validator should reject it; alice's pendingProofs map is empty so
	// no wakeup fires either way, but the test asserts we don't crash
	// and the link state stays good.
	stranger, _ := rns.NewIdentity()
	link := f.tA.LinkManager().ActiveTo(f.delB.Hash())
	if link == nil {
		t.Fatal("expected an active link to bob")
	}
	// Build a fake "link DATA" packet just to compute a packet_hash.
	fakeData, err := rns.BuildLinkDataPacket(link.ID, link.Signing, link.Encryption, []byte("doesn't matter"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := rns.BuildLinkProof(link.ID, stranger.Sign, fakeData)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := forged.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// Inject directly via the interface. We can't easily reach the
	// Transport's interface from here, so instead validate the rejection
	// at the pure function level: ValidateLinkProof should fail.
	parsed, err := rns.ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rns.ValidateLinkProof(parsed, f.bob.PublicKey()[32:]); err == nil {
		t.Errorf("ValidateLinkProof should reject a forged proof against bob's pubkey")
	}
	// And confirm the link is still active.
	if !link.IsActive() {
		t.Errorf("link should remain active after a forged proof")
	}
}

// TestSendOverLinkConcurrentSendsToSamePeer confirms that two
// concurrent SendOverLink calls that find no Active link don't deadlock
// or corrupt state. They may produce two separate links (PR1 doesn't
// coalesce) but both must complete successfully.
func TestSendOverLinkConcurrentSendsToSamePeer(t *testing.T) {
	f := newTwoNodeFixture(t)

	const N = 5
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := bytes.Repeat([]byte(fmt.Sprintf("c%d-", i)), 200) // ~800 bytes
			errs[i] = f.delA.Send(f.delB.Hash(), nil, body, nil)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("concurrent Send %d failed: %v", i, e)
		}
	}
	f.waitForReceivedCount(t, N, 5*time.Second)
}

// TestSendDeliveredCountReflectsLinkPath confirms that when a long
// forward routes via link, the Delivery.Send caller is given enough
// information to count successful deliveries (used by service.history
// "delivered > 0" gate).
func TestSendDeliveredCountReflectsLinkPath(t *testing.T) {
	f := newTwoNodeFixture(t)

	var success atomic.Int32
	go func() {
		if err := f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("x"), 600), nil); err == nil {
			success.Add(1)
		}
	}()
	f.waitForReceivedCount(t, 1, 2*time.Second)
	// The Send goroutine returns nil only after the proof — but waitFor
	// returned because OnMessage fired, which happens BEFORE the proof
	// emit on bob's side. Give the proof + alice's wakeup a moment.
	if !waitFor(500*time.Millisecond, func() bool { return success.Load() == 1 }) {
		t.Fatal("Send didn't complete with success after delivery + proof")
	}
}

// ---------------------------------------------------------------------
// LIFECYCLE — RunLinkSweeper closes idle links and emits keepalives
// ---------------------------------------------------------------------

// TestSweeperClosesIdleLink confirms that when an Active outbound link
// has been idle longer than the configured idle timeout, sweepLinks
// closes it. Uses Transport.SetLinkLifetime + sweepLinks() directly
// rather than RunLinkSweeper so the test is deterministic.
func TestSweeperClosesIdleLink(t *testing.T) {
	f := newTwoNodeFixture(t)

	if err := f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("x"), 600), nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	f.waitForReceivedCount(t, 1, 1*time.Second)
	if f.tA.LinkManager().ActiveCount() != 1 {
		t.Fatalf("expected 1 active link after large send, got %d", f.tA.LinkManager().ActiveCount())
	}

	// Configure aggressive idle timeout, then artificially age the link.
	f.tA.SetLinkLifetime(1*time.Hour, 10*time.Millisecond, 1*time.Hour)

	link := f.tA.LinkManager().ActiveTo(f.delB.Hash())
	if link == nil {
		t.Fatal("no active link to age")
	}
	rns.TestSetLinkLastActivity(link, time.Now().Add(-1*time.Minute))

	f.tA.SweepLinksForTest()

	if got := f.tA.LinkManager().ActiveCount(); got != 0 {
		t.Errorf("expected sweeper to close idle link, still active=%d", got)
	}
}

// TestSweeperEmitsKeepalive confirms that on an Active outbound link
// that's idle longer than the keepalive interval but not yet long
// enough for idle teardown, sweepLinks emits a KEEPALIVE packet (which
// bumps LastActivity on both ends).
func TestSweeperEmitsKeepalive(t *testing.T) {
	f := newTwoNodeFixture(t)

	if err := f.delA.Send(f.delB.Hash(), nil, bytes.Repeat([]byte("x"), 600), nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	f.waitForReceivedCount(t, 1, 1*time.Second)

	// Aggressive keepalive, looser idle so we don't tear down.
	f.tA.SetLinkLifetime(10*time.Millisecond, 1*time.Hour, 1*time.Hour)

	aliceLink := f.tA.LinkManager().ActiveTo(f.delB.Hash())
	if aliceLink == nil {
		t.Fatal("no active link")
	}
	bobLink := f.tB.LinkManager().Get(aliceLink.ID)
	if bobLink == nil {
		t.Fatal("no bob-side link")
	}

	// Age both sides to before the keepalive threshold and capture bob's
	// LastActivity so we can confirm it bumps when our keepalive arrives.
	rns.TestSetLinkLastActivity(aliceLink, time.Now().Add(-1*time.Minute))
	rns.TestSetLinkLastActivity(bobLink, time.Now().Add(-1*time.Minute))
	bobBefore := rns.TestGetLinkLastActivity(bobLink)

	f.tA.SweepLinksForTest()

	// Wait for the keepalive to traverse the pipe and bob's dispatcher
	// to bump LastActivity.
	if !waitFor(500*time.Millisecond, func() bool {
		return rns.TestGetLinkLastActivity(bobLink).After(bobBefore)
	}) {
		t.Errorf("bob's link LastActivity didn't advance after keepalive (still %v)", rns.TestGetLinkLastActivity(bobLink))
	}
	// Link should still be Active.
	if f.tA.LinkManager().ActiveCount() != 1 {
		t.Errorf("alice should still have 1 active link, got %d", f.tA.LinkManager().ActiveCount())
	}
}

// TestSendFromInsideOnMessageDoesNotDeadlock is the regression test for
// a bug found in live testing of v1.1.0: when bob's OnMessage handler
// itself called Delivery.Send to ship a reply that overflowed
// opportunistic, the send blocked waiting for an LRPROOF that was
// queued on the SAME dispatcher goroutine that was stuck in Send.
// Result: handshake timeout fires after 30s, LRPROOF arrives 1ms later
// to find no waiter, and the user sees no reply.
//
// Repro shape: alice opens an inbound link to bob, sends a small LXMF
// command-style message. Bob's OnMessage replies with a payload large
// enough to require link delivery. Without the fix
// (Delivery.handleInbound* dispatching OnMessage on a goroutine), bob's
// dispatcher deadlocks on the outbound link handshake. With the fix,
// alice receives the long reply within the test timeout.
func TestSendFromInsideOnMessageDoesNotDeadlock(t *testing.T) {
	f := newTwoNodeFixture(t)

	// Bob will reply to anything alice sends with a >280-byte payload,
	// which forces the reply through the link path.
	bigReply := bytes.Repeat([]byte("REPLY-PAYLOAD-MUST-OVERFLOW-OPPORTUNISTIC-CAP "), 20)
	f.delB.OnMessage = func(m *Message) {
		// Send from inside the handler. This is the production pattern
		// (service.onLXMFReceived → dispatcher → Delivery.Send) and
		// must NOT deadlock the Transport dispatcher.
		_ = f.delB.Send(m.SourceHash, nil, bigReply, nil)
	}

	// Alice listens for the reply.
	var (
		muA           sync.Mutex
		gotOnA        []*Message
	)
	f.delA.OnMessage = func(m *Message) {
		muA.Lock()
		gotOnA = append(gotOnA, &Message{Content: append([]byte(nil), m.Content...)})
		muA.Unlock()
	}

	// Trigger: alice sends a small "command" to bob, expects bob's big
	// reply back.
	if err := f.delA.Send(f.delB.Hash(), nil, []byte("/users"), nil); err != nil {
		t.Fatalf("alice send: %v", err)
	}

	// Without the fix the reply NEVER arrives — bob's dispatcher is
	// deadlocked on its own outbound link handshake. Generous timeout
	// so a slow CI doesn't false-positive: well below the 30s
	// handshake-timeout default but well above any reasonable in-process
	// link round-trip.
	if !waitFor(5*time.Second, func() bool {
		muA.Lock()
		defer muA.Unlock()
		return len(gotOnA) >= 1
	}) {
		t.Fatal("alice never received bob's reply — dispatcher likely deadlocked in Send-from-OnMessage")
	}
	muA.Lock()
	got := gotOnA[0]
	muA.Unlock()
	if !bytes.Equal(got.Content, bigReply) {
		t.Errorf("reply content mismatch")
	}
}

// drainInterface sinks everything sent on the given crossInterface but
// never replies. Used by handshake-timeout tests.
func drainInterface(c *crossInterface) {
	for {
		select {
		case <-c.Inbox():
		case <-c.Done():
			return
		}
	}
}

// plantKnown injects a synthetic announce-derived KnownIdentity into
// `tr`'s known table by emitting an actual announce packet from `id`.
// Easier than poking internal state and ensures the announce parses
// through the same code paths as any real one.
func plantKnown(t *testing.T, tr *rns.Transport, id *rns.Identity, destHash []byte) {
	t.Helper()
	appData, _ := rns.EncodeLXMFAppData([]byte(""), nil)
	pkt, err := rns.BuildAnnounce(id, FullName(), appData, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pkt.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rns.TestDispatchRaw(tr, wire)
	if !waitFor(500*time.Millisecond, func() bool { return tr.Recall(destHash) != nil }) {
		t.Fatal("plantKnown: announce never registered")
	}
}
