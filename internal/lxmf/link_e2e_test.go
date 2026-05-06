package lxmf

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

// TestLinkE2EReceiveLongMessage proves the receive-side link-delivery
// pipeline end-to-end: alice opens a Reticulum Link to bob and sends an
// LXMF body that's far over the 295-byte opportunistic single-packet
// cap. Bob's Transport routes the LRPROOF + link DATA + emits the
// SPEC §6.5.6 explicit-form PROOF, the LinkManager decrypts the link
// DATA, and Bob's Delivery surfaces the parsed LXMF to OnMessage.
//
// This is the minimum viable receive-side validation that PR 3 wires
// everything together correctly.
func TestLinkE2EReceiveLongMessage(t *testing.T) {
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()

	aIface, bIface, stop := pairedInterfaces()
	defer stop()

	tA := rns.NewTransport(nil)
	tA.AddInterface(aIface)
	tB := rns.NewTransport(nil)
	tB.AddInterface(bIface)

	delA, _ := NewDelivery(tA, alice)
	delB, _ := NewDelivery(tB, bob)

	var (
		mu       sync.Mutex
		received [][]byte
	)
	delB.OnMessage = func(m *Message) {
		mu.Lock()
		received = append(received, append([]byte(nil), m.Content...))
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tA.Run(ctx)
	go tB.Run(ctx)

	// Both sides announce so the other can verify signatures + path.
	mustAnnounce := func(t *testing.T, tr *rns.Transport, id *rns.Identity) {
		t.Helper()
		appData, _ := rns.EncodeLXMFAppData([]byte(""), nil)
		pkt, err := rns.BuildAnnounce(id, FullName(), appData, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Broadcast(pkt); err != nil {
			t.Fatal(err)
		}
	}
	mustAnnounce(t, tA, alice)
	mustAnnounce(t, tB, bob)

	if !waitFor(500*time.Millisecond, func() bool {
		return tA.Recall(delB.Hash()) != nil && tB.Recall(delA.Hash()) != nil
	}) {
		t.Fatal("announces never propagated between transports")
	}

	// Alice opens a link to bob's destination.
	aliceLink, lrReq, err := tA.LinkManager().StartLinkAsInitiator(delB.Hash(), nil)
	if err != nil {
		t.Fatalf("StartLinkAsInitiator: %v", err)
	}
	if err := tA.Broadcast(lrReq); err != nil {
		t.Fatal(err)
	}

	// Wait for the link to go Active on alice's side (bob's Transport
	// will receive the LINKREQUEST, build + broadcast the LRPROOF, and
	// alice's Transport will route it back through HandleLRProof).
	if !waitFor(500*time.Millisecond, func() bool { return aliceLink.IsActive() }) {
		t.Fatalf("link never went Active on initiator (alice) side")
	}
	// Bob's responder-side link should also be active.
	if bobLink := tB.LinkManager().Get(aliceLink.ID); bobLink == nil || !bobLink.IsActive() {
		t.Fatal("bob's responder-side link is not Active")
	}

	// Build a long LXMF body in DIRECT form (>>> 295-byte opportunistic cap).
	long := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 30)) // ~1.4 KB
	directBody, err := SignAndPackDirect(
		alice,
		delA.Hash(),
		delB.Hash(),
		[]byte(""),
		long,
		nil,
	)
	if err != nil {
		t.Fatalf("SignAndPackDirect: %v", err)
	}

	// Send it as link DATA.
	dataPkt, err := rns.BuildLinkDataPacket(aliceLink.ID, aliceLink.Signing, aliceLink.Encryption, directBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := tA.Broadcast(dataPkt); err != nil {
		t.Fatal(err)
	}

	// Wait for bob's OnMessage to fire.
	if !waitFor(1*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	}) {
		t.Fatal("link DATA never surfaced to bob's OnMessage")
	}
	mu.Lock()
	got := received[0]
	mu.Unlock()
	if !bytes.Equal(got, long) {
		t.Errorf("link-delivered content mismatch (got %d bytes, want %d)", len(got), len(long))
	}
}
