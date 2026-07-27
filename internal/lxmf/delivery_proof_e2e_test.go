package lxmf

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// TestSendTimesOutWhenRecipientOffline models the field failure that
// motivated delivery-proof tracking: the recipient has announced (so we
// have their keys and Send proceeds), but their client is disconnected —
// nothing on the network emits a §6.5 proof. Send must surface that as
// ErrDeliveryProofTimeout instead of reporting fire-and-forget success,
// so the outbound queue retries and the propagation fallback can engage.
func TestSendTimesOutWhenRecipientOffline(t *testing.T) {
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
	delA.DeliveryProofTimeout = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	go tA.Run(ctx)
	go tB.Run(ctx)
	t.Cleanup(func() {
		cancel()
		stop()
	})

	// Bob announced (alice learns his keys) but his delivery destination
	// is NOT registered on any transport — he's offline.
	bobDest := bob.DestinationHashFor(FullName())
	appData, _ := rns.EncodeLXMFAppData([]byte("bob"), nil)
	pkt, err := rns.BuildAnnounce(bob, FullName(), appData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tB.Broadcast(pkt); err != nil {
		t.Fatal(err)
	}
	if !waitFor(500*time.Millisecond, func() bool { return tA.Recall(bobDest) != nil }) {
		t.Fatal("bob's announce never reached alice")
	}

	start := time.Now()
	err = delA.Send(bobDest, nil, []byte("anyone home?"), nil)
	if !errors.Is(err, ErrDeliveryProofTimeout) {
		t.Fatalf("Send to offline recipient: err = %v, want ErrDeliveryProofTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Errorf("Send returned after %s — didn't actually wait for the proof window", elapsed)
	}
}
