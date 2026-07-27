package lxmf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// pnFixture stands up alice (sender, transport A) and a fake propagation
// node (transport B) that captures every link plaintext arriving at its
// lxmf.propagation destination — the responder half of the §5.8 upload
// flow. bob exists as an identity only (the recipient a message is
// encrypted to); his announce is broadcast from B so alice learns his
// keys, exactly like a real network where the recipient is offline but
// previously announced.
type pnFixture struct {
	alice, bob, node *rns.Identity
	delA             *Delivery
	nodeDest         []byte
	bobDest          []byte

	mu       sync.Mutex
	captured [][]byte
}

func newPNFixture(t *testing.T, pnAppData []byte) *pnFixture {
	t.Helper()
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()
	node, _ := rns.NewIdentity()

	aIface, bIface, stop := pairedInterfaces()
	tA := rns.NewTransport(nil)
	tA.AddInterface(aIface)
	tB := rns.NewTransport(nil)
	tB.AddInterface(bIface)

	delA, err := NewDelivery(tA, alice, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &pnFixture{
		alice:    alice,
		bob:      bob,
		node:     node,
		delA:     delA,
		nodeDest: node.DestinationHashFor(PropagationFullName()),
		bobDest:  bob.DestinationHashFor(FullName()),
	}

	// The fake node: accepts links to its lxmf.propagation destination
	// and records each decrypted upload payload.
	if err := tB.RegisterLocal(&rns.LocalDestination{
		DestHash: f.nodeDest,
		Identity: node,
		OnPacket: func(*rns.Packet) {}, // uploads only arrive via link
		OnLinkPlaintext: func(plaintext []byte) {
			f.mu.Lock()
			f.captured = append(f.captured, append([]byte(nil), plaintext...))
			f.mu.Unlock()
		},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go tA.Run(ctx)
	go tB.Run(ctx)
	t.Cleanup(func() {
		cancel()
		stop()
	})

	// Announce the node (lxmf.propagation aspect, §5.8.5 app_data) and
	// bob (lxmf.delivery) from B; alice needs both in her known table.
	nodePkt, err := rns.BuildAnnounce(node, PropagationFullName(), pnAppData, nil)
	if err != nil {
		t.Fatal(err)
	}
	bobAppData, _ := rns.EncodeLXMFAppData([]byte("bob"), nil)
	bobPkt, err := rns.BuildAnnounce(bob, FullName(), bobAppData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tB.Broadcast(nodePkt); err != nil {
		t.Fatal(err)
	}
	if err := tB.Broadcast(bobPkt); err != nil {
		t.Fatal(err)
	}
	if !waitFor(500*time.Millisecond, func() bool {
		return tA.Recall(f.nodeDest) != nil && tA.Recall(f.bobDest) != nil
	}) {
		t.Fatal("announces never reached alice")
	}
	return f
}

func (f *pnFixture) waitForUpload(t *testing.T) []byte {
	t.Helper()
	if !waitFor(2*time.Second, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.captured) > 0
	}) {
		t.Fatal("propagation node never received an upload")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.captured[0]
}

// decodeBundle unpacks the §5.8 upload envelope and returns the single
// contained lxmf_data.
func decodeBundle(t *testing.T, bundle []byte) []byte {
	t.Helper()
	var outer []msgpack.RawMessage
	if err := msgpack.Unmarshal(bundle, &outer); err != nil {
		t.Fatalf("upload is not a msgpack array: %v", err)
	}
	if len(outer) != 2 {
		t.Fatalf("upload envelope has %d elements, want 2", len(outer))
	}
	var bodies [][]byte
	if err := msgpack.Unmarshal(outer[1], &bodies); err != nil {
		t.Fatalf("upload bodies: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("upload carries %d messages, want 1", len(bodies))
	}
	return bodies[0]
}

func TestSendPropagatedE2E(t *testing.T) {
	f := newPNFixture(t, validPNAppData(t, true, 0, 0))

	msgID, err := f.delA.SendPropagated(f.nodeDest, f.bobDest, nil, []byte("offline mail"), nil)
	if err != nil {
		t.Fatalf("SendPropagated: %v", err)
	}

	lxmfData := decodeBundle(t, f.waitForUpload(t))
	if !bytes.Equal(lxmfData[:rns.IdentityHashLen], f.bobDest) {
		t.Errorf("lxmf_data keyed to %x, want bob %x", lxmfData[:rns.IdentityHashLen], f.bobDest)
	}

	// Bob's client decrypts and verifies exactly as if the message had
	// arrived opportunistically (flows/receive-propagated-lxmf.md §7).
	plain, err := rns.TokenDecrypt(f.bob, lxmfData[rns.IdentityHashLen:])
	if err != nil {
		t.Fatalf("bob TokenDecrypt: %v", err)
	}
	msg, err := ParseOpportunisticBody(plain, f.bobDest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := msg.Verify(f.alice.PublicKey()[32:]); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(msg.Content) != "offline mail" {
		t.Errorf("content = %q", msg.Content)
	}
	if !bytes.Equal(msg.MessageID(), msgID) {
		t.Errorf("message_id mismatch: recipient view %x, SendPropagated returned %x",
			msg.MessageID(), msgID)
	}
}

func TestSendPropagatedAppendsValidStamp(t *testing.T) {
	const cost = 8
	f := newPNFixture(t, validPNAppData(t, true, 0, cost))

	if _, err := f.delA.SendPropagated(f.nodeDest, f.bobDest, nil, []byte("stamped"), nil); err != nil {
		t.Fatalf("SendPropagated: %v", err)
	}

	lxmfData := decodeBundle(t, f.waitForUpload(t))
	if len(lxmfData) <= StampSize+rns.IdentityHashLen {
		t.Fatalf("lxmf_data too short to carry a stamp: %d", len(lxmfData))
	}
	body, stamp := lxmfData[:len(lxmfData)-StampSize], lxmfData[len(lxmfData)-StampSize:]

	// The stamp is ground over transient_id = SHA256(unstamped body).
	transientID := sha256.Sum256(body)
	wb, err := stampWorkblock(transientID[:], workblockExpandRoundsPN)
	if err != nil {
		t.Fatal(err)
	}
	if !stampValid(stamp, cost, wb) {
		t.Error("appended stamp does not clear the node's declared cost")
	}

	// And the stamped suffix must not have corrupted the message proper.
	if _, err := rns.TokenDecrypt(f.bob, body[rns.IdentityHashLen:]); err != nil {
		t.Errorf("body no longer decrypts after stamping: %v", err)
	}
}

func TestSendPropagatedRefusesDisabledNode(t *testing.T) {
	f := newPNFixture(t, validPNAppData(t, false /* not accepting */, 0, 0))

	_, err := f.delA.SendPropagated(f.nodeDest, f.bobDest, nil, []byte("x"), nil)
	if !errors.Is(err, ErrPropagationNodeDisabled) {
		t.Fatalf("err = %v, want ErrPropagationNodeDisabled", err)
	}
	f.mu.Lock()
	uploads := len(f.captured)
	f.mu.Unlock()
	if uploads != 0 {
		t.Errorf("disabled node received %d uploads, want 0", uploads)
	}
}

func TestSendPropagatedEnforcesTransferLimit(t *testing.T) {
	f := newPNFixture(t, validPNAppData(t, true, 1 /* 1 KB cap */, 0))

	big := bytes.Repeat([]byte("A"), 2000)
	_, err := f.delA.SendPropagated(f.nodeDest, f.bobDest, nil, big, nil)
	if !errors.Is(err, ErrPropagationTransferTooLarge) {
		t.Fatalf("err = %v, want ErrPropagationTransferTooLarge", err)
	}
}

func TestSendPropagatedUnknownNode(t *testing.T) {
	f := newPNFixture(t, validPNAppData(t, true, 0, 0))

	unknown := bytes.Repeat([]byte{0x77}, rns.IdentityHashLen)
	_, err := f.delA.SendPropagated(unknown, f.bobDest, nil, []byte("x"), nil)
	if !errors.Is(err, ErrPropagationNodeUnknown) {
		t.Fatalf("err = %v, want ErrPropagationNodeUnknown", err)
	}
}
