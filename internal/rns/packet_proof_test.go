package rns

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// Unit tests for the outbound packet-proof waiter (SPEC §6.5 delivery
// confirmation, the PacketReceipt concept). Wire-level round trips are
// covered by the lxmf package's Send e2e tests; these exercise the
// verification branches directly.

func testWaiterFixture(t *testing.T) (*Transport, *Identity, []byte, <-chan error, func()) {
	t.Helper()
	tr := NewTransport(nil)
	receiver, _ := NewIdentity()
	fullHash := make([]byte, sha256.Size)
	if _, err := rand.Read(fullHash); err != nil {
		t.Fatal(err)
	}
	ch, cancel, err := tr.RegisterPacketProofWaiter(fullHash, receiver.PublicKey()[32:])
	if err != nil {
		t.Fatal(err)
	}
	return tr, receiver, fullHash, ch, cancel
}

func proofResolved(ch <-chan error) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestPacketProofImplicitFormResolves(t *testing.T) {
	tr, receiver, fullHash, ch, cancel := testWaiterFixture(t)
	defer cancel()

	tr.handlePacketProof(&Packet{
		PacketType: PacketProof,
		DestHash:   fullHash[:IdentityHashLen],
		Data:       receiver.Sign(fullHash),
	})
	if !proofResolved(ch) {
		t.Fatal("valid implicit proof did not resolve the waiter")
	}
}

func TestPacketProofExplicitFormResolves(t *testing.T) {
	tr, receiver, fullHash, ch, cancel := testWaiterFixture(t)
	defer cancel()

	body := append(append([]byte(nil), fullHash...), receiver.Sign(fullHash)...)
	tr.handlePacketProof(&Packet{
		PacketType: PacketProof,
		DestHash:   fullHash[:IdentityHashLen],
		Data:       body,
	})
	if !proofResolved(ch) {
		t.Fatal("valid explicit proof did not resolve the waiter")
	}
}

func TestPacketProofRejectsForgedSignature(t *testing.T) {
	tr, _, fullHash, ch, cancel := testWaiterFixture(t)
	defer cancel()

	forger, _ := NewIdentity()
	tr.handlePacketProof(&Packet{
		PacketType: PacketProof,
		DestHash:   fullHash[:IdentityHashLen],
		Data:       forger.Sign(fullHash),
	})
	if proofResolved(ch) {
		t.Fatal("proof signed by the wrong identity resolved the waiter")
	}
}

func TestPacketProofExplicitHashMismatchIgnored(t *testing.T) {
	tr, receiver, fullHash, ch, cancel := testWaiterFixture(t)
	defer cancel()

	wrongHash := make([]byte, sha256.Size)
	body := append(append([]byte(nil), wrongHash...), receiver.Sign(wrongHash)...)
	tr.handlePacketProof(&Packet{
		PacketType: PacketProof,
		DestHash:   fullHash[:IdentityHashLen],
		Data:       body,
	})
	if proofResolved(ch) {
		t.Fatal("explicit proof for a different packet hash resolved the waiter")
	}
}

func TestPacketProofAfterCancelIsDropped(t *testing.T) {
	tr, receiver, fullHash, ch, cancel := testWaiterFixture(t)
	cancel()

	tr.handlePacketProof(&Packet{
		PacketType: PacketProof,
		DestHash:   fullHash[:IdentityHashLen],
		Data:       receiver.Sign(fullHash),
	})
	if proofResolved(ch) {
		t.Fatal("proof resolved a cancelled waiter")
	}
}
