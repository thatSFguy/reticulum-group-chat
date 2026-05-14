package rns

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// TestBuildLinkIdentifyHappyPath builds a LINKIDENTIFY packet for a
// known link, decrypts the body with the same session keys (as the
// responder would), and verifies the wire shape SPEC §6.6 expects:
// identity_hash(16) || ed25519_signature(64) where the signature
// covers link_id(16) || identity.public_key(64).
func TestBuildLinkIdentifyHappyPath(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	linkID := bytes.Repeat([]byte{0xA5}, IdentityHashLen)
	signing := bytes.Repeat([]byte{0x11}, 32)
	encryption := bytes.Repeat([]byte{0x22}, 32)

	pkt, err := BuildLinkIdentify(linkID, signing, encryption, id)
	if err != nil {
		t.Fatalf("BuildLinkIdentify: %v", err)
	}

	if pkt.PacketType != PacketData {
		t.Errorf("packet_type = %d, want PacketData (0)", pkt.PacketType)
	}
	if pkt.DestinationType != DestinationLink {
		t.Errorf("dest_type = %d, want DestinationLink", pkt.DestinationType)
	}
	if pkt.Context != ContextLinkIdentify {
		t.Errorf("context = 0x%02x, want 0x%02x", pkt.Context, ContextLinkIdentify)
	}
	if !bytes.Equal(pkt.DestHash, linkID) {
		t.Errorf("dest_hash = %x, want %x", pkt.DestHash, linkID)
	}

	plaintext, err := LinkTokenDecrypt(pkt.Data, signing, encryption)
	if err != nil {
		t.Fatalf("LinkTokenDecrypt: %v", err)
	}
	if len(plaintext) != IdentityHashLen+ed25519.SignatureSize {
		t.Fatalf("plaintext = %d bytes, want %d", len(plaintext),
			IdentityHashLen+ed25519.SignatureSize)
	}
	gotHash := plaintext[:IdentityHashLen]
	gotSig := plaintext[IdentityHashLen:]

	if !bytes.Equal(gotHash, id.Hash()) {
		t.Errorf("identity_hash mismatch: got %x, want %x", gotHash, id.Hash())
	}

	signedData := append(append([]byte{}, linkID...), id.PublicKey()...)
	edPub := id.PublicKey()[32:]
	if !ed25519.Verify(ed25519.PublicKey(edPub), signedData, gotSig) {
		t.Error("signature did not verify against link_id || pubkey")
	}
}

func TestBuildLinkIdentifyRejectsBadInputs(t *testing.T) {
	id, _ := NewIdentity()
	signing := bytes.Repeat([]byte{0x11}, 32)
	encryption := bytes.Repeat([]byte{0x22}, 32)

	if _, err := BuildLinkIdentify(nil, signing, encryption, id); err == nil {
		t.Error("nil link_id should error")
	}
	if _, err := BuildLinkIdentify(make([]byte, 4), signing, encryption, id); err == nil {
		t.Error("short link_id should error")
	}
	if _, err := BuildLinkIdentify(bytes.Repeat([]byte{0}, IdentityHashLen), signing, encryption, nil); err == nil {
		t.Error("nil identity should error")
	}
}
