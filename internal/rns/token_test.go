package rns

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	recipient, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	cases := [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte(strings.Repeat("x", 16)),  // exact block boundary
		[]byte(strings.Repeat("x", 17)),  // one over
		bytesOfLen(t, 1024),
	}
	for _, plaintext := range cases {
		ciphertext, err := TokenEncrypt(plaintext, recipient.X25519Public(), recipient.Hash())
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", len(plaintext), err)
		}
		got, err := TokenDecrypt(recipient, ciphertext)
		if err != nil {
			t.Fatalf("decrypt %d bytes: %v", len(plaintext), err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-trip mismatch for %d bytes\n got %x\nwant %x", len(plaintext), got, plaintext)
		}
	}
}

func TestTokenWrongRecipientRejected(t *testing.T) {
	intended, _ := NewIdentity()
	other, _ := NewIdentity()

	ct, err := TokenEncrypt([]byte("for intended only"), intended.X25519Public(), intended.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := TokenDecrypt(other, ct); err == nil {
		t.Error("decrypted with wrong identity — should have failed HMAC check")
	}
}

func TestTokenTamperedCiphertextRejected(t *testing.T) {
	id, _ := NewIdentity()
	ct, _ := TokenEncrypt([]byte("don't change me"), id.X25519Public(), id.Hash())

	// Flip a bit in the ciphertext region (after eph_pub + IV, before HMAC).
	tampered := append([]byte(nil), ct...)
	tampered[tokenEphPubLen+tokenIVLen+1] ^= 0x01

	if _, err := TokenDecrypt(id, tampered); err == nil {
		t.Error("tampered ciphertext decrypted — HMAC didn't catch it")
	}
}

func TestTokenTamperedHMACRejected(t *testing.T) {
	id, _ := NewIdentity()
	ct, _ := TokenEncrypt([]byte("hi"), id.X25519Public(), id.Hash())

	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := TokenDecrypt(id, tampered); err == nil {
		t.Error("tampered HMAC accepted")
	}
}

// TestTokenSaltIsIdentityHashNotDestinationHash pins the SPEC §3.2 / §9 gotcha.
// Encrypting with the destination hash as salt would produce ciphertext that
// the recipient cannot decrypt (because they HKDF with their identity hash on
// the receive side). We verify the inverse: a deliberate "wrong-salt" encrypt
// is rejected by decrypt.
func TestTokenSaltIsIdentityHashNotDestinationHash(t *testing.T) {
	recipient, _ := NewIdentity()
	wrongSalt := recipient.DestinationHashFor(FullName("lxmf", "delivery"))
	if bytes.Equal(wrongSalt, recipient.Hash()) {
		t.Fatal("test setup wrong: dest hash == identity hash by chance")
	}
	ct, err := TokenEncrypt([]byte("misrouted"), recipient.X25519Public(), wrongSalt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TokenDecrypt(recipient, ct); err == nil {
		t.Error("decrypt accepted ciphertext encrypted with destination_hash salt — gotcha regression!")
	}
}

func bytesOfLen(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
