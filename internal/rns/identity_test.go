package rns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityHashFromPublicKey(t *testing.T) {
	pub := bytes.Repeat([]byte{0x5A}, PublicKeyLen)
	sum := sha256.Sum256(pub)
	want := sum[:IdentityHashLen]

	got := IdentityHashFromPublicKey(pub)
	if !bytes.Equal(got, want) {
		t.Errorf("IdentityHashFromPublicKey = %x, want %x", got, want)
	}
	if len(got) != IdentityHashLen {
		t.Errorf("len = %d, want %d", len(got), IdentityHashLen)
	}
	// Wrong-length key → nil (not a panic, not a partial hash).
	if IdentityHashFromPublicKey(pub[:10]) != nil {
		t.Error("short public key should return nil")
	}
	// KnownIdentity.IdentityHash mirrors the free function and is
	// distinct from the destination hash.
	k := &KnownIdentity{PublicKey: pub, DestHash: bytes.Repeat([]byte{0x99}, IdentityHashLen)}
	if !bytes.Equal(k.IdentityHash(), want) {
		t.Errorf("KnownIdentity.IdentityHash = %x, want %x", k.IdentityHash(), want)
	}
	if bytes.Equal(k.IdentityHash(), k.DestHash) {
		t.Error("identity hash must not equal destination hash (the gotcha this guards)")
	}
}

// testVectorsPath points at the spec repo's identities.json. The repo is a
// sibling of this project on the dev machine; tests are skipped if it isn't
// present so this package still passes in environments without the spec.
const testVectorsPath = "../../../reticulum-specifications/test-vectors/identities.json"

type identityVector struct {
	Label                 string `json:"label"`
	DestinationFullName   string `json:"destination_full_name"`
	Inputs                struct {
		PrivateKeyHex string `json:"private_key_hex"`
	} `json:"inputs"`
	Expected struct {
		PublicKeyHex      string `json:"public_key_hex"`
		IdentityHashHex   string `json:"identity_hash_hex"`
		NameHashHex       string `json:"name_hash_hex"`
		DestinationHashHex string `json:"destination_hash_hex"`
	} `json:"expected"`
}

type identityVectorsFile struct {
	Vectors []identityVector `json:"vectors"`
}

func loadIdentityVectors(t *testing.T) []identityVector {
	t.Helper()
	abs, err := filepath.Abs(testVectorsPath)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("test vectors unavailable (%s): %v", abs, err)
	}
	var f identityVectorsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no vectors loaded from %s", abs)
	}
	return f.Vectors
}

// TestIdentityVectors validates our identity derivation against the spec's
// alice + bob test vectors. This is the load-bearing assertion that we agree
// with upstream Python RNS on every byte of the identity layer.
func TestIdentityVectors(t *testing.T) {
	for _, v := range loadIdentityVectors(t) {
		t.Run(v.Label, func(t *testing.T) {
			privBytes, err := hex.DecodeString(v.Inputs.PrivateKeyHex)
			if err != nil {
				t.Fatalf("decode privkey hex: %v", err)
			}
			id, err := IdentityFromPrivateKey(privBytes)
			if err != nil {
				t.Fatalf("IdentityFromPrivateKey: %v", err)
			}

			expectedPub, _ := hex.DecodeString(v.Expected.PublicKeyHex)
			if !bytes.Equal(id.PublicKey(), expectedPub) {
				t.Errorf("public key mismatch\n got %x\nwant %x", id.PublicKey(), expectedPub)
			}

			expectedIDHash, _ := hex.DecodeString(v.Expected.IdentityHashHex)
			if !bytes.Equal(id.Hash(), expectedIDHash) {
				t.Errorf("identity hash mismatch\n got %x\nwant %x", id.Hash(), expectedIDHash)
			}

			expectedNameHash, _ := hex.DecodeString(v.Expected.NameHashHex)
			gotNameHash := NameHash(v.DestinationFullName)
			if !bytes.Equal(gotNameHash, expectedNameHash) {
				t.Errorf("name hash mismatch for %q\n got %x\nwant %x",
					v.DestinationFullName, gotNameHash, expectedNameHash)
			}

			expectedDestHash, _ := hex.DecodeString(v.Expected.DestinationHashHex)
			gotDestHash := id.DestinationHashFor(v.DestinationFullName)
			if !bytes.Equal(gotDestHash, expectedDestHash) {
				t.Errorf("destination hash mismatch\n got %x\nwant %x", gotDestHash, expectedDestHash)
			}
		})
	}
}

// TestLXMFDeliveryNameHash pins the well-known constant for the lxmf.delivery
// aspect (SPEC §9.7) — independent of the broader vector suite.
func TestLXMFDeliveryNameHash(t *testing.T) {
	got := hex.EncodeToString(NameHash(FullName("lxmf", "delivery")))
	const want = "6ec60bc318e2c0f0d908"
	if got != want {
		t.Errorf("name_hash for lxmf.delivery = %s, want %s", got, want)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "identity")

	original, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != PrivateKeyLen {
		t.Errorf("file size = %d, want %d", info.Size(), PrivateKeyLen)
	}

	loaded, err := IdentityFromFile(path)
	if err != nil {
		t.Fatalf("IdentityFromFile: %v", err)
	}
	if !bytes.Equal(loaded.PrivateKey(), original.PrivateKey()) {
		t.Error("private key bytes differ after round-trip")
	}
	if !bytes.Equal(loaded.PublicKey(), original.PublicKey()) {
		t.Error("derived public key differs after round-trip")
	}
	if !bytes.Equal(loaded.Hash(), original.Hash()) {
		t.Error("identity hash differs after round-trip")
	}
}

func TestSignAndValidate(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	msg := []byte("forwarding service hello")
	sig := id.Sign(msg)
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sig))
	}
	// pubkey portion of PublicKey() at offset 32:64 is the Ed25519 public
	pub := id.PublicKey()[32:]
	if !Validate(pub, msg, sig) {
		t.Error("Validate: own signature didn't verify")
	}
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if Validate(pub, tampered, sig) {
		t.Error("Validate accepted a tampered message")
	}
}

func TestSharedSecretMatchesBetweenPeers(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	ab, err := a.SharedSecret(b.X25519Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.SharedSecret(a.X25519Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Error("shared secrets differ between peers")
	}
}
