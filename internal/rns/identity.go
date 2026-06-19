// Package rns is a minimal-viable, spec-faithful implementation of the
// Reticulum protocol stack in pure Go. It is NOT a port of any other
// implementation; it tracks the spec at github.com/thatSFguy/reticulum-specifications
// and is verified against the test vectors there plus a live Python rnsd peer.
//
// Currently implemented: identity, Token cipher, packet header, announce,
// HDLC framing for TCPClientInterface. Out of scope (for now): link delivery,
// propagation node, ratchets, RNode/LoRa, transport-relay forwarding.
package rns

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	// IdentityHashLen is the truncation length of SHA-256 used for identity
	// and destination hashes (SPEC §1.1, §1.2).
	IdentityHashLen = 16

	// NameHashLen is the truncation length of SHA-256 used for the destination
	// name hash (SPEC §1.2).
	NameHashLen = 10

	// PrivateKeyLen is the on-disk private-key file size: X25519 priv (32) ||
	// Ed25519 seed (32) (SPEC §1.3).
	PrivateKeyLen = 64

	// PublicKeyLen is the announced public-key blob: X25519 pub (32) ||
	// Ed25519 pub (32) (SPEC §1.1).
	PublicKeyLen = 64
)

// Identity is a Reticulum identity: an X25519 keypair (for ECDH) plus an
// Ed25519 keypair (for signing). Both keys are derived from raw bytes; we do
// not retain the expanded crypto/ed25519.PrivateKey to keep the in-memory
// shape close to the on-disk shape (see SPEC §1.3 — the on-disk file is just
// the two 32-byte private halves concatenated, with no header).
type Identity struct {
	x25519Priv  [32]byte
	ed25519Seed [32]byte
	x25519Pub   [32]byte
	ed25519Pub  [32]byte
}

// NewIdentity generates a fresh Identity using crypto/rand.
func NewIdentity() (*Identity, error) {
	var x25519Priv [32]byte
	if _, err := rand.Read(x25519Priv[:]); err != nil {
		return nil, fmt.Errorf("read random for X25519: %w", err)
	}
	// X25519 scalar clamping per RFC 7748. golang.org/x/crypto/curve25519
	// performs the clamp internally during X25519, but we apply it here so the
	// stored bytes match what callers would see on disk after a Python rnsd
	// would clamp during load.
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	var ed25519Seed [32]byte
	if _, err := rand.Read(ed25519Seed[:]); err != nil {
		return nil, fmt.Errorf("read random for Ed25519: %w", err)
	}

	return identityFromHalves(x25519Priv, ed25519Seed)
}

// IdentityFromPrivateKey constructs an Identity from a 64-byte concatenation
// of (X25519 priv 32 || Ed25519 seed 32).
func IdentityFromPrivateKey(b []byte) (*Identity, error) {
	if len(b) != PrivateKeyLen {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", PrivateKeyLen, len(b))
	}
	var x25519Priv, ed25519Seed [32]byte
	copy(x25519Priv[:], b[:32])
	copy(ed25519Seed[:], b[32:])
	return identityFromHalves(x25519Priv, ed25519Seed)
}

// IdentityFromFile loads an Identity from disk.
func IdentityFromFile(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity %s: %w", path, err)
	}
	return IdentityFromPrivateKey(data)
}

// Save writes the 64-byte private key to path with 0600 permissions, creating
// parent directories as needed. Atomic via tempfile rename.
func (id *Identity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(id.PrivateKey()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// PrivateKey returns the 64-byte concatenation written to disk.
func (id *Identity) PrivateKey() []byte {
	out := make([]byte, PrivateKeyLen)
	copy(out[:32], id.x25519Priv[:])
	copy(out[32:], id.ed25519Seed[:])
	return out
}

// PublicKey returns the announced 64-byte public key (X25519 pub || Ed25519 pub).
func (id *Identity) PublicKey() []byte {
	out := make([]byte, PublicKeyLen)
	copy(out[:32], id.x25519Pub[:])
	copy(out[32:], id.ed25519Pub[:])
	return out
}

// Hash returns the 16-byte identity hash: SHA-256(public_key)[:16].
func (id *Identity) Hash() []byte {
	return IdentityHashFromPublicKey(id.PublicKey())
}

// IdentityHashFromPublicKey returns the RNS identity hash,
// SHA-256(public_key)[:16], for a 64-byte announced public key
// (X25519 pub || Ed25519 pub). This is the identity hash, NOT a
// destination hash — destinations derive from it via DestinationHash.
// Returns nil for a wrong-length key.
func IdentityHashFromPublicKey(pub []byte) []byte {
	if len(pub) != PublicKeyLen {
		return nil
	}
	h := sha256.Sum256(pub)
	out := make([]byte, IdentityHashLen)
	copy(out, h[:IdentityHashLen])
	return out
}

// HexHash is a convenience for Hash() rendered as a lowercase hex string.
func (id *Identity) HexHash() string {
	return hex.EncodeToString(id.Hash())
}

// X25519Public returns the 32-byte X25519 public key (used by senders to
// derive the shared secret with this identity).
func (id *Identity) X25519Public() []byte {
	out := make([]byte, 32)
	copy(out, id.x25519Pub[:])
	return out
}

// Sign returns an Ed25519 signature over msg using this identity's Ed25519
// private key.
func (id *Identity) Sign(msg []byte) []byte {
	priv := ed25519.NewKeyFromSeed(id.ed25519Seed[:])
	return ed25519.Sign(priv, msg)
}

// Validate verifies an Ed25519 signature against the 32-byte public key.
// Static helper because verifies often happen against a remote identity for
// which we only have the public bytes (e.g. from an announce).
func Validate(ed25519Pub []byte, msg, sig []byte) bool {
	if len(ed25519Pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(ed25519Pub), msg, sig)
}

// SharedSecret derives the X25519 shared secret with a peer's public key.
// peerX25519Pub must be 32 bytes.
func (id *Identity) SharedSecret(peerX25519Pub []byte) ([]byte, error) {
	if len(peerX25519Pub) != 32 {
		return nil, errors.New("peer X25519 public must be 32 bytes")
	}
	return curve25519.X25519(id.x25519Priv[:], peerX25519Pub)
}

// FullName joins aspect parts with "." as Python RNS.Destination.full_name
// does (e.g. "lxmf", "delivery" -> "lxmf.delivery").
func FullName(aspects ...string) string { return strings.Join(aspects, ".") }

// NameHash returns SHA-256(fullName)[:10] (SPEC §1.2). For LXMF delivery
// (FullName("lxmf","delivery") -> "lxmf.delivery") this yields the
// well-known constant 6ec60bc318e2c0f0d908.
func NameHash(fullName string) []byte {
	h := sha256.Sum256([]byte(fullName))
	out := make([]byte, NameHashLen)
	copy(out, h[:NameHashLen])
	return out
}

// DestinationHash returns SHA-256(name_hash || identity_hash)[:16] (SPEC §1.2).
func DestinationHash(nameHash, identityHash []byte) []byte {
	if len(nameHash) != NameHashLen || len(identityHash) != IdentityHashLen {
		panic(fmt.Sprintf("DestinationHash: bad input lengths (name=%d, identity=%d)",
			len(nameHash), len(identityHash)))
	}
	buf := make([]byte, 0, NameHashLen+IdentityHashLen)
	buf = append(buf, nameHash...)
	buf = append(buf, identityHash...)
	h := sha256.Sum256(buf)
	out := make([]byte, IdentityHashLen)
	copy(out, h[:IdentityHashLen])
	return out
}

// DestinationHashFor is shorthand: derive an identity's destination hash for
// the given dotted full name.
func (id *Identity) DestinationHashFor(fullName string) []byte {
	return DestinationHash(NameHash(fullName), id.Hash())
}

// identityFromHalves derives the public-key halves and assembles an Identity.
func identityFromHalves(x25519Priv, ed25519Seed [32]byte) (*Identity, error) {
	x25519Pub, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive X25519 public: %w", err)
	}
	ed25519Priv := ed25519.NewKeyFromSeed(ed25519Seed[:])
	ed25519Pub := ed25519Priv.Public().(ed25519.PublicKey)

	id := &Identity{
		x25519Priv:  x25519Priv,
		ed25519Seed: ed25519Seed,
	}
	copy(id.x25519Pub[:], x25519Pub)
	copy(id.ed25519Pub[:], ed25519Pub)
	return id, nil
}
