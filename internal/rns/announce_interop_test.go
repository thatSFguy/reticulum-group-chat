package rns

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// TestAnnounceVectorsBytewiseInterop loads
// ../reticulum-specifications/test-vectors/announces.json (deterministic
// announces produced by upstream Python rns 1.2.0 via tools/regen_announces.py)
// and verifies that:
//
//  1. Our buildAnnounce, given the SAME inputs (identity, full name,
//     random_hash prefix, timestamp, app_data, optional ratchet), emits
//     bytes that match expected.wire_bytes_hex BYTE-FOR-BYTE.
//  2. The reverse parse + verify path accepts those same bytes.
//
// This is the load-bearing wire-format check against the canonical
// upstream implementation. If this passes for every vector, our announce
// codec interoperates with Python rns at the byte level.
func TestAnnounceVectorsBytewiseInterop(t *testing.T) {
	idVectors := loadIdentityVectors(t)
	idByLabel := map[string]*Identity{}
	for _, v := range idVectors {
		priv, _ := hex.DecodeString(v.Inputs.PrivateKeyHex)
		id, err := IdentityFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		idByLabel[v.Label] = id
	}

	vectors := loadAnnounceVectors(t)
	for _, v := range vectors {
		t.Run(v.Label, func(t *testing.T) {
			id, ok := idByLabel[v.Inputs.IdentityLabel]
			if !ok {
				t.Fatalf("vector references unknown identity %q", v.Inputs.IdentityLabel)
			}

			appData, _ := hex.DecodeString(v.Inputs.AppDataMsgpackHex)
			rhPrefix, _ := hex.DecodeString(v.Inputs.RandomHashPrefixHex)
			if len(rhPrefix) != 5 {
				t.Fatalf("random_hash_prefix_hex must decode to 5 bytes, got %d", len(rhPrefix))
			}

			var ratchetPub []byte
			if v.WithRatchet {
				ratchetPriv, _ := hex.DecodeString(v.Inputs.RatchetPrivHex)
				if len(ratchetPriv) != 32 {
					t.Fatalf("ratchet priv decode = %d bytes, want 32", len(ratchetPriv))
				}
				pub, err := derivePublicX25519(ratchetPriv)
				if err != nil {
					t.Fatal(err)
				}
				ratchetPub = pub
			}

			now := func() time.Time { return time.Unix(v.Inputs.RandomHashTimestamp, 0) }
			rnd := scriptedRandom(rhPrefix)

			pkt, err := buildAnnounce(id, v.Inputs.DestinationFullName, appData, ratchetPub, ContextNone, now, rnd)
			if err != nil {
				t.Fatalf("buildAnnounce: %v", err)
			}
			gotWire, err := pkt.Pack()
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}

			wantWire, _ := hex.DecodeString(v.Expected.WireBytesHex)
			if !bytes.Equal(gotWire, wantWire) {
				t.Errorf("wire bytes mismatch\n got %x\nwant %x", gotWire, wantWire)
			}

			// Reverse: parse the canonical bytes and assert verify succeeds.
			parsed, err := ParsePacket(wantWire)
			if err != nil {
				t.Fatalf("ParsePacket on canonical bytes: %v", err)
			}
			a, err := ParseAnnounce(parsed)
			if err != nil {
				t.Fatalf("ParseAnnounce: %v", err)
			}
			if err := a.Verify(); err != nil {
				t.Fatalf("Verify on canonical bytes: %v", err)
			}

			expectedDest, _ := hex.DecodeString(v.Expected.DestinationHashHex)
			if !bytes.Equal(parsed.DestHash, expectedDest) {
				t.Errorf("dest_hash mismatch\n got %x\nwant %x", parsed.DestHash, expectedDest)
			}
		})
	}
}

type announceVector struct {
	Label        string `json:"label"`
	ContextFlag  int    `json:"context_flag"`
	WithRatchet  bool   `json:"with_ratchet"`
	Inputs       struct {
		IdentityLabel       string `json:"identity_label"`
		DestinationFullName string `json:"destination_full_name"`
		RandomHashPrefixHex string `json:"random_hash_prefix_hex"`
		RandomHashTimestamp int64  `json:"random_hash_timestamp"`
		RatchetPrivHex      string `json:"ratchet_priv_hex"`
		AppDataMsgpackHex   string `json:"app_data_msgpack_hex"`
	} `json:"inputs"`
	Expected struct {
		DestinationHashHex string `json:"destination_hash_hex"`
		WireBytesHex       string `json:"wire_bytes_hex"`
	} `json:"expected"`
}

type announceVectorsFile struct {
	Vectors []announceVector `json:"vectors"`
}

func loadAnnounceVectors(t *testing.T) []announceVector {
	t.Helper()
	path, err := filepath.Abs("../../../reticulum-specifications/test-vectors/announces.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("announces.json unavailable (%s): %v", path, err)
	}
	var f announceVectorsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal announces.json: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no announce vectors in %s", path)
	}
	return f.Vectors
}

// scriptedRandom returns an rnd-source function that, on its first call,
// fills the buffer with `prefix`. Subsequent calls panic — the caller
// shouldn't be asking for more entropy than the announce body uses.
func scriptedRandom(prefix []byte) func(p []byte) (int, error) {
	called := false
	return func(p []byte) (int, error) {
		if called {
			panic("scriptedRandom called more than once")
		}
		called = true
		if len(p) > len(prefix) {
			return 0, errAsRead("scripted prefix shorter than requested")
		}
		copy(p, prefix[:len(p)])
		return len(p), nil
	}
}

type errAsRead string

func (e errAsRead) Error() string { return string(e) }

// derivePublicX25519 reproduces the upstream RNS ratchet-pub derivation
// from a private scalar. Used only by tests to feed the ratchet vector.
func derivePublicX25519(priv []byte) ([]byte, error) {
	scratch := make([]byte, 32)
	copy(scratch, priv)
	scratch[0] &= 248
	scratch[31] &= 127
	scratch[31] |= 64
	return curve25519.X25519(scratch, curve25519.Basepoint)
}
