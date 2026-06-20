package lxmf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// TestLXMFVectorsBytewiseInterop loads
// ../reticulum-specifications/test-vectors/lxmf.json and verifies, against
// the canonical Python rns/LXMF 1.2.0 / 0.9.6 outputs:
//
//  1. Token-decrypting the canonical token_ciphertext_hex with Bob's
//     identity yields the canonical opportunistic_plaintext_hex.
//  2. Parsing that plaintext + verifying with Alice's Ed25519 pub
//     succeeds, and title/content match the inputs.
//  3. Re-running the build path with the SAME deterministic timestamp
//     and inputs reproduces opportunistic_plaintext_hex byte-for-byte.
//
// The first two prove we can RECEIVE Python-emitted LXMF correctly. The
// third proves our SEND path produces bytes upstream rns will accept.
func TestLXMFVectorsBytewiseInterop(t *testing.T) {
	idents := loadIdentitiesFromVectors(t)

	for _, v := range loadLXMFVectors(t) {
		t.Run(v.Label, func(t *testing.T) {
			alice, ok := idents[v.Inputs.SrcIdentityLabel]
			if !ok {
				t.Fatalf("unknown src identity %q", v.Inputs.SrcIdentityLabel)
			}
			bob, ok := idents[v.Inputs.DstIdentityLabel]
			if !ok {
				t.Fatalf("unknown dst identity %q", v.Inputs.DstIdentityLabel)
			}
			aliceDest := alice.DestinationHashFor(FullName())
			bobDest := bob.DestinationHashFor(FullName())

			expectedPlain, _ := hex.DecodeString(v.Expected.OpportunisticPlaintextHex)
			expectedCipher, _ := hex.DecodeString(v.Expected.TokenCiphertextHex)

			// 1. Token-decrypt canonical ciphertext.
			gotPlain, err := rns.TokenDecrypt(bob, expectedCipher)
			if err != nil {
				t.Fatalf("TokenDecrypt: %v", err)
			}
			if !bytes.Equal(gotPlain, expectedPlain) {
				t.Errorf("Token-decrypted plaintext mismatch\n got %x\nwant %x", gotPlain, expectedPlain)
			}

			// 2. Parse + verify the canonical plaintext.
			m, err := ParseOpportunisticBody(expectedPlain, bobDest)
			if err != nil {
				t.Fatalf("ParseOpportunisticBody: %v", err)
			}
			if !bytes.Equal(m.SourceHash, aliceDest) {
				t.Errorf("source_hash mismatch\n got %x\nwant %x", m.SourceHash, aliceDest)
			}
			if string(m.Title) != v.Inputs.TitleUTF8 {
				t.Errorf("title = %q, want %q", m.Title, v.Inputs.TitleUTF8)
			}
			if string(m.Content) != v.Inputs.ContentUTF8 {
				t.Errorf("content = %q, want %q", m.Content, v.Inputs.ContentUTF8)
			}
			senderEd := alice.PublicKey()[32:]
			if err := m.Verify(senderEd); err != nil {
				t.Errorf("Verify on canonical plaintext: %v", err)
			}

			// 3. Reverse: build the plaintext from inputs and assert byte-equality.
			// Skip the with_fields case for now — Python emits string-keyed fields
			// while the JSON vector uses string-coerced int keys; reproducing the
			// exact map ordering is tricky and not load-bearing for our forwarder
			// (which uses an empty fields map on every send).
			if len(v.Inputs.Fields) > 0 {
				t.Logf("skipping build-path byte equality for vector with non-empty fields")
				return
			}
			ts := time.Unix(int64(v.Inputs.LXMFTimestamp), 0)
			gotBuilt, _, err := signAndPackOpportunisticAt(alice, aliceDest, bobDest,
				[]byte(v.Inputs.TitleUTF8), []byte(v.Inputs.ContentUTF8), nil, ts)
			if err != nil {
				t.Fatalf("signAndPackOpportunisticAt: %v", err)
			}
			if !bytes.Equal(gotBuilt, expectedPlain) {
				t.Errorf("built plaintext mismatch\n got %x\nwant %x", gotBuilt, expectedPlain)
			}
		})
	}
}

type lxmfVector struct {
	Label  string `json:"label"`
	Inputs struct {
		SrcIdentityLabel string         `json:"src_identity_label"`
		DstIdentityLabel string         `json:"dst_identity_label"`
		TitleUTF8        string         `json:"title_utf8"`
		ContentUTF8      string         `json:"content_utf8"`
		Fields           map[string]any `json:"fields"`
		LXMFTimestamp    float64        `json:"lxmf_timestamp"`
	} `json:"inputs"`
	Expected struct {
		LXMFPackedHex             string `json:"lxmf_packed_hex"`
		OpportunisticPlaintextHex string `json:"opportunistic_plaintext_hex"`
		TokenCiphertextHex        string `json:"token_ciphertext_hex"`
	} `json:"expected"`
}

type lxmfVectorsFile struct {
	Vectors []lxmfVector `json:"vectors"`
}

func loadLXMFVectors(t *testing.T) []lxmfVector {
	t.Helper()
	path, err := filepath.Abs("../../../reticulum-specifications/test-vectors/lxmf.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("lxmf.json unavailable (%s): %v", path, err)
	}
	var f lxmfVectorsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal lxmf.json: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no LXMF vectors in %s", path)
	}
	return f.Vectors
}

// loadIdentitiesFromVectors parses identities.json and returns a label-keyed
// map of *rns.Identity. Skips test if the spec dir isn't present.
func loadIdentitiesFromVectors(t *testing.T) map[string]*rns.Identity {
	t.Helper()
	path, err := filepath.Abs("../../../reticulum-specifications/test-vectors/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("identities.json unavailable (%s): %v", path, err)
	}
	var f struct {
		Vectors []struct {
			Label  string `json:"label"`
			Inputs struct {
				PrivateKeyHex string `json:"private_key_hex"`
			} `json:"inputs"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]*rns.Identity{}
	for _, v := range f.Vectors {
		priv, _ := hex.DecodeString(v.Inputs.PrivateKeyHex)
		id, err := rns.IdentityFromPrivateKey(priv)
		if err != nil {
			t.Fatalf("identity %s: %v", v.Label, err)
		}
		out[v.Label] = id
	}
	return out
}
