package lxmf

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// TestMsgpackIntEncodingMatchesPython pins the round-counter encoding
// inside stampWorkblock's salt to Python msgpack.packb output. A
// divergence here silently produces a different workblock than upstream
// LXStamper and every stamp we grind gets rejected by real nodes.
func TestMsgpackIntEncodingMatchesPython(t *testing.T) {
	cases := map[int][]byte{
		0:   {0x00},             // positive fixint
		127: {0x7f},             // fixint upper bound
		128: {0xcc, 0x80},       // uint8
		300: {0xcd, 0x01, 0x2c}, // uint16
		999: {0xcd, 0x03, 0xe7}, // max round counter for PN workblock
	}
	for n, want := range cases {
		got, err := msgpack.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("msgpack(%d) = %x, want %x (Python packb)", n, got, want)
		}
	}
}

func TestStampWorkblockShape(t *testing.T) {
	material := bytes.Repeat([]byte{0x42}, 32)
	wb, err := stampWorkblock(material, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(wb) != 3*workblockRoundLen {
		t.Fatalf("workblock length = %d, want %d", len(wb), 3*workblockRoundLen)
	}
	// Rounds must differ (each uses a distinct salt) — a repeated block
	// would mean the round counter isn't feeding the salt.
	if bytes.Equal(wb[:workblockRoundLen], wb[workblockRoundLen:2*workblockRoundLen]) {
		t.Error("rounds 0 and 1 identical; round counter not in salt")
	}
	// Deterministic: same material → same workblock.
	wb2, _ := stampWorkblock(material, 3)
	if !bytes.Equal(wb, wb2) {
		t.Error("workblock not deterministic")
	}
}

func TestGeneratePropagationStamp(t *testing.T) {
	transientID := sha256.Sum256([]byte("some lxmf_data"))

	stamp, err := GeneratePropagationStamp(transientID[:], 8)
	if err != nil {
		t.Fatalf("GeneratePropagationStamp: %v", err)
	}
	if len(stamp) != StampSize {
		t.Fatalf("stamp length = %d, want %d", len(stamp), StampSize)
	}
	wb, err := stampWorkblock(transientID[:], workblockExpandRoundsPN)
	if err != nil {
		t.Fatal(err)
	}
	if !stampValid(stamp, 8, wb) {
		t.Error("generated stamp does not validate against its own workblock")
	}
	// A random non-ground value should (overwhelmingly) not clear 8 bits.
	if stampValid(bytes.Repeat([]byte{0x01}, StampSize), 8, wb) {
		t.Error("fixed junk stamp validated — leading-zero check is broken")
	}
}

func TestGeneratePropagationStampNoCost(t *testing.T) {
	stamp, err := GeneratePropagationStamp([]byte("x"), 0)
	if err != nil || stamp != nil {
		t.Errorf("cost 0 should be (nil, nil), got (%x, %v)", stamp, err)
	}
}

func TestGeneratePropagationStampCostCap(t *testing.T) {
	_, err := GeneratePropagationStamp([]byte("x"), MaxPropagationStampCost+1)
	if !errors.Is(err, ErrStampCostTooHigh) {
		t.Errorf("err = %v, want ErrStampCostTooHigh", err)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte{0x80}, 0},
		{[]byte{0x01}, 7},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x00, 0x0f}, 12},
		{[]byte{0x00, 0x00}, 16},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.in); got != c.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", c.in, got, c.want)
		}
	}
}
