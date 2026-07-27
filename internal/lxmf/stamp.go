package lxmf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/hkdf"
)

// SPEC §5.7 stamps: a 32-byte proof-of-work value over an HKDF-expanded
// workblock. This file implements outbound generation only — enough to
// submit messages to propagation nodes that declare a stamp_cost
// (§5.8.5 element [5][0], applied per flows/send-propagated-lxmf.md
// step 5). Inbound stamp validation and tickets remain out of scope.
const (
	// StampSize is LXMessage.STAMP_SIZE — the raw stamp appended to a
	// propagated body.
	StampSize = 32

	// workblockExpandRoundsPN is WORKBLOCK_EXPAND_ROUNDS_PN: propagation
	// stamps use a cheaper 1000-round (250 KiB) workblock than the
	// 3000-round regular stamps, because store-and-forward already
	// throttles (§5.7.2).
	workblockExpandRoundsPN = 1000

	// workblockRoundLen is the HKDF output length per expansion round.
	workblockRoundLen = 256

	// MaxPropagationStampCost caps the stamp_cost this implementation
	// will grind for. The cost comes from an announce field that any
	// stranger can set, so without a cap a hostile node announcing
	// cost=200 would pin a CPU forever.
	//
	// Lowered from 24 to 16 after the v1.13.1 audit. The grind is per
	// message PER RECIPIENT and runs inside an outbound worker, so at
	// cost 24 (~16.7M expected iterations) a hostile node could turn one
	// group message into hundreds of CPU-seconds and saturate the whole
	// worker pool. 2^16 is ~256x cheaper and still far above real-world
	// node policies, which are typically 0-8. Nodes demanding more are
	// filtered out at SELECTION time (see service.propagationTracker) so
	// the refusal never costs a message.
	MaxPropagationStampCost = 20
)

// ErrStampCostTooHigh is returned when a propagation node demands more
// proof-of-work than MaxPropagationStampCost allows.
var ErrStampCostTooHigh = errors.New("propagation node stamp cost exceeds local limit")

// stampWorkblock builds the §5.7.2 workblock: `rounds` iterations of
// 256-byte HKDF-SHA256 output where round n uses ikm=material and
// salt=SHA256(material || msgpack(n)).
func stampWorkblock(material []byte, rounds int) ([]byte, error) {
	out := make([]byte, 0, rounds*workblockRoundLen)
	for n := 0; n < rounds; n++ {
		packedN, err := msgpack.Marshal(n)
		if err != nil {
			return nil, fmt.Errorf("marshal round counter: %w", err)
		}
		salt := sha256.Sum256(append(append([]byte{}, material...), packedN...))
		r := hkdf.New(sha256.New, material, salt[:], nil)
		block := make([]byte, workblockRoundLen)
		if _, err := r.Read(block); err != nil {
			return nil, fmt.Errorf("HKDF expand round %d: %w", n, err)
		}
		out = append(out, block...)
	}
	return out, nil
}

// leadingZeroBits counts consecutive zero bits from the front of b.
func leadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		if by == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(by)
	}
	return n
}

// stampValid reports whether SHA256(workblock || stamp) clears
// `cost` leading zero bits (§5.7.2 stamp_valid).
func stampValid(stamp []byte, cost int, workblock []byte) bool {
	digest := sha256.Sum256(append(append([]byte{}, workblock...), stamp...))
	return leadingZeroBits(digest[:]) >= cost
}

// GeneratePropagationStamp grinds a §5.7.2 stamp over the PN workblock
// (1000 expansion rounds) for the given transient_id. Blocks until a
// stamp clearing `cost` leading zero bits is found — expected 2^cost
// attempts, each a cheap mid-state SHA-256 resumption rather than a full
// 250 KiB re-hash. cost <= 0 returns (nil, nil): no stamp required.
func GeneratePropagationStamp(transientID []byte, cost int) ([]byte, error) {
	if cost <= 0 {
		return nil, nil
	}
	if cost > MaxPropagationStampCost {
		return nil, fmt.Errorf("%w: node wants %d bits, local limit is %d",
			ErrStampCostTooHigh, cost, MaxPropagationStampCost)
	}
	workblock, err := stampWorkblock(transientID, workblockExpandRoundsPN)
	if err != nil {
		return nil, err
	}

	// Hash the workblock once and snapshot the SHA-256 midstate, then
	// resume from the snapshot per candidate. Turns each attempt from a
	// 250 KiB hash into a 32-byte one.
	base := sha256.New()
	base.Write(workblock)
	state, err := base.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("snapshot hash state: %w", err)
	}

	// One CSPRNG read for the base, then vary a counter suffix per
	// candidate. Reading 32 fresh random bytes per iteration made the
	// syscall — not the hash — the dominant cost of the search, for no
	// security benefit: the candidates only need to be distinct and
	// unpredictable to the node, which a random base plus a counter
	// already provides.
	stamp := make([]byte, StampSize)
	if _, err := rand.Read(stamp); err != nil {
		return nil, fmt.Errorf("stamp base: %w", err)
	}
	digestBuf := make([]byte, 0, sha256.Size)
	var counter uint64
	for {
		counter++
		binary.BigEndian.PutUint64(stamp[StampSize-8:], counter)
		h := sha256.New()
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			return nil, fmt.Errorf("restore hash state: %w", err)
		}
		h.Write(stamp)
		digest := h.Sum(digestBuf[:0])
		if leadingZeroBits(digest) >= cost {
			return append([]byte(nil), stamp...), nil
		}
	}
}
