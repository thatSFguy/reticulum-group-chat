package rns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Structural pre-validation for attacker-controlled msgpack.
//
// WHY THIS EXISTS: vmihailenco/msgpack v5.4.1 does not enforce its own
// documented `sliceAllocLimit` (1e6 elements). In decode_slice.go the
// guard reads
//
//	noLimit := d.flags&disableAllocLimitFlag != 1
//
// but disableAllocLimitFlag is 1<<3 = 8, so `flags&8` is either 0 or 8
// and the expression is ALWAYS true — the limit is never applied. Both
// the typed path (growSliceValue -> reflect.MakeSlice) and the untyped
// path (decodeSlice -> make([]interface{}, 0, n)) then allocate from
// the length header verbatim, with no reference to how many bytes are
// actually available.
//
// The practical effect: a 5-byte input `dd ff ff ff ff` (array32
// claiming 2^32-1 elements) requests ~103 GB in one allocation. Go
// answers an impossible allocation with an unrecoverable runtime throw,
// which no recover() can catch — the process dies. Measured on the
// pinned version: a 5-byte input allocates 229 MB at n=5e6.
//
// The library's DisableAllocLimit API cannot switch the broken check
// back on (both flag states satisfy `!= 1`), so the only reliable
// defense short of forking the dependency is to reject malformed input
// BEFORE the decoder sees it.
//
// The check is a single allocation-free pass that enforces one
// invariant: every declared length must be satisfiable by the bytes
// actually present. An array of N elements needs at least N more bytes
// (one per element, minimum); a map of N pairs needs at least 2N. Any
// header claiming more than the remaining input is malformed by
// construction, so rejecting it costs nothing in compatibility.

// ErrMsgpackMalformed is returned when input fails structural
// validation — a length header that the remaining bytes cannot satisfy,
// truncated input, or nesting beyond MaxMsgpackDepth.
var ErrMsgpackMalformed = errors.New("malformed msgpack")

// MaxMsgpackDepth caps container nesting. The decoder recurses per
// level, so deep nesting is a stack-exhaustion vector independent of
// the allocation bug. Real LXMF payloads nest 3 deep (payload array ->
// fields map -> field value array); 32 is far beyond any legitimate
// use.
const MaxMsgpackDepth = 32

// ValidateMsgpackBounds reports whether data is structurally plausible:
// every array/map/str/bin/ext length is satisfiable by the remaining
// bytes, nesting stays within MaxMsgpackDepth, and exactly one complete
// top-level value is present. It allocates nothing and never decodes
// values — it only walks headers.
//
// Trailing bytes after the first complete value are allowed: some LXMF
// producers pad, and the decoders we guard read a single value anyway.
func ValidateMsgpackBounds(data []byte) error {
	// stack holds the count of values still expected in each enclosing
	// container. need is the count for the innermost open container.
	stack := make([]int, 0, 8)
	need := 1 // exactly one top-level value
	i := 0

	for {
		for need == 0 {
			if len(stack) == 0 {
				return nil // top-level value complete
			}
			need = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		}
		if i >= len(data) {
			return fmt.Errorf("%w: truncated at byte %d", ErrMsgpackMalformed, i)
		}
		c := data[i]
		i++
		need--

		payload, children, isMap, err := msgpackHeader(c, data, &i)
		if err != nil {
			return err
		}

		// Length plausibility: each remaining element needs >= 1 byte,
		// each map pair >= 2. This is what makes a bogus array32 header
		// impossible to turn into a giant allocation.
		remaining := len(data) - i
		if payload > remaining {
			return fmt.Errorf("%w: declared payload %d exceeds %d remaining bytes",
				ErrMsgpackMalformed, payload, remaining)
		}
		if children > remaining {
			kind := "array"
			if isMap {
				kind = "map"
			}
			return fmt.Errorf("%w: %s declares %d values but only %d bytes remain",
				ErrMsgpackMalformed, kind, children, remaining)
		}

		if payload > 0 {
			i += payload
		}
		if children > 0 {
			if len(stack) >= MaxMsgpackDepth {
				return fmt.Errorf("%w: nesting deeper than %d", ErrMsgpackMalformed, MaxMsgpackDepth)
			}
			stack = append(stack, need)
			need = children
		}
	}
}

// msgpackHeader decodes one format byte plus its length prefix,
// advancing *i past the prefix. It returns the number of raw payload
// bytes the value occupies (strings, binary, ext) and the number of
// child VALUES it introduces (arrays: n, maps: 2n). Exactly one of the
// two is non-zero for any given type.
func msgpackHeader(c byte, data []byte, i *int) (payload, children int, isMap bool, err error) {
	readLen := func(n int) (int, error) {
		if *i+n > len(data) {
			return 0, fmt.Errorf("%w: truncated %d-byte length prefix", ErrMsgpackMalformed, n)
		}
		var v uint64
		switch n {
		case 1:
			v = uint64(data[*i])
		case 2:
			v = uint64(binary.BigEndian.Uint16(data[*i:]))
		case 4:
			v = uint64(binary.BigEndian.Uint32(data[*i:]))
		}
		*i += n
		// A length that doesn't fit in int (32-bit platforms) is
		// malformed for our purposes; the remaining-bytes check below
		// would reject it anyway, but avoid the overflow first.
		if v > uint64(maxInt) {
			return 0, fmt.Errorf("%w: length %d out of range", ErrMsgpackMalformed, v)
		}
		return int(v), nil
	}

	switch {
	case c <= 0x7f, c >= 0xe0: // positive / negative fixint
		return 0, 0, false, nil
	case c >= 0x80 && c <= 0x8f: // fixmap
		return 0, 2 * int(c&0x0f), true, nil
	case c >= 0x90 && c <= 0x9f: // fixarray
		return 0, int(c & 0x0f), false, nil
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return int(c & 0x1f), 0, false, nil
	}

	switch c {
	case 0xc0, 0xc2, 0xc3: // nil, false, true
		return 0, 0, false, nil
	case 0xc4, 0xd9: // bin8, str8
		n, e := readLen(1)
		return n, 0, false, e
	case 0xc5, 0xda: // bin16, str16
		n, e := readLen(2)
		return n, 0, false, e
	case 0xc6, 0xdb: // bin32, str32
		n, e := readLen(4)
		return n, 0, false, e
	case 0xc7: // ext8
		n, e := readLen(1)
		return n + 1, 0, false, e // +1 type byte
	case 0xc8: // ext16
		n, e := readLen(2)
		return n + 1, 0, false, e
	case 0xc9: // ext32
		n, e := readLen(4)
		return n + 1, 0, false, e
	case 0xca: // float32
		return 4, 0, false, nil
	case 0xcb: // float64
		return 8, 0, false, nil
	case 0xcc, 0xd0: // uint8, int8
		return 1, 0, false, nil
	case 0xcd, 0xd1: // uint16, int16
		return 2, 0, false, nil
	case 0xce, 0xd2: // uint32, int32
		return 4, 0, false, nil
	case 0xcf, 0xd3: // uint64, int64
		return 8, 0, false, nil
	case 0xd4: // fixext1
		return 2, 0, false, nil
	case 0xd5: // fixext2
		return 3, 0, false, nil
	case 0xd6: // fixext4
		return 5, 0, false, nil
	case 0xd7: // fixext8
		return 9, 0, false, nil
	case 0xd8: // fixext16
		return 17, 0, false, nil
	case 0xdc: // array16
		n, e := readLen(2)
		return 0, n, false, e
	case 0xdd: // array32
		n, e := readLen(4)
		return 0, n, false, e
	case 0xde: // map16
		n, e := readLen(2)
		return 0, 2 * n, true, e
	case 0xdf: // map32
		n, e := readLen(4)
		if e != nil {
			return 0, 0, true, e
		}
		if n > maxInt/2 {
			return 0, 0, true, fmt.Errorf("%w: map length %d out of range", ErrMsgpackMalformed, n)
		}
		return 0, 2 * n, true, nil
	case 0xc1: // never used
		return 0, 0, false, fmt.Errorf("%w: reserved format byte 0xc1", ErrMsgpackMalformed)
	}
	return 0, 0, false, fmt.Errorf("%w: unknown format byte 0x%02x", ErrMsgpackMalformed, c)
}

const maxInt = int(^uint(0) >> 1)
