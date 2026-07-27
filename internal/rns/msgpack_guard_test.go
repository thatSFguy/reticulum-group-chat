package rns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// array32Header returns the 5-byte msgpack array32 header claiming n
// elements, with no element data following — the decoder-bomb shape.
func array32Header(n uint32) []byte {
	b := []byte{0xdd, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], n)
	return b
}

// TestMsgpackBombIsRejected is the regression test for the remote
// unauthenticated OOM. The pinned msgpack library does not enforce its
// own sliceAllocLimit (the flag test in decode_slice.go is written
// `!= 1` against a value of 8, so it is always true), and allocates
// straight from the length header. A 5-byte input therefore requests
// ~103 GB, which Go answers with an unrecoverable runtime throw.
func TestMsgpackBombIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"array32 claiming 2^32-1", array32Header(^uint32(0))},
		{"array32 claiming 5 million", array32Header(5_000_000)},
		{"array16 claiming 65535", []byte{0xdc, 0xff, 0xff}},
		{"map32 claiming 2^32-1", append([]byte{0xdf}, 0xff, 0xff, 0xff, 0xff)},
		{"map16 claiming 65535", []byte{0xde, 0xff, 0xff}},
		{"str32 claiming 4GB", []byte{0xdb, 0xff, 0xff, 0xff, 0xff}},
		{"bin32 claiming 4GB", []byte{0xc6, 0xff, 0xff, 0xff, 0xff}},
	} {
		if err := ValidateMsgpackBounds(tc.data); !errors.Is(err, ErrMsgpackMalformed) {
			t.Errorf("%s: err = %v, want ErrMsgpackMalformed", tc.name, err)
		}
	}
}

// TestMsgpackBombRejectedWithoutAllocating proves the guard runs before
// any large allocation — the whole point is that we never hand the
// header to the decoder.
func TestMsgpackBombRejectedWithoutAllocating(t *testing.T) {
	bomb := array32Header(5_000_000) // ~229 MB if it reaches the decoder

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	if err := ValidateMsgpackBounds(bomb); err == nil {
		t.Fatal("bomb accepted")
	}

	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Errorf("validation allocated %d bytes; must be ~zero", grew)
	}
}

// TestNestedMsgpackBombIsRejected covers the untyped path: a field
// value carrying a bogus array header. decodeSlice has the same
// unclamped make([]interface{}, 0, n), so nesting must be walked too.
func TestNestedMsgpackBombIsRejected(t *testing.T) {
	// fixmap(1) { 6: array32(2^32-1) }
	nested := []byte{0x81, 0x06}
	nested = append(nested, array32Header(^uint32(0))...)

	if err := ValidateMsgpackBounds(nested); !errors.Is(err, ErrMsgpackMalformed) {
		t.Fatalf("err = %v, want ErrMsgpackMalformed", err)
	}
}

func TestDeeplyNestedIsRejected(t *testing.T) {
	// MaxMsgpackDepth+1 nested single-element arrays. Each level is a
	// legitimate length, so only the depth cap catches this — the
	// decoder recurses per level.
	deep := bytes.Repeat([]byte{0x91}, MaxMsgpackDepth+2)
	deep = append(deep, 0xc0) // nil at the bottom
	if err := ValidateMsgpackBounds(deep); !errors.Is(err, ErrMsgpackMalformed) {
		t.Errorf("err = %v, want depth rejection", err)
	}
}

// TestValidMsgpackAccepted is the compatibility half: everything the
// protocol actually produces must pass untouched. Each case is
// round-tripped through the real encoder.
func TestValidMsgpackAccepted(t *testing.T) {
	cases := map[string]any{
		"lxmf payload": []any{
			1700000000.5, []byte("title"), []byte("content"),
			map[any]any{},
		},
		"payload with int-keyed fields": []any{
			1700000000.5, []byte(""), []byte("hi"),
			map[any]any{
				0x30: bytes.Repeat([]byte{0xAB}, 32),
				0x40: map[any]any{0x00: bytes.Repeat([]byte{0x01}, 32), 0x01: []byte("👍")},
			},
		},
		"image field (nested array)": []any{
			1700000000.5, []byte(""), []byte(""),
			map[any]any{6: []any{[]byte("png"), bytes.Repeat([]byte{0x89}, 512)}},
		},
		"propagation app_data": []any{
			false, int64(1700000000), true, 256, 256,
			[]any{8, 0, 0}, map[any]any{},
		},
		"announce app_data": []any{[]byte("display name"), nil},
		"empty array":       []any{},
		"empty map":         map[any]any{},
		"nil":               nil,
		"large binary":      bytes.Repeat([]byte{0x42}, 100_000),
		"negative ints":     []any{-1, -32, -1000, -70000},
		"floats":            []any{1.5, float32(2.5)},
	}
	for name, v := range cases {
		encoded, err := msgpack.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if err := ValidateMsgpackBounds(encoded); err != nil {
			t.Errorf("%s: real msgpack rejected: %v", name, err)
		}
	}
}

func TestTruncatedInputRejected(t *testing.T) {
	full, _ := msgpack.Marshal([]any{1.5, []byte("abc"), []byte("def"), map[any]any{}})
	for cut := 1; cut < len(full); cut++ {
		// Truncation must never be accepted as a complete value.
		if err := ValidateMsgpackBounds(full[:cut]); err == nil {
			t.Errorf("truncation at %d/%d accepted", cut, len(full))
		}
	}
}

func TestEmptyInputRejected(t *testing.T) {
	if err := ValidateMsgpackBounds(nil); !errors.Is(err, ErrMsgpackMalformed) {
		t.Errorf("err = %v, want ErrMsgpackMalformed", err)
	}
}

// FuzzValidateMsgpackBounds asserts the guard's core contract: anything
// it accepts must be decodable without a giant allocation, and it must
// never panic. Run with -fuzz to explore; the seed corpus runs in CI.
func FuzzValidateMsgpackBounds(f *testing.F) {
	f.Add([]byte{0xc0})
	f.Add(array32Header(^uint32(0)))
	f.Add([]byte{0x91, 0x91, 0x91, 0xc0})
	seed, _ := msgpack.Marshal([]any{1.5, []byte("t"), []byte("c"), map[any]any{}})
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := ValidateMsgpackBounds(data); err != nil {
			return // rejected: nothing further to check
		}
		// Accepted input must decode without a runaway allocation.
		// Cap the input so the test itself stays cheap.
		if len(data) > 4096 {
			return
		}
		var v any
		_ = msgpack.Unmarshal(data, &v)
	})
}
