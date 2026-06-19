package rns

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// --- hash math --------------------------------------------------------

func TestResourceHashMatchesSpecFormula(t *testing.T) {
	body := []byte("hello world")
	r := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	want := sha256.Sum256(append(append([]byte(nil), body...), r...))
	got := ResourceHash(body, r)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("ResourceHash mismatch:\nwant %x\ngot  %x", want, got)
	}
}

func TestResourceExpectedProofMatchesSpecFormula(t *testing.T) {
	body := []byte("payload")
	hash := sha256.Sum256([]byte("any 32-byte hash works for input"))
	want := sha256.Sum256(append(append([]byte(nil), body...), hash[:]...))
	got := ResourceExpectedProof(body, hash[:])
	if !bytes.Equal(got, want[:]) {
		t.Errorf("ResourceExpectedProof mismatch:\nwant %x\ngot  %x", want, got)
	}
}

func TestResourceMapHashIs4Bytes(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xAA}, 64)
	r := []byte{1, 2, 3, 4}
	mh := ResourceMapHash(chunk, r)
	if len(mh) != ResourceMapHashLen {
		t.Errorf("map_hash len = %d, want %d", len(mh), ResourceMapHashLen)
	}
	full := sha256.Sum256(append(append([]byte(nil), chunk...), r...))
	if !bytes.Equal(mh, full[:ResourceMapHashLen]) {
		t.Errorf("map_hash = %x, want %x (first 4 bytes of SHA256(chunk||r))", mh, full[:ResourceMapHashLen])
	}
}

func TestResourceMapHashRejectsBadRandomHashLen(t *testing.T) {
	got := ResourceMapHash([]byte("x"), []byte{1, 2, 3}) // 3 bytes, not 4
	if !bytes.Equal(got, make([]byte, ResourceMapHashLen)) {
		t.Errorf("expected zero map_hash for bad random_hash, got %x", got)
	}
}

// --- SplitParts -------------------------------------------------------

func TestSplitPartsExactSDU(t *testing.T) {
	blob := bytes.Repeat([]byte{0x42}, ResourceSDU)
	parts := SplitParts(blob)
	if len(parts) != 1 || len(parts[0]) != ResourceSDU {
		t.Errorf("len=%d parts[0]=%d, want 1 part of %d bytes", len(parts), len(parts[0]), ResourceSDU)
	}
}

func TestSplitPartsShortLastSlice(t *testing.T) {
	blob := bytes.Repeat([]byte{0x42}, ResourceSDU+10)
	parts := SplitParts(blob)
	if len(parts) != 2 {
		t.Fatalf("len=%d, want 2 parts", len(parts))
	}
	if len(parts[0]) != ResourceSDU {
		t.Errorf("parts[0] = %d, want %d", len(parts[0]), ResourceSDU)
	}
	if len(parts[1]) != 10 {
		t.Errorf("parts[1] = %d, want 10", len(parts[1]))
	}
}

func TestSplitPartsEmptyReturnsNil(t *testing.T) {
	if SplitParts(nil) != nil {
		t.Error("SplitParts(nil) should return nil")
	}
	if SplitParts([]byte{}) != nil {
		t.Error("SplitParts([]byte{}) should return nil")
	}
}

func TestSplitPartsCopiesSlices(t *testing.T) {
	blob := bytes.Repeat([]byte{0x01}, 16)
	parts := SplitParts(blob)
	parts[0][0] = 0xFF
	if blob[0] == 0xFF {
		t.Error("SplitParts must copy: mutating part[0] modified source blob")
	}
}

// --- BuildHashmap -----------------------------------------------------

func TestBuildHashmapHappyPath(t *testing.T) {
	parts := [][]byte{
		bytes.Repeat([]byte{1}, 16),
		bytes.Repeat([]byte{2}, 16),
		bytes.Repeat([]byte{3}, 16),
	}
	r := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	hm, err := BuildHashmap(parts, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(hm) != 3*ResourceMapHashLen {
		t.Errorf("hashmap len = %d, want %d", len(hm), 3*ResourceMapHashLen)
	}
	for i, p := range parts {
		want := ResourceMapHash(p, r)
		got := hm[i*ResourceMapHashLen : (i+1)*ResourceMapHashLen]
		if !bytes.Equal(got, want) {
			t.Errorf("hashmap[%d] = %x, want %x", i, got, want)
		}
	}
}

func TestBuildHashmapDetectsCollisionWithinGuardWindow(t *testing.T) {
	// Two identical-content parts within COLLISION_GUARD_SIZE → same
	// map_hash. Note WindowMaxFast is 75, HashmapMaxLen 74 — we
	// only need enough parts to fit both within the guard window.
	parts := [][]byte{
		bytes.Repeat([]byte{0x11}, 16),
		bytes.Repeat([]byte{0x22}, 16),
		bytes.Repeat([]byte{0x11}, 16), // collision with parts[0]
	}
	_, err := BuildHashmap(parts, []byte{1, 2, 3, 4})
	if !errors.Is(err, ErrResourceCollisionGuard) {
		t.Errorf("expected ErrResourceCollisionGuard, got %v", err)
	}
}

// --- RESOURCE_REQ -----------------------------------------------------

func TestResourceReqRoundTripNotExhausted(t *testing.T) {
	req := &ResourceRequest{
		ResourceHash: bytes.Repeat([]byte{0xAA}, 32),
		RequestedMap: [][]byte{
			{0x01, 0x02, 0x03, 0x04},
			{0x05, 0x06, 0x07, 0x08},
		},
	}
	body, err := BuildResourceReq(req)
	if err != nil {
		t.Fatal(err)
	}
	if body[0] != HashmapNotExhausted {
		t.Errorf("first byte = 0x%02x, want 0x%02x", body[0], HashmapNotExhausted)
	}
	parsed, err := ParseResourceReq(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Exhausted {
		t.Error("parsed should not be Exhausted")
	}
	if !bytes.Equal(parsed.ResourceHash, req.ResourceHash) {
		t.Errorf("resource_hash mismatch")
	}
	if len(parsed.RequestedMap) != 2 {
		t.Fatalf("requested_map len = %d, want 2", len(parsed.RequestedMap))
	}
	if !bytes.Equal(parsed.RequestedMap[0], req.RequestedMap[0]) {
		t.Errorf("requested_map[0] mismatch")
	}
}

func TestResourceReqRoundTripExhausted(t *testing.T) {
	req := &ResourceRequest{
		Exhausted:    true,
		LastMapHash:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		ResourceHash: bytes.Repeat([]byte{0xBB}, 32),
	}
	body, err := BuildResourceReq(req)
	if err != nil {
		t.Fatal(err)
	}
	if body[0] != HashmapExhausted {
		t.Errorf("first byte = 0x%02x, want 0x%02x", body[0], HashmapExhausted)
	}
	parsed, err := ParseResourceReq(body)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Exhausted {
		t.Error("parsed should be Exhausted")
	}
	if !bytes.Equal(parsed.LastMapHash, req.LastMapHash) {
		t.Errorf("last_map_hash mismatch: got %x, want %x", parsed.LastMapHash, req.LastMapHash)
	}
}

func TestResourceReqRejectsBadFlag(t *testing.T) {
	body := append([]byte{0x42}, bytes.Repeat([]byte{0}, 32)...)
	if _, err := ParseResourceReq(body); err == nil {
		t.Error("expected error for unknown exhausted flag")
	}
}

func TestResourceReqRejectsTooShort(t *testing.T) {
	if _, err := ParseResourceReq([]byte{HashmapNotExhausted}); err == nil {
		t.Error("expected error for body shorter than min length")
	}
}

// --- RESOURCE_HMU -----------------------------------------------------

func TestResourceHmuRoundTrip(t *testing.T) {
	h := &ResourceHmu{
		ResourceHash: bytes.Repeat([]byte{0xCC}, 32),
		SegmentIndex: 2,
		HashmapBytes: bytes.Repeat([]byte{0x77}, 8),
	}
	body, err := BuildResourceHmu(h)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResourceHmu(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SegmentIndex != h.SegmentIndex {
		t.Errorf("segment_index = %d, want %d", parsed.SegmentIndex, h.SegmentIndex)
	}
	if !bytes.Equal(parsed.ResourceHash, h.ResourceHash) {
		t.Errorf("resource_hash mismatch")
	}
	if !bytes.Equal(parsed.HashmapBytes, h.HashmapBytes) {
		t.Errorf("hashmap bytes mismatch")
	}
}

// --- RESOURCE_PRF -----------------------------------------------------

func TestResourceProofRoundTrip(t *testing.T) {
	p := &ResourceProof{
		ResourceHash: bytes.Repeat([]byte{0xDD}, 32),
		FullProof:    bytes.Repeat([]byte{0xEE}, 32),
	}
	body, err := BuildResourceProof(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 64 {
		t.Errorf("proof body len = %d, want 64", len(body))
	}
	parsed, err := ParseResourceProof(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.ResourceHash, p.ResourceHash) || !bytes.Equal(parsed.FullProof, p.FullProof) {
		t.Errorf("round-trip mismatch")
	}
}

func TestResourceProofRejectsBadLen(t *testing.T) {
	if _, err := ParseResourceProof(make([]byte, 63)); err == nil {
		t.Error("expected error for 63-byte body")
	}
	if _, err := ParseResourceProof(make([]byte, 65)); err == nil {
		t.Error("expected error for 65-byte body")
	}
}

// --- RESOURCE_ICL / RESOURCE_RCL -------------------------------------

func TestResourceCancelRoundTrip(t *testing.T) {
	rh := bytes.Repeat([]byte{0xFF}, 32)
	body, err := BuildResourceCancel(rh)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResourceCancel(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, rh) {
		t.Errorf("resource_hash mismatch")
	}
}

// --- RESOURCE_ADV -----------------------------------------------------

func TestResourceAdvRoundTrip(t *testing.T) {
	hash := bytes.Repeat([]byte{0x11}, 32)
	hashmap := bytes.Repeat([]byte{0x22}, 4*3) // 3 parts × 4 bytes each
	adv := &ResourceAdvertisement{
		TransferSize:  544,
		DataSize:      484,
		NumParts:      3,
		Hash:          hash,
		RandomHash:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
		OriginalHash:  hash,
		SegmentIndex:  1,
		TotalSegments: 1,
		Flags:         int(ResourceFlagEncrypted),
		Hashmap:       hashmap,
	}
	body, err := PackResourceAdv(adv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResourceAdv(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TransferSize != adv.TransferSize {
		t.Errorf("t=%d, want %d", parsed.TransferSize, adv.TransferSize)
	}
	if parsed.NumParts != adv.NumParts {
		t.Errorf("n=%d, want %d", parsed.NumParts, adv.NumParts)
	}
	if !bytes.Equal(parsed.Hash, adv.Hash) {
		t.Errorf("hash mismatch")
	}
	if !parsed.HasFlag(ResourceFlagEncrypted) {
		t.Errorf("encrypted flag not set after round-trip")
	}
}

func TestResourceAdvRejectsOversize(t *testing.T) {
	adv := minimalValidAdv(t)
	adv.TransferSize = MaxAcceptedResourceSize + 1
	body, err := PackResourceAdv(adv)
	if err != nil {
		// PackResourceAdv has no t-cap (sender is trusted); rebuild
		// the body by hand if the pack helper rejected.
		t.Fatal(err)
	}
	_, err = ParseResourceAdv(body)
	if !errors.Is(err, ErrResourceTooLarge) {
		t.Errorf("expected ErrResourceTooLarge, got %v", err)
	}
}

func TestResourceAdvRejectsTooManyParts(t *testing.T) {
	// Build the wire body manually to bypass the sender-side
	// HashmapMaxLen guard in PackResourceAdv. The receiver MUST
	// reject independently — a malicious sender shouldn't be able
	// to bypass our cap by encoding without our packer.
	bigCount := MaxAcceptedResourceParts + 1
	adv := &ResourceAdvertisement{
		TransferSize:  100,
		DataSize:      100,
		NumParts:      bigCount,
		Hash:          bytes.Repeat([]byte{0x01}, 32),
		RandomHash:    []byte{1, 2, 3, 4},
		OriginalHash:  bytes.Repeat([]byte{0x01}, 32),
		SegmentIndex:  1,
		TotalSegments: 1,
		Flags:         int(ResourceFlagEncrypted),
		Hashmap:       bytes.Repeat([]byte{0xAA}, 4), // 1 map_hash; rest would arrive via HMU
	}
	// Use msgpack directly to skip our packer's sanity checks.
	body, err := msgpackMarshalAdvForTest(adv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseResourceAdv(body)
	if !errors.Is(err, ErrResourceTooManyParts) {
		t.Errorf("expected ErrResourceTooManyParts for n=%d, got %v", bigCount, err)
	}
}

func TestResourceAdvRejectsBadHashLen(t *testing.T) {
	adv := minimalValidAdv(t)
	adv.Hash = bytes.Repeat([]byte{0xAA}, 31) // wrong length
	body, err := msgpackMarshalAdvForTest(adv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseResourceAdv(body)
	if err == nil || !strings.Contains(err.Error(), "hash len") {
		t.Errorf("expected hash-len error, got %v", err)
	}
}

func TestResourceAdvRejectsHashmapNotMultipleOfMapHash(t *testing.T) {
	adv := minimalValidAdv(t)
	adv.Hashmap = bytes.Repeat([]byte{0xAA}, 7) // 7 not divisible by 4
	body, err := msgpackMarshalAdvForTest(adv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseResourceAdv(body)
	if err == nil || !strings.Contains(err.Error(), "MAPHASH_LEN") {
		t.Errorf("expected MAPHASH_LEN-aligned error, got %v", err)
	}
}

// TestParseResourceAdvRejectsMetadataFlag guards the SPEC §10.2.1 metadata
// (x=1) reject: fwdsvc doesn't strip the `uint24-len ‖ msgpack` metadata
// prefix, so accepting x=1 would feed it to the LXMF parser as body. Reject
// up front rather than silently mis-deliver.
func TestParseResourceAdvRejectsMetadataFlag(t *testing.T) {
	adv := minimalValidAdv(t)
	adv.Flags |= int(ResourceFlagHasMetadata) // x=1
	body, err := msgpackMarshalAdvForTest(adv) // bypass sender-side validation
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResourceAdv(body); !errors.Is(err, ErrResourceADVMalformed) {
		t.Errorf("x=1 ADV: got err=%v, want wrap of ErrResourceADVMalformed", err)
	}
}

// --- helpers ---------------------------------------------------------

func minimalValidAdv(t *testing.T) *ResourceAdvertisement {
	t.Helper()
	hash := bytes.Repeat([]byte{0xAA}, 32)
	return &ResourceAdvertisement{
		TransferSize:  100,
		DataSize:      100,
		NumParts:      1,
		Hash:          hash,
		RandomHash:    []byte{1, 2, 3, 4},
		OriginalHash:  hash,
		SegmentIndex:  1,
		TotalSegments: 1,
		Flags:         int(ResourceFlagEncrypted),
		Hashmap:       bytes.Repeat([]byte{0xCC}, 4),
	}
}

// msgpackMarshalAdvForTest bypasses PackResourceAdv's sender-side
// validation so receiver-side rejection paths can be tested with
// inputs that the legitimate sender wouldn't produce.
func msgpackMarshalAdvForTest(adv *ResourceAdvertisement) ([]byte, error) {
	return msgpack.Marshal(adv)
}
