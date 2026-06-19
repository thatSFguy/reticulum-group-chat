package rns

import (
	"encoding/hex"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// RESOURCE_ADV (SPEC §10.4) wire format. Body is a msgpack map with
// these keys; the receiver decodes and decides whether to accept.
//
// Per upstream `RNS/Resource.py:1336-1358 (ResourceAdvertisement.pack)`,
// the keys are short single-character strings — fwdsvc must marshal
// the same way for byte-identical wire output.

// ResourceAdvertisement is the parsed view of a RESOURCE_ADV body.
// Field comments cite the SPEC §10.4 column they implement; the
// short msgpack tag matches the upstream wire key.
type ResourceAdvertisement struct {
	TransferSize  int    `msgpack:"t"` // wire byte length (encrypted)
	DataSize      int    `msgpack:"d"` // original plaintext byte length
	NumParts      int    `msgpack:"n"` // parts in THIS segment
	Hash          []byte `msgpack:"h"` // SHA256(plaintext_body || r)
	RandomHash    []byte `msgpack:"r"` // 4-byte salt for hash + map_hash
	OriginalHash  []byte `msgpack:"o"` // first segment's h (= h if single-segment)
	SegmentIndex  int    `msgpack:"i"` // 1-based
	TotalSegments int    `msgpack:"l"`
	RequestID     []byte `msgpack:"q"` // 16 bytes if this Resource carries a Link REQUEST/RESPONSE body, else nil
	Flags         int    `msgpack:"f"` // see ResourceFlag* constants
	Hashmap       []byte `msgpack:"m"` // concat of map_hashes for this segment, capped at HashmapMaxLen entries
}

// HasFlag tests one bit position from the f field.
func (a *ResourceAdvertisement) HasFlag(bit byte) bool {
	return a.Flags&int(bit) != 0
}

// MapHashAt returns the i-th 4-byte map_hash from the embedded
// hashmap fragment, or nil if i is out of range. Cheap accessor that
// keeps callers from doing the slice math themselves and miscomputing
// boundaries.
func (a *ResourceAdvertisement) MapHashAt(i int) []byte {
	off := i * ResourceMapHashLen
	if off+ResourceMapHashLen > len(a.Hashmap) {
		return nil
	}
	return a.Hashmap[off : off+ResourceMapHashLen]
}

// PackResourceAdv msgpack-encodes the advertisement for use as the
// body of a Link DATA packet with context = RESOURCE_ADV. Validates
// field consistency before encoding so callers can't ship a half-
// constructed ADV.
//
// adv.Hashmap MUST hold the FULL hashmap (NumParts map_hashes). When
// NumParts exceeds HashmapMaxLen the whole hashmap can't fit one
// advertisement packet, so only the first segment (HashmapMaxLen
// entries) is placed on the wire; the receiver pulls the rest on
// demand via RESOURCE_HMU (SPEC §10.7). Mirrors upstream
// ResourceAdvertisement.pack(segment=0).
func PackResourceAdv(adv *ResourceAdvertisement) ([]byte, error) {
	if adv == nil {
		return nil, fmt.Errorf("resource adv: nil")
	}
	if len(adv.Hash) != 32 {
		return nil, fmt.Errorf("resource adv: hash must be 32 bytes, got %d", len(adv.Hash))
	}
	if len(adv.RandomHash) != ResourceRandomHashSize {
		return nil, fmt.Errorf("resource adv: random_hash must be %d bytes, got %d", ResourceRandomHashSize, len(adv.RandomHash))
	}
	if len(adv.OriginalHash) != 32 {
		return nil, fmt.Errorf("resource adv: original_hash must be 32 bytes, got %d", len(adv.OriginalHash))
	}
	if adv.NumParts <= 0 {
		return nil, fmt.Errorf("resource adv: n must be positive, got %d", adv.NumParts)
	}
	expectedHashmapBytes := adv.NumParts * ResourceMapHashLen
	if len(adv.Hashmap) != expectedHashmapBytes {
		return nil, fmt.Errorf("resource adv: hashmap = %d bytes, expected full %d (n=%d × MAPHASH_LEN=%d)",
			len(adv.Hashmap), expectedHashmapBytes, adv.NumParts, ResourceMapHashLen)
	}
	if adv.SegmentIndex <= 0 || adv.SegmentIndex > adv.TotalSegments {
		return nil, fmt.Errorf("resource adv: bad segment_index=%d / total_segments=%d", adv.SegmentIndex, adv.TotalSegments)
	}
	// Emit only the first hashmap segment on the wire; HMU delivers
	// the rest. wire is a shallow copy so the caller's full hashmap is
	// left intact (the sender keeps it to serve HMU + part requests).
	seg0Parts := adv.NumParts
	if seg0Parts > HashmapMaxLen {
		seg0Parts = HashmapMaxLen
	}
	wire := *adv
	wire.Hashmap = adv.Hashmap[:seg0Parts*ResourceMapHashLen]
	return msgpack.Marshal(&wire)
}

// ParseResourceAdv decodes an inbound RESOURCE_ADV body and applies
// receiver-side validation: caps the advertised sizes, confirms the
// hashmap length matches `n`, rejects malformed segment indexing.
//
// Returns a parsed advertisement on success, or one of:
//   - ErrResourceADVMalformed for any decode / consistency error
//   - ErrResourceTooLarge if `t` or `d` exceed MaxAcceptedResourceSize
//   - ErrResourceTooManyParts if `n` exceeds MaxAcceptedResourceParts
//
// These errors are the spec-recommended early rejection point per the
// SPEC §10.4 security callout — they protect the receiver from
// allocation bombs BEFORE we call ResourceReceiver.Open().
func ParseResourceAdv(body []byte) (*ResourceAdvertisement, error) {
	var adv ResourceAdvertisement
	if err := msgpack.Unmarshal(body, &adv); err != nil {
		return nil, fmt.Errorf("%w: msgpack: %v", ErrResourceADVMalformed, err)
	}
	if len(adv.Hash) != 32 {
		return nil, fmt.Errorf("%w: hash len = %d, want 32", ErrResourceADVMalformed, len(adv.Hash))
	}
	if len(adv.RandomHash) != ResourceRandomHashSize {
		return nil, fmt.Errorf("%w: random_hash len = %d, want %d", ErrResourceADVMalformed, len(adv.RandomHash), ResourceRandomHashSize)
	}
	if len(adv.OriginalHash) != 32 {
		return nil, fmt.Errorf("%w: original_hash len = %d, want 32", ErrResourceADVMalformed, len(adv.OriginalHash))
	}
	if adv.NumParts <= 0 {
		return nil, fmt.Errorf("%w: n=%d non-positive", ErrResourceADVMalformed, adv.NumParts)
	}
	if adv.SegmentIndex <= 0 || adv.SegmentIndex > adv.TotalSegments || adv.TotalSegments <= 0 {
		return nil, fmt.Errorf("%w: segment %d / %d invalid", ErrResourceADVMalformed, adv.SegmentIndex, adv.TotalSegments)
	}
	if adv.TransferSize <= 0 || adv.DataSize <= 0 {
		return nil, fmt.Errorf("%w: t=%d d=%d", ErrResourceADVMalformed, adv.TransferSize, adv.DataSize)
	}
	expectedHashmapBytes := adv.NumParts * ResourceMapHashLen
	if len(adv.Hashmap) != expectedHashmapBytes {
		// In the multi-hashmap (HMU) case, an ADV's m may legally
		// be SHORTER than n*MAPHASH_LEN — the rest comes via
		// RESOURCE_HMU. Only reject when m is clearly inconsistent
		// (longer than n claims, or zero with n>0).
		if len(adv.Hashmap) == 0 {
			return nil, fmt.Errorf("%w: hashmap empty, want at least one map_hash for n=%d", ErrResourceADVMalformed, adv.NumParts)
		}
		if len(adv.Hashmap) > expectedHashmapBytes {
			return nil, fmt.Errorf("%w: hashmap %d bytes > n*MAPHASH_LEN=%d",
				ErrResourceADVMalformed, len(adv.Hashmap), expectedHashmapBytes)
		}
		if len(adv.Hashmap)%ResourceMapHashLen != 0 {
			return nil, fmt.Errorf("%w: hashmap %d bytes not multiple of MAPHASH_LEN=%d",
				ErrResourceADVMalformed, len(adv.Hashmap), ResourceMapHashLen)
		}
	}
	if adv.RequestID != nil && len(adv.RequestID) != 16 {
		return nil, fmt.Errorf("%w: request_id len = %d, want 0 or 16", ErrResourceADVMalformed, len(adv.RequestID))
	}

	// Apply receiver caps AFTER structural validation. Order matters:
	// a malformed ADV should report the structural error, not "too
	// large" — easier to debug interop issues that way.
	//
	// fwdsvc reassembles only single-segment resources. A body larger
	// than MaxEfficientSize is split by RNS into l>1 segments (§10.11);
	// accepting one segment of such a transfer would hand a truncated
	// body to the LXMF parser. Reject the whole transfer up front.
	if adv.TotalSegments > 1 {
		return nil, fmt.Errorf("%w: multi-segment resource (l=%d) — fwdsvc accepts single-segment only",
			ErrResourceTooLarge, adv.TotalSegments)
	}
	if adv.TransferSize > MaxAcceptedResourceSize || adv.DataSize > MaxAcceptedResourceSize {
		return nil, fmt.Errorf("%w: t=%d d=%d cap=%d hash=%s",
			ErrResourceTooLarge, adv.TransferSize, adv.DataSize, MaxAcceptedResourceSize, hex.EncodeToString(adv.Hash[:8]))
	}
	if adv.NumParts > MaxAcceptedResourceParts {
		return nil, fmt.Errorf("%w: n=%d cap=%d", ErrResourceTooManyParts, adv.NumParts, MaxAcceptedResourceParts)
	}
	// Reject compressed resources. fwdsvc never sends c=1 (we never
	// produce inbound bodies large enough to benefit from bz2), and
	// accepting c=1 means inviting bz2 decompression-bomb attacks
	// per the SPEC §10.4 callout. A 256 KiB encrypted body that bz2-
	// expands to 100 MiB would OOM the daemon. Rejecting outright is
	// the most defensive posture; if a real use case for inbound
	// compressed Resources appears, add bounded
	// bz2.NewReader(io.LimitReader(...)) decompression in assemble
	// and verify post-decompress size against MaxDecompressedResourceLen.
	if adv.Flags&int(ResourceFlagCompressed) != 0 {
		return nil, fmt.Errorf("%w: compressed (c=1) resources rejected — fwdsvc has no use case + bz2 decompression-bomb risk",
			ErrResourceTooLarge)
	}
	// Reject metadata-bearing resources (x=1, SPEC §10.2.1). fwdsvc never
	// sets x, and it does NOT strip the leading `uint24-len ‖ msgpack`
	// metadata prefix on receive — accepting x=1 would hand that prefix to
	// the LXMF parser as if it were body content (the §10.8 hash still
	// passes, since it covers plaintext-including-metadata), silently
	// corrupting the parse. Reject up front rather than mis-deliver.
	if adv.Flags&int(ResourceFlagHasMetadata) != 0 {
		return nil, fmt.Errorf("%w: metadata (x=1) resources rejected — fwdsvc does not strip the §10.2.1 metadata prefix",
			ErrResourceADVMalformed)
	}
	return &adv, nil
}
