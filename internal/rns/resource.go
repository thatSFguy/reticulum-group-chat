// Package rns Resource constants and state machine — see SPEC.md §10
// (`flows/send-resource.md`, `flows/receive-resource.md`) for the full
// reference and `RNS/Resource.py` for the upstream implementation
// pinned at RNS 1.2.4.
//
// A Resource transfers a payload too large to fit in one Link DATA
// packet. fwdsvc needs this for any reply or forwarded message whose
// LXMF direct-form body exceeds Link.MDU (~431 bytes). Without
// Resource, oversized link DATA packets exceed Reticulum.MTU on any
// MTU-enforcing hop and the responder never proofs them — the failure
// mode the operator hit on /users.
//
// Wire format invariants from SPEC §10 captured as Go constants here so
// every resource_*.go file references the same values without cross-
// importing magic numbers.

package rns

import (
	"errors"
	"time"
)

// Reticulum frame budget. Mirrors RNS/Reticulum.py:92,146-148. These
// drive HASHMAP_MAX_LEN and the per-part SDU below.
const (
	ReticulumMTU             = 500
	ReticulumHeaderMaxSize   = 35 // 2+1+(TRUNCATED_HASHLENGTH/8)*2 = 2+1+32
	ReticulumHeaderMinSize   = 19 // 2+1+(TRUNCATED_HASHLENGTH/8)
	ReticulumIFACMinSize     = 1
	ReticulumTokenOverhead   = 48 // 16 IV + 32 HMAC, RNS/Cryptography/Token.py:50
	ReticulumAES128BlockSize = 16
)

// LinkMDU is the plaintext payload budget for one Link DATA packet —
// the largest body that can ride a single BuildLinkDataPacket.
// Computed identically to upstream RNS/Link.py:73:
//
//	floor((MTU - IFAC - HEADER_MIN - TOKEN_OVERHEAD) / 16) * 16 - 1
//
// = floor((500 - 1 - 19 - 48)/16)*16 - 1 = 27*16 - 1 = 431.
//
// Anything over this MUST go via Resource; anything at or under can
// (and should) ride a single Link DATA for round-trip efficiency.
const LinkMDU = (((ReticulumMTU - ReticulumIFACMinSize - ReticulumHeaderMinSize - ReticulumTokenOverhead) / ReticulumAES128BlockSize) * ReticulumAES128BlockSize) - 1

// ResourceSDU is the size of one Resource part on the wire (raw
// ciphertext slice — no per-part Token framing; the whole encrypted
// blob is sliced after one Token wrap, see SPEC §10.12). Per upstream
// `Resource.sdu = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE`.
const ResourceSDU = ReticulumMTU - ReticulumHeaderMaxSize - ReticulumIFACMinSize

// Resource wire-context constants. Map directly to RNS/Packet.py:72-78.
// Values MUST match the upstream byte-exact for interop.
const (
	ContextResource    byte = 0x01 // RESOURCE — one part of the encrypted body
	ContextResourceADV byte = 0x02 // RESOURCE_ADV — advertisement msgpack
	ContextResourceREQ byte = 0x03 // RESOURCE_REQ — receiver part request
	ContextResourceHMU byte = 0x04 // RESOURCE_HMU — hashmap continuation
	ContextResourcePRF byte = 0x05 // RESOURCE_PRF — final proof (PROOF-type packet)
	ContextResourceICL byte = 0x06 // RESOURCE_ICL — initiator cancel
	ContextResourceRCL byte = 0x07 // RESOURCE_RCL — receiver cancel/reject
)

// ResourceRandomHashSize is the per-resource salt length in bytes
// (`Resource.RANDOM_HASH_SIZE`). Used both as the leading prefix of the
// encrypted body (scaffolding only — receiver strips it without
// comparing to anything) AND as the discrete `r` field of the
// advertisement that participates in `hash`, `expected_proof`, and the
// per-part `map_hash` formula. SPEC.md §10.8 and the source-code dive
// in `flows/send-resource.md` clarify these are TWO DIFFERENT random
// calls — same length, distinct values, distinct roles.
const ResourceRandomHashSize = 4

// ResourceMapHashLen is the per-part hashmap entry length in bytes
// (`Resource.MAPHASH_LEN`). Each chunk is identified by
// `SHA256(chunk_ciphertext || advertisement.r)[:4]`.
const ResourceMapHashLen = 4

// HashmapMaxLen is the cap on map_hashes per advertisement segment.
// `floor((Link.MDU - 134) / MAPHASH_LEN)` — 134 covers msgpack ADV
// dict overhead (keys, fixed-size values). Resources with more parts
// than this need RESOURCE_HMU to deliver subsequent hashmap segments.
//
// = floor((431 - 134) / 4) = 74 parts.
const HashmapMaxLen = (LinkMDU - 134) / ResourceMapHashLen

// Sliding-window constants (SPEC §10.10, RNS/Resource.py:107-117).
// All receiver-private; not negotiated. Picked to interop cleanly with
// upstream (a Go sender ignoring window changes from the reference
// receiver still works — the receiver just paces requests).
const (
	WindowDefault       = 4
	WindowMin           = 2
	WindowMaxSlow       = 10
	WindowMaxFast       = 75
	WindowMaxVerySlow   = 4
	WindowFlexibility   = 4
	FastRateThreshold   = 10 // consecutive rounds at fast rate
	VerySlowRateThresh  = 2  // rounds at very-slow rate
)

// CollisionGuardSize is the sliding window within which map_hash
// uniqueness is enforced (SPEC §10.2 step 7). The receiver searches
// only `parts[height : height + COLLISION_GUARD_SIZE]` to disambiguate
// a part by its 4-byte map_hash, so the construction-time guard MUST
// span at least that range. WINDOW_MAX is the upper bound across all
// rate regimes — using WindowMaxFast keeps the guard valid even after
// the receiver promotes its window.
const CollisionGuardSize = 2*WindowMaxFast + HashmapMaxLen

// Watchdog timing (SPEC §10 RNS/Resource.py:108-137). Used by both
// sender (advertisement retries) and receiver (part timeouts). All
// scale with observed link RTT — the multipliers here are the upstream
// constants; the actual durations come from `link.RTT() * factor`.
const (
	MaxAdvRetries          = 4
	MaxRetries             = 16
	PartTimeoutFactor      = 4
	PartTimeoutFactorAfter = 2
	ProofTimeoutFactor     = 3
	HMUWaitFactor          = 7 // 3.5x doubled to integer for our coarser math
	SenderGraceTime        = 10 * time.Second
	WatchdogMaxSleep       = 5 * time.Second
)

// MaxEfficientSize is the multi-segment boundary
// (`Resource.MAX_EFFICIENT_SIZE`). Resources larger than this split
// into multiple segments at this boundary. fwdsvc replies are far
// below this — we never multi-segment in practice — but the constant
// matters when we receive ADVs from upstream.
const MaxEfficientSize = (1 << 20) - 1 // 1 MiB - 1

// MetadataMaxSize is the per-resource metadata cap, encoded as a
// 3-byte big-endian uint24 length prefix (SPEC §10.2 step 1). 16 MiB - 1.
const MetadataMaxSize = (1 << 24) - 1

// Receive-side caps. fwdsvc forwards LXMF DMs and group-chat messages
// including image/file attachments. A single-segment Resource tops
// out at MaxEfficientSize (1 MiB - 1) of plaintext — RNS splits
// anything larger into multiple segments (§10.11), which fwdsvc does
// not reassemble (multi-segment ADVs are rejected at parse). We
// therefore accept up to one full segment. The size cap is the
// spec-strongly-recommended guard against allocation bombs (SPEC
// §10.4 callout) and bz2-decompression bombs.
const (
	// MaxAcceptedResourceSize is the `t`/`d` reject threshold — one
	// full single-segment resource (MaxEfficientSize of plaintext)
	// plus headroom for the random-hash prefix and link-Token framing.
	MaxAcceptedResourceSize = MaxEfficientSize + 8*1024
	// MaxAcceptedResourceParts caps `n`. One segment slices into at
	// most ceil(MaxAcceptedResourceSize / ResourceSDU) parts; +4 slack.
	// Far above HashmapMaxLen (74) — anything past 74 parts has its
	// hashmap delivered segment-by-segment via RESOURCE_HMU.
	MaxAcceptedResourceParts   = MaxAcceptedResourceSize/ResourceSDU + 4
	MaxDecompressedResourceLen = MaxAcceptedResourceSize
)

// MaxConcurrentInboundResourcesPerLink caps how many distinct-hash
// resources a single link can have in-flight as inbound transfers.
// A misbehaving peer that sent a flood of distinct-hash ADVs would
// otherwise spawn one receiver goroutine per ADV (each living up to
// DefaultLinkSendTimeout = 30s) — a slow leak. Four concurrent inbound
// transfers per link is more than any legitimate workload needs.
const MaxConcurrentInboundResourcesPerLink = 4

// HashmapExhaustedFlag values (SPEC §10.5).
const (
	HashmapNotExhausted byte = 0x00
	HashmapExhausted    byte = 0xFF
)

// ResourceFlag bit positions in the ADV `f` field (SPEC §10.4).
const (
	ResourceFlagEncrypted   byte = 1 << 0 // e
	ResourceFlagCompressed  byte = 1 << 1 // c
	ResourceFlagSplit       byte = 1 << 2 // s — multi-segment
	ResourceFlagIsRequest   byte = 1 << 3 // u
	ResourceFlagIsResponse  byte = 1 << 4 // p
	ResourceFlagHasMetadata byte = 1 << 5 // x
)

// ResourceState is the lifecycle of one Resource transfer at one end.
// Names mirror the upstream `Resource.QUEUED`..`COMPLETE` enum;
// numeric values aren't on the wire so we can pick our own.
type ResourceState int

const (
	ResourceStateQueued ResourceState = iota
	ResourceStateAdvertised
	ResourceStateTransferring
	ResourceStateAwaitingProof
	ResourceStateAssembling
	ResourceStateComplete
	ResourceStateCorrupt
	ResourceStateFailed
	ResourceStateCancelled
)

func (s ResourceState) String() string {
	switch s {
	case ResourceStateQueued:
		return "queued"
	case ResourceStateAdvertised:
		return "advertised"
	case ResourceStateTransferring:
		return "transferring"
	case ResourceStateAwaitingProof:
		return "awaiting-proof"
	case ResourceStateAssembling:
		return "assembling"
	case ResourceStateComplete:
		return "complete"
	case ResourceStateCorrupt:
		return "corrupt"
	case ResourceStateFailed:
		return "failed"
	case ResourceStateCancelled:
		return "cancelled"
	}
	return "unknown"
}

// Sentinel errors surfaced from the Resource send/receive paths so
// callers can branch on outcome without string-matching.
var (
	ErrResourceTooLarge        = errors.New("resource: advertised size exceeds receiver cap")
	ErrResourceTooManyParts    = errors.New("resource: advertised part count exceeds receiver cap")
	ErrResourceADVMalformed    = errors.New("resource: malformed advertisement")
	ErrResourceHashMismatch    = errors.New("resource: assembled-data hash does not match advertisement")
	ErrResourceProofMismatch   = errors.New("resource: final proof does not match expected_proof")
	ErrResourceCancelled       = errors.New("resource: cancelled by peer")
	ErrResourceTimeout         = errors.New("resource: timed out")
	ErrResourceCollisionGuard  = errors.New("resource: hashmap collision could not be resolved after retries")
	ErrResourceLinkClosed      = errors.New("resource: link closed before transfer completed")
	ErrResourceUnknownHash     = errors.New("resource: control packet references unknown resource_hash")
)
