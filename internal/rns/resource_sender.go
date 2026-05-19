package rns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// ResourceSender drives one outbound Resource transfer over an active
// Link. State machine per SPEC §10:
//
//	NewResourceSender → ADVERTISED → TRANSFERRING → AWAITING_PROOF → COMPLETE
//	                       ↓                              ↓
//	                     FAILED   ←─── RESOURCE_RCL ───── CANCELLED
//
// Lifecycle is driven by Run(ctx); incoming RESOURCE_REQ / RESOURCE_PRF
// / RESOURCE_RCL packets are delivered to the sender via channels by
// the Transport dispatcher, so the dispatcher goroutine never blocks
// on Resource state work.

// ResourceSender owns the per-resource state and the goroutine that
// drives it. One sender per outbound resource per Link; concurrent
// outbound resources on the same Link are allowed but each owns its
// own ResourceSender.
type ResourceSender struct {
	transport *Transport
	link      *Link
	logger    Logger

	// Identification — set at construction, immutable after.
	resourceHash    []byte // h
	randomR         []byte // r — 4-byte salt
	bodyPrefix      []byte // 4-byte body prefix (separate random)
	expectedProof   []byte // SHA256(plaintext_body || h)
	originalLen     int    // d
	transferLen     int    // t — encrypted byte length
	parts           [][]byte // ciphertext slices per part
	hashmap         []byte   // concatenated map_hashes
	advBody         []byte   // pre-packed RESOURCE_ADV msgpack body
	multihopID      []byte   // transport_id when peer is multi-hop, nil otherwise

	// linkSigning/linkEncryption are snapshotted at construction —
	// the link's session keys at the moment the resource was built.
	// Used to encrypt outbound ADV / REQ / HMU / ICL / RCL bodies
	// (parts and PRF go raw; SPEC §10.3 + upstream Packet.pack).
	linkSigning    []byte
	linkEncryption []byte

	// Channels: dispatcher → sender goroutine. Buffered 8 to absorb a
	// burst without backpressure on the dispatcher; the sender drains
	// them on every loop iteration.
	reqCh    chan *ResourceRequest
	prfCh    chan *ResourceProof
	cancelCh chan struct{}

	// Atomic state — readable from any goroutine without locking.
	state atomic.Int32

	// Result — closed exactly once when the sender exits.
	done   chan struct{}
	resErr atomic.Value // stored error; nil for success
}

// NewResourceSender builds the resource: generates randoms, encrypts
// via the Link's session keys, splits into parts, computes the
// hashmap (with collision retries), and pre-packs the ADV body. The
// returned sender is in QUEUED state — call Run to advertise and
// fulfill the transfer.
//
// The body parameter is the FULL plaintext to be transmitted (an
// LXMF direct-form body, a NomadNet page, etc.). Caller MUST NOT
// mutate body after calling NewResourceSender.
//
// Returns ErrResourceCollisionGuard if 4 successive random_hash
// regenerations all produce hashmap collisions — vanishingly rare in
// practice (4-byte map_hashes inside a small window) but honest
// failure beats silent corruption.
//
// Multi-hop: if the link's peer is reachable only via a transit
// relay (TransportID set on the cached KnownIdentity), pass
// `transportID` so each part is routed via HEADER_2; pass nil
// otherwise.
func NewResourceSender(t *Transport, link *Link, body []byte, transportID []byte, logger Logger) (*ResourceSender, error) {
	if t == nil || link == nil {
		return nil, errors.New("resource sender: nil transport or link")
	}
	if len(body) == 0 {
		return nil, errors.New("resource sender: empty body")
	}
	if logger == nil {
		logger = noopLogger{}
	}

	// Snapshot the link's session keys under the link mutex so a
	// concurrent teardown can't race with our encryption step. The
	// Resource is link-encrypted ONCE up-front (SPEC §10.12) so we
	// don't need ongoing access to these keys after construction.
	link.mu.Lock()
	state := link.State
	signing := append([]byte(nil), link.Signing...)
	encryption := append([]byte(nil), link.Encryption...)
	linkID := append([]byte(nil), link.ID...)
	link.mu.Unlock()
	if state != LinkActive {
		return nil, fmt.Errorf("resource sender: link state is %s, want active", state)
	}

	bodyPrefix := make([]byte, ResourceRandomHashSize)
	if _, err := rand.Read(bodyPrefix); err != nil {
		return nil, fmt.Errorf("resource sender: random body-prefix: %w", err)
	}

	// Encryption pipeline (SPEC §10.2 steps 3-6, with compression off
	// — Stage 5 may opt in for large NomadNet pages, but for fwdsvc
	// LXMF replies the size doesn't justify the bz2 cost).
	clearPayload := make([]byte, 0, len(bodyPrefix)+len(body))
	clearPayload = append(clearPayload, bodyPrefix...)
	clearPayload = append(clearPayload, body...)

	wireBlob, err := LinkTokenEncrypt(clearPayload, signing, encryption)
	if err != nil {
		return nil, fmt.Errorf("resource sender: link-encrypt: %w", err)
	}

	parts := SplitParts(wireBlob)
	if len(parts) == 0 {
		return nil, errors.New("resource sender: zero parts after split (impossible — body validated non-empty)")
	}
	if len(parts) > MaxAcceptedResourceParts {
		return nil, fmt.Errorf("resource sender: %d parts exceeds single-segment cap %d (body too large to forward — multi-segment not implemented)",
			len(parts), MaxAcceptedResourceParts)
	}

	// Hashmap with collision retry. SPEC §10.2 step 7 calls for
	// regenerating randomR on collision; we cap retries at 4 to
	// prevent a pathological body from spinning forever (vanishingly
	// rare in practice — 4-byte map_hashes inside a 75-part window
	// have <1e-15 collision probability per attempt).
	const maxCollisionRetries = 4
	var (
		randomR []byte
		hashmap []byte
	)
	for retry := 0; retry < maxCollisionRetries; retry++ {
		candidate, err := NewResourceRandomHash()
		if err != nil {
			return nil, fmt.Errorf("resource sender: random_hash: %w", err)
		}
		hm, hmErr := BuildHashmap(parts, candidate)
		if hmErr == nil {
			randomR = candidate
			hashmap = hm
			break
		}
		if !errors.Is(hmErr, ErrResourceCollisionGuard) {
			return nil, fmt.Errorf("resource sender: hashmap: %w", hmErr)
		}
		// loop with a fresh random
	}
	if randomR == nil {
		return nil, ErrResourceCollisionGuard
	}

	hash := ResourceHash(body, randomR)
	expectedProof := ResourceExpectedProof(body, hash)

	advBody, err := PackResourceAdv(&ResourceAdvertisement{
		TransferSize:  len(wireBlob),
		DataSize:      len(body),
		NumParts:      len(parts),
		Hash:          hash,
		RandomHash:    randomR,
		OriginalHash:  hash,
		SegmentIndex:  1,
		TotalSegments: 1,
		Flags:         int(ResourceFlagEncrypted),
		Hashmap:       hashmap,
	})
	if err != nil {
		return nil, fmt.Errorf("resource sender: pack adv: %w", err)
	}

	rs := &ResourceSender{
		transport:        t,
		link:             link,
		logger:           logger,
		resourceHash:     hash,
		randomR:          randomR,
		bodyPrefix:       bodyPrefix,
		expectedProof:    expectedProof,
		originalLen:      len(body),
		transferLen:      len(wireBlob),
		parts:            parts,
		hashmap:          hashmap,
		advBody:          advBody,
		multihopID:       transportID,
		linkSigning:      signing,
		linkEncryption:   encryption,
		reqCh:            make(chan *ResourceRequest, 8),
		prfCh:            make(chan *ResourceProof, 1),
		cancelCh:         make(chan struct{}, 1),
		done:             make(chan struct{}),
	}
	rs.state.Store(int32(ResourceStateQueued))

	// Use linkID to dedup the goroutine-side log prefix; helps when
	// chasing multiple concurrent transfers in a single log file.
	logger.Printf("resource sender: link=%x resource=%s parts=%d t=%d d=%d",
		linkID[:4], ResourceHashShortHex(hash), len(parts), len(wireBlob), len(body))

	return rs, nil
}

// State returns the current sender state. Goroutine-safe.
func (rs *ResourceSender) State() ResourceState {
	return ResourceState(rs.state.Load())
}

// ResourceHash returns the 32-byte resource hash. Used by the link's
// resource registry to dispatch incoming REQ/PRF/RCL packets to the
// right sender by matching the resource_hash in the inbound body.
func (rs *ResourceSender) ResourceHash() []byte {
	return append([]byte(nil), rs.resourceHash...)
}

// ExpectedProof returns the pre-computed proof for inspection in
// tests; not used by senders themselves (validation is a
// constant-time compare against rs.expectedProof).
func (rs *ResourceSender) ExpectedProof() []byte {
	return append([]byte(nil), rs.expectedProof...)
}

// ParseAdvertisement re-parses our pre-packed ADV body. Useful for
// tests asserting the wire shape without exposing rs.advBody.
func (rs *ResourceSender) ParseAdvertisement() (*ResourceAdvertisement, error) {
	return ParseResourceAdv(rs.advBody)
}

// HandleRequest is invoked by the Transport dispatcher when a
// RESOURCE_REQ arrives on this link bearing this resource_hash.
// Non-blocking: drops the REQ if the sender's channel is full
// (sender will catch up on the next iteration; receiver retransmits
// per spec §10.10 watchdog).
func (rs *ResourceSender) HandleRequest(req *ResourceRequest) {
	select {
	case rs.reqCh <- req:
	default:
		rs.logger.Printf("resource sender: REQ channel full for %s — dropping", ResourceHashShortHex(rs.resourceHash))
	}
}

// HandleProof is invoked by the Transport dispatcher when a
// RESOURCE_PRF arrives on this link bearing this resource_hash.
// Non-blocking; drops on full channel (a duplicate PRF in flight
// while the sender is in cleanup is harmless).
func (rs *ResourceSender) HandleProof(prf *ResourceProof) {
	select {
	case rs.prfCh <- prf:
	default:
	}
}

// HandleCancel is invoked by the Transport dispatcher when a
// RESOURCE_RCL arrives on this link bearing this resource_hash. The
// receiver has refused or aborted; we exit with ErrResourceCancelled.
func (rs *ResourceSender) HandleCancel() {
	select {
	case rs.cancelCh <- struct{}{}:
	default:
	}
}

// Done is closed when the sender exits. After close(), Err() returns
// the final error (nil on success).
func (rs *ResourceSender) Done() <-chan struct{} { return rs.done }

// Err returns the final error after Done() closes; nil on success.
func (rs *ResourceSender) Err() error {
	if v := rs.resErr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// Run drives the resource transfer to completion. Returns when:
//   - RESOURCE_PRF received and validated → nil
//   - peer sent RESOURCE_RCL → ErrResourceCancelled
//   - context cancelled → ctx.Err()
//   - max ADV retries exhausted with no REQ → ErrResourceTimeout
//
// Caller is expected to register the sender with the LinkManager
// BEFORE calling Run so REQ/PRF arriving immediately after the ADV
// can be routed back. (NewResourceSender doesn't auto-register so
// the registration ordering is explicit at the call site.)
func (rs *ResourceSender) Run(ctx context.Context) error {
	defer close(rs.done)
	defer rs.transport.linkManager.unregisterResource(rs.link.ID, rs.resourceHash)

	// SPEC §10 ADV retransmit cadence is RTT-driven; we don't track
	// RTT yet so use a conservative fixed interval — long enough to
	// avoid spamming on a slow link, short enough that a dropped ADV
	// recovers within the LXMF retry budget. Stage 5 can plumb
	// real RTT here.
	const advTimeout = 8 * time.Second

	if err := rs.broadcastAdv(); err != nil {
		rs.fail(err)
		return err
	}
	rs.state.Store(int32(ResourceStateAdvertised))

	var (
		gotFirstReq    bool
		advRetries     int
		expectedParts  = len(rs.parts)
		deliveredParts int
	)

	advTimer := time.NewTimer(advTimeout)
	defer advTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			rs.fail(ctx.Err())
			return ctx.Err()

		case <-rs.cancelCh:
			rs.fail(ErrResourceCancelled)
			return ErrResourceCancelled

		case <-advTimer.C:
			if gotFirstReq {
				// We're past the ADV phase — the timer is only meaningful
				// before the first REQ. Reset and continue.
				advTimer.Reset(advTimeout)
				continue
			}
			advRetries++
			if advRetries > MaxAdvRetries {
				rs.fail(ErrResourceTimeout)
				return ErrResourceTimeout
			}
			rs.logger.Printf("resource sender: ADV retry %d/%d for %s",
				advRetries, MaxAdvRetries, ResourceHashShortHex(rs.resourceHash))
			if err := rs.broadcastAdv(); err != nil {
				rs.fail(err)
				return err
			}
			advTimer.Reset(advTimeout)

		case req := <-rs.reqCh:
			if !gotFirstReq {
				gotFirstReq = true
				rs.state.Store(int32(ResourceStateTransferring))
			}
			if req.Exhausted {
				// The receiver has consumed every map_hash it knows and
				// needs the next hashmap segment — answer with a
				// RESOURCE_HMU (SPEC §10.7). A sequencing error here is
				// unrecoverable, so it fails the transfer.
				if err := rs.serveHmu(req); err != nil {
					rs.logger.Printf("resource sender: serve HMU for %s: %v",
						ResourceHashShortHex(rs.resourceHash), err)
					rs.fail(err)
					return err
				}
				continue
			}
			n, err := rs.fulfillRequest(req)
			if err != nil {
				rs.fail(err)
				return err
			}
			deliveredParts += n
			if deliveredParts >= expectedParts {
				rs.state.Store(int32(ResourceStateAwaitingProof))
			}

		case prf := <-rs.prfCh:
			if !proofEqualsConstantTime(prf.FullProof, rs.expectedProof) {
				err := fmt.Errorf("%w: link=%x resource=%s",
					ErrResourceProofMismatch, rs.link.ID[:4], ResourceHashShortHex(rs.resourceHash))
				rs.fail(err)
				return err
			}
			rs.state.Store(int32(ResourceStateComplete))
			rs.logger.Printf("resource sender: complete link=%x resource=%s parts=%d",
				rs.link.ID[:4], ResourceHashShortHex(rs.resourceHash), expectedParts)
			return nil
		}
	}
}

// broadcastAdv emits the pre-packed ADV body as a Link DATA packet
// with context = RESOURCE_ADV. Body is link-Token-encrypted under the
// link's session keys (SPEC §10.3 — unlike RESOURCE part packets,
// ADV is encrypted because it must be confidential against transit
// relays even though those relays already decrypt the outer Reticulum
// frame). Multi-hop routing is applied per-packet so a re-broadcast
// after a transit-relay change still routes correctly.
func (rs *ResourceSender) broadcastAdv() error {
	ciphertext, err := LinkTokenEncrypt(rs.advBody, rs.linkSigning, rs.linkEncryption)
	if err != nil {
		return fmt.Errorf("encrypt ADV: %w", err)
	}
	pkt, err := buildResourceCtxPacket(rs.link.ID, ciphertext, ContextResourceADV, false)
	if err != nil {
		return fmt.Errorf("build ADV packet: %w", err)
	}
	// Resource ADV stays HEADER_1 even for multi-hop peers — same
	// reasoning as link DATA in transport.go SendOverLink. Setting
	// transport_id here would make the relay forward HEADER_2 to the
	// final hop, where packet_filter drops it as "for other transport
	// instance". Upstream's RNS.Packet(link, data, context=RESOURCE_ADV)
	// defaults to HEADER_1 with no transport_id — mirror that.
	if err := rs.transport.Broadcast(pkt); err != nil {
		return fmt.Errorf("broadcast ADV: %w", err)
	}
	return nil
}

// fulfillRequest emits one part packet per requested map_hash. Returns
// the count of parts actually emitted (a request for a map_hash we
// don't have is silently skipped — the receiver's collision-guard
// search bound makes such requests rare and harmless).
func (rs *ResourceSender) fulfillRequest(req *ResourceRequest) (int, error) {
	if !bytesEqual(req.ResourceHash, rs.resourceHash) {
		return 0, fmt.Errorf("REQ resource_hash %s != ours %s",
			hex.EncodeToString(req.ResourceHash[:8]), hex.EncodeToString(rs.resourceHash[:8]))
	}
	delivered := 0
	for _, mh := range req.RequestedMap {
		idx := rs.findPartByMapHash(mh)
		if idx < 0 {
			rs.logger.Printf("resource sender: REQ asks for unknown map_hash %x — skipping", mh)
			continue
		}
		pkt, err := buildResourceCtxPacket(rs.link.ID, rs.parts[idx], ContextResource, false)
		if err != nil {
			return delivered, fmt.Errorf("build PART packet idx=%d: %w", idx, err)
		}
		// Resource PART stays HEADER_1 — same reasoning as ADV above.
		if err := rs.transport.Broadcast(pkt); err != nil {
			return delivered, fmt.Errorf("broadcast PART idx=%d: %w", idx, err)
		}
		delivered++
	}
	return delivered, nil
}

// serveHmu answers an exhausted RESOURCE_REQ by sending the next
// hashmap segment as a RESOURCE_HMU packet (SPEC §10.7). The
// receiver's LastMapHash is the last map_hash it already has; the
// segment of HashmapMaxLen entries immediately after it is what we
// send. Mirrors upstream Resource.request()'s wants_more_hashmap
// branch — including the segment-boundary sequencing check.
//
// Re-serving the same segment (a duplicate exhausted REQ on a lossy
// link) is harmless: the lookup is deterministic and the receiver's
// applyHmu is idempotent.
func (rs *ResourceSender) serveHmu(req *ResourceRequest) error {
	if len(req.LastMapHash) != ResourceMapHashLen {
		return fmt.Errorf("exhausted REQ has no last_map_hash")
	}
	k := rs.findPartByMapHash(req.LastMapHash)
	if k < 0 {
		return fmt.Errorf("exhausted REQ last_map_hash %x not in hashmap", req.LastMapHash)
	}
	// The receiver knows map_hashes [0, k]; the next part index is the
	// start of the segment it still needs. It MUST land on a segment
	// boundary — otherwise the receiver and sender disagree on
	// segmentation (a protocol error).
	partIndex := k + 1
	if partIndex%HashmapMaxLen != 0 {
		return fmt.Errorf("HMU sequencing error: last_map_hash at index %d is not a segment boundary", k)
	}
	segment := partIndex / HashmapMaxLen
	start := segment * HashmapMaxLen
	end := start + HashmapMaxLen
	if end > len(rs.parts) {
		end = len(rs.parts)
	}
	if start >= end {
		return fmt.Errorf("HMU requested past end of resource: segment=%d n=%d", segment, len(rs.parts))
	}
	hmuBody, err := BuildResourceHmu(&ResourceHmu{
		ResourceHash: rs.resourceHash,
		SegmentIndex: segment,
		HashmapBytes: rs.hashmap[start*ResourceMapHashLen : end*ResourceMapHashLen],
	})
	if err != nil {
		return fmt.Errorf("build HMU: %w", err)
	}
	ciphertext, err := LinkTokenEncrypt(hmuBody, rs.linkSigning, rs.linkEncryption)
	if err != nil {
		return fmt.Errorf("encrypt HMU: %w", err)
	}
	pkt, err := buildResourceCtxPacket(rs.link.ID, ciphertext, ContextResourceHMU, false)
	if err != nil {
		return err
	}
	rs.logger.Printf("resource sender: HMU segment=%d entries=%d for %s",
		segment, end-start, ResourceHashShortHex(rs.resourceHash))
	return rs.transport.Broadcast(pkt)
}

// findPartByMapHash scans the hashmap for the requested map_hash and
// returns the part index, or -1 if not found. A 4-byte map_hash is
// unique only within a CollisionGuardSize window, so on a large
// resource a far-apart collision could return the wrong index — the
// receiver's end-to-end SHA-256 over the assembled body catches that
// (the transfer fails cleanly rather than delivering corruption).
func (rs *ResourceSender) findPartByMapHash(mh []byte) int {
	for i := 0; i < len(rs.parts); i++ {
		off := i * ResourceMapHashLen
		if bytesEqual(rs.hashmap[off:off+ResourceMapHashLen], mh) {
			return i
		}
	}
	return -1
}

// fail captures the terminal error and transitions to FAILED.
func (rs *ResourceSender) fail(err error) {
	rs.state.Store(int32(ResourceStateFailed))
	rs.resErr.Store(err)
}

// buildResourceCtxPacket wraps a body in a Link DATA (or PROOF)
// packet with the given context. Centralised so every Resource-class
// packet uses the same Reticulum framing and one place would catch
// a wire-format regression.
func buildResourceCtxPacket(linkID, body []byte, context byte, isProof bool) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("resource packet: link_id must be %d bytes", IdentityHashLen)
	}
	var pktType byte = PacketData
	if isProof {
		pktType = PacketProof
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      pktType,
		Hops:            0,
		DestHash:        append([]byte(nil), linkID...),
		Context:         context,
		Data:            append([]byte(nil), body...),
	}, nil
}

