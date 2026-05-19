package rns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceReceiver collects the parts of one inbound Resource transfer
// over an active Link, reassembles, validates, and emits the final
// proof. State machine per SPEC §10:
//
//	openResourceReceiver(ADV)
//	    ↓
//	  REQUESTING ──(parts arrive)──→ ASSEMBLING ──(hash OK)──→ COMPLETE
//	    ↓                                ↓
//	  TIMEOUT/CANCEL                  CORRUPT
//
// Lifecycle is driven by Run(ctx); inbound RESOURCE parts and HMU
// segments arrive via channels from the Transport dispatcher so
// dispatcher work never blocks on receiver state.
//
// fwdsvc itself is unlikely to receive a Resource as a relay (we
// only forward small command messages), but the receiver is needed
// for interop completeness — any LXMF DM whose direct body exceeds
// Link.MDU MUST come through this path. Without it, oversized inbound
// DMs would be RCL'd back to the sender and never delivered.

const (
	// ReceiverWindowMaxOutstanding caps how many parts the receiver
	// will request in one REQ. Conservative — upstream's WINDOW_MAX
	// scales by observed throughput; we pick the slow-rate cap as a
	// universal safe value. Stage 5 may add adaptive scaling.
	ReceiverWindowMaxOutstanding = WindowMaxSlow
)

// ResourceReceiver owns the per-resource state and the goroutine that
// drives reassembly. One receiver per inbound resource per Link. A
// completed receiver (success or failure) MUST unregister itself
// from the LinkManager so a dead transfer doesn't keep its slot.
type ResourceReceiver struct {
	transport *Transport
	link      *Link
	logger    Logger

	// Identification — captured from the ADV, immutable after.
	resourceHash    []byte
	randomR         []byte
	expectedSize    int
	dataSize        int
	flags           int
	multihopID      []byte

	linkSigning    []byte
	linkEncryption []byte

	// Hashmap is the concatenated map_hashes from the ADV. Receiver
	// scans this to find the slot for an inbound part by computing
	// SHA256(part || randomR)[:4] and matching.
	hashmap []byte

	// hashmapKnownPrefix tracks how many leading map_hashes of `parts`
	// we have a hashmap entry for. Starts at min(numParts, len(adv.m)/4).
	// Grows as RESOURCE_HMU segments arrive. While < len(parts) we
	// only request parts in [0, hashmapKnownPrefix) and keep an eye
	// out for the next segment via the Exhausted REQ flag.
	hashmapKnownPrefix int

	// parts[i] = ciphertext slice for part i (nil until received).
	// Indexed by hashmap position (0-based).
	parts         [][]byte
	receivedCount int
	receivedFlags []bool // parts[i] arrived?

	// Channels: dispatcher → receiver goroutine.
	partCh   chan []byte
	hmuCh    chan *ResourceHmu
	cancelCh chan struct{}

	state atomic.Int32
	done  chan struct{}

	// pendingTarget is the receivedCount value at which the current
	// outstanding REQ window is fully satisfied. The receive loop only
	// issues the NEXT window once receivedCount reaches it — without
	// this, a fresh 10-part REQ would fire after every single placed
	// part, amplifying sender traffic ~6x and congesting the path
	// (the bug that stalled inbound image transfers at ~18/30 parts).
	pendingTarget int

	// consecutiveHeight is the highest index H such that parts[0..H]
	// have all been received (-1 until part 0 arrives). placePart
	// anchors its bounded-window map_hash search here — map_hashes are
	// only guaranteed unique within CollisionGuardSize of each other,
	// so a whole-hashmap scan could mis-place a part on a large
	// transfer where two distant parts collide on their 4-byte hash.
	consecutiveHeight int

	mu sync.Mutex // guards parts / receivedFlags / receivedCount / pendingTarget / consecutiveHeight

	// OnAssembled is called from the receiver goroutine with the
	// fully-assembled, decrypted, prefix-stripped body. Wired by the
	// caller of openResourceReceiver to plug into Delivery's normal
	// inbound-link-plaintext handler.
	OnAssembled func(body []byte)
}

// openResourceReceiver constructs a ResourceReceiver from a parsed
// ADV and starts its goroutine. Registers the receiver with the
// LinkManager so inbound parts can be routed by (link_id,
// resource_hash). Idempotency is enforced by registerResourceReceiver
// returning an error on duplicate registration.
func (t *Transport) openResourceReceiver(link *Link, adv *ResourceAdvertisement) error {
	link.mu.Lock()
	state := link.State
	signing := append([]byte(nil), link.Signing...)
	encryption := append([]byte(nil), link.Encryption...)
	cb := link.OnInboundData
	link.mu.Unlock()
	if state != LinkActive {
		return fmt.Errorf("resource receiver: link state %s, want active", state)
	}

	// Cap inbound concurrent receivers per link — defends against a
	// peer that floods us with distinct-hash ADVs, which would
	// otherwise spawn one receiver goroutine per ADV (each living up
	// to DefaultLinkSendTimeout=30s before timing out). Counting
	// happens in the LinkManager registry under its own lock.
	if existing := t.linkManager.countReceiversForLink(link.ID); existing >= MaxConcurrentInboundResourcesPerLink {
		return fmt.Errorf("resource receiver: link=%x already has %d inbound resources (cap %d)",
			link.ID[:4], existing, MaxConcurrentInboundResourcesPerLink)
	}
	// Hashmap stored full-size (numParts * MAPHASH_LEN) so HMU
	// segments can fill in the trailing parts without reallocation.
	// The known-prefix counter tracks how much is currently valid.
	fullHashmap := make([]byte, adv.NumParts*ResourceMapHashLen)
	copy(fullHashmap, adv.Hashmap)
	knownPrefix := len(adv.Hashmap) / ResourceMapHashLen
	if knownPrefix > adv.NumParts {
		knownPrefix = adv.NumParts
	}
	rr := &ResourceReceiver{
		transport:          t,
		link:               link,
		logger:             t.logger,
		resourceHash:       append([]byte(nil), adv.Hash...),
		randomR:            append([]byte(nil), adv.RandomHash...),
		expectedSize:       adv.TransferSize,
		dataSize:           adv.DataSize,
		flags:              adv.Flags,
		hashmap:            fullHashmap,
		hashmapKnownPrefix: knownPrefix,
		consecutiveHeight:  -1,
		parts:              make([][]byte, adv.NumParts),
		receivedFlags:      make([]bool, adv.NumParts),
		partCh:             make(chan []byte, 32),
		cancelCh:           make(chan struct{}, 1),
		hmuCh:              make(chan *ResourceHmu, 4),
		done:               make(chan struct{}),
		linkSigning:        signing,
		linkEncryption:     encryption,
		OnAssembled: func(body []byte) {
			if cb != nil {
				cb(body)
			}
		},
	}
	rr.state.Store(int32(ResourceStateTransferring))

	if err := t.linkManager.registerResourceReceiver(link.ID, rr.resourceHash, rr); err != nil {
		return err
	}

	// Run synchronously in a goroutine — caller (handleResourceAdv)
	// returns immediately. The goroutine's lifetime is budgeted from
	// the advertised transfer size: a small link DATA needs ~30s, but
	// a ~1 MiB image over a multi-hop mesh is minutes — a fixed 30s
	// would time the transfer out long before it completes.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), resourceTransferTimeout(adv.TransferSize))
		defer cancel()
		_ = rr.Run(ctx)
	}()
	return nil
}

// resourceTransferTimeout budgets how long one Resource transfer of
// `transferSize` wire bytes may take — a fixed base plus a
// conservative ~2 KiB/s throughput floor. A ~1 MiB transfer gets
// ~9 min; tiny transfers stay near the old 30s. Clamped so a bogus
// size can't pin a goroutine for hours. Used for both the receiver
// goroutine lifetime and the outbound SendResourceOverLink deadline.
func resourceTransferTimeout(transferSize int) time.Duration {
	const (
		base             = 30 * time.Second
		floorBytesPerSec = 2048
		maxTimeout       = 20 * time.Minute
	)
	d := base + time.Duration(transferSize/floorBytesPerSec)*time.Second
	if d > maxTimeout {
		d = maxTimeout
	}
	return d
}

// HandleCancel is invoked when the peer (initiator) sends RESOURCE_ICL
// or when CloseLink terminates the link.
func (rr *ResourceReceiver) HandleCancel() {
	select {
	case rr.cancelCh <- struct{}{}:
	default:
	}
}

// HandlePart is invoked by the Transport dispatcher when a RESOURCE
// (context = 0x01) packet arrives on the same link. The part body
// is the raw ciphertext slice; receiver matches by computing its
// 4-byte map_hash against its hashmap window.
func (rr *ResourceReceiver) HandlePart(partCiphertext []byte) {
	// An inbound part is link activity — refresh the link timer so the
	// idle sweeper doesn't tear down a long (multi-minute) transfer
	// that carries no other link DATA while it runs.
	rr.link.mu.Lock()
	rr.link.LastActivity = time.Now()
	rr.link.mu.Unlock()
	select {
	case rr.partCh <- append([]byte(nil), partCiphertext...):
	default:
		rr.logger.Printf("resource receiver: PART channel full for %s — dropping",
			ResourceHashShortHex(rr.resourceHash))
	}
}

// HandleHmu is invoked by the Transport dispatcher when a
// RESOURCE_HMU arrives carrying the next hashmap segment.
func (rr *ResourceReceiver) HandleHmu(h *ResourceHmu) {
	select {
	case rr.hmuCh <- h:
	default:
		rr.logger.Printf("resource receiver: HMU channel full for %s — dropping",
			ResourceHashShortHex(rr.resourceHash))
	}
}

// Run drives the receive state machine. Issues REQs for unreceived
// parts, processes inbound parts, and on completion validates +
// emits PRF. Returns nil on COMPLETE.
func (rr *ResourceReceiver) Run(ctx context.Context) error {
	defer close(rr.done)
	defer rr.transport.linkManager.unregisterResource(rr.link.ID, rr.resourceHash)

	// Initial request — ask for as many as fit our window.
	if err := rr.requestNextWindow(); err != nil {
		rr.logger.Printf("resource receiver: initial REQ: %v", err)
		rr.state.Store(int32(ResourceStateFailed))
		return err
	}

	// lossRecoveryInterval bounds how long the loop waits with no part
	// arriving before re-requesting the gaps. Normal completion is
	// driven by windowComplete (re-REQ fires the instant a window
	// drains); this timer only covers parts lost in flight. Kept short
	// — the old 12s value let stragglers sit long enough that a lossy
	// multi-hop path never recovered within the receiver's lifetime.
	const lossRecoveryInterval = 4 * time.Second
	timer := time.NewTimer(lossRecoveryInterval)
	defer timer.Stop()

	for rr.receivedCount < len(rr.parts) {
		select {
		case <-ctx.Done():
			rr.logger.Printf("resource receiver: timed out link=%x resource=%s — %d/%d parts received",
				rr.link.ID[:4], ResourceHashShortHex(rr.resourceHash), rr.receivedCount, len(rr.parts))
			rr.state.Store(int32(ResourceStateFailed))
			return ctx.Err()

		case <-rr.cancelCh:
			rr.logger.Printf("resource receiver: cancelled link=%x resource=%s — %d/%d parts received",
				rr.link.ID[:4], ResourceHashShortHex(rr.resourceHash), rr.receivedCount, len(rr.parts))
			rr.state.Store(int32(ResourceStateCancelled))
			return ErrResourceCancelled

		case <-timer.C:
			// No parts arrived recently — re-request the outstanding
			// gaps. The receiver's overall lifetime is bounded by the
			// caller's context, so this loops until ctx fires.
			if err := rr.requestNextWindow(); err != nil {
				rr.logger.Printf("resource receiver: re-REQ: %v", err)
			}
			timer.Reset(lossRecoveryInterval)

		case part := <-rr.partCh:
			switch err := rr.placePart(part); {
			case err == nil:
				// progress
			case errors.Is(err, errResourceDuplicatePart):
				// A retransmit of an already-placed part — normal on a
				// lossy link, not worth logging or resetting timers for.
				continue
			default:
				rr.logger.Printf("resource receiver: place part: %v", err)
				continue
			}
			// A real part landed — push the loss-recovery timer out.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(lossRecoveryInterval)

			// Request the next window only once the outstanding one has
			// fully drained — NOT after every part (see pendingTarget).
			if rr.windowComplete() && rr.receivedCount < len(rr.parts) {
				if err := rr.requestNextWindow(); err != nil {
					rr.logger.Printf("resource receiver: window REQ: %v", err)
				}
			}

		case hmu := <-rr.hmuCh:
			if err := rr.applyHmu(hmu); err != nil {
				rr.logger.Printf("resource receiver: apply HMU: %v", err)
				continue
			}
			// HMU extended our hashmap; immediately request the new
			// range.
			if err := rr.requestNextWindow(); err != nil {
				rr.logger.Printf("resource receiver: post-HMU REQ: %v", err)
			}
		}
	}

	// All parts in. Reassemble + decrypt + verify.
	rr.state.Store(int32(ResourceStateAssembling))
	body, err := rr.assemble()
	if err != nil {
		rr.state.Store(int32(ResourceStateCorrupt))
		// Politely tell the sender we can't reassemble so they don't
		// keep retransmitting on watchdog.
		if cancelErr := rr.transport.broadcastResourceCancel(rr.link, rr.resourceHash, false); cancelErr != nil {
			rr.logger.Printf("resource receiver: RCL on assemble error: %v", cancelErr)
		}
		return err
	}
	rr.state.Store(int32(ResourceStateComplete))
	rr.logger.Printf("resource receiver: complete link=%x resource=%s body=%d bytes",
		rr.link.ID[:4], ResourceHashShortHex(rr.resourceHash), len(body))

	// Emit PRF before invoking the application callback so the sender
	// gets fast confirmation even if OnAssembled is slow.
	if err := rr.broadcastProof(); err != nil {
		rr.logger.Printf("resource receiver: PRF emit: %v", err)
		// Continue to deliver the body anyway — failing PRF emit
		// just means the sender will eventually time out, but we
		// already have the body.
	}

	if rr.OnAssembled != nil {
		// Run on a goroutine to avoid blocking the receive loop's
		// teardown if the application handler is slow.
		go rr.OnAssembled(body)
	}
	return nil
}

// errResourceDuplicatePart marks a part whose map_hash matches an
// already-filled slot — a routine retransmit on a lossy link, not an
// error worth logging. placePart returns it so the receive loop can
// drop the part quietly while still surfacing genuinely unknown parts
// (a map_hash matching no slot at all).
var errResourceDuplicatePart = errors.New("resource receiver: duplicate part (retransmit)")

// placePart locates the part's hashmap slot via map_hash and drops it
// in. Returns nil when the part filled a new slot, errResourceDuplicatePart
// when it matched an already-received slot, or a plain error when its
// map_hash matches no slot in the active window.
//
// The scan is bounded to CollisionGuardSize slots anchored at the
// consecutive-completed frontier. The sender only guarantees map_hash
// uniqueness within a CollisionGuardSize sliding window (SPEC §10.2 /
// §10.6), so a whole-hashmap scan on a large transfer (thousands of
// parts) could mis-place a part when two distant parts collide on
// their 4-byte map_hash. A window of exactly CollisionGuardSize sees
// at most one match. Inbound parts always fall in this window: the
// receiver only requests parts within ~WindowMax of the frontier and
// the sender serves from the same bounded range.
func (rr *ResourceReceiver) placePart(part []byte) error {
	mh := ResourceMapHash(part, rr.randomR)
	rr.mu.Lock()
	defer rr.mu.Unlock()
	base := rr.consecutiveHeight
	if base < 0 {
		base = 0
	}
	end := base + CollisionGuardSize
	if end > rr.hashmapKnownPrefix {
		end = rr.hashmapKnownPrefix
	}
	dup := false
	for i := base; i < end; i++ {
		off := i * ResourceMapHashLen
		if !bytesEqual(rr.hashmap[off:off+ResourceMapHashLen], mh) {
			continue
		}
		if rr.receivedFlags[i] {
			dup = true
			continue
		}
		rr.parts[i] = part
		rr.receivedFlags[i] = true
		rr.receivedCount++
		// Advance the consecutive-completed frontier as far as the
		// contiguous run of received parts now reaches.
		for rr.consecutiveHeight+1 < len(rr.parts) && rr.receivedFlags[rr.consecutiveHeight+1] {
			rr.consecutiveHeight++
		}
		return nil
	}
	if dup {
		return errResourceDuplicatePart
	}
	// No match in the active window — a duplicate of a long-since-
	// completed part, or a part leaking in from another resource on
	// the same link. Either way it's safe to drop.
	return errors.New("part map_hash not in active window")
}

// windowComplete reports whether the parts requested in the most
// recent REQ window have all arrived — i.e. it is time to request the
// next window. requestNextWindow records pendingTarget as the
// receivedCount value that marks the window satisfied; until then we
// keep collecting parts without issuing redundant REQs. (The previous
// implementation returned true after any single part, which made the
// receive loop fire a fresh window-sized REQ per part — a request
// storm that congested multi-hop paths and stalled large transfers.)
func (rr *ResourceReceiver) windowComplete() bool {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.receivedCount >= rr.pendingTarget
}

// applyHmu validates an inbound RESOURCE_HMU against the receiver's
// expected next segment and extends the hashmap. SPEC §10.7: the
// segment_index is `part_index // HASHMAP_MAX_LEN` of the first new
// part — i.e. equal to the number of complete hashmap segments we
// already have (1-indexed). The provided hashmap_segment_bytes get
// copied into hashmap[segment*HashmapMaxLen*MAPHASH_LEN ... ].
//
// Rejects HMU with the wrong segment_index (sequencing error) by
// returning an error; the caller will RCL and abandon. Mirrors
// upstream Resource.py:1043-1046.
func (rr *ResourceReceiver) applyHmu(h *ResourceHmu) error {
	if !bytesEqual(h.ResourceHash, rr.resourceHash) {
		return fmt.Errorf("HMU resource_hash mismatch")
	}
	rr.mu.Lock()
	defer rr.mu.Unlock()
	expectedSegment := rr.hashmapKnownPrefix / HashmapMaxLen
	if h.SegmentIndex != expectedSegment {
		return fmt.Errorf("HMU segment_index=%d, expected %d (sequencing error)", h.SegmentIndex, expectedSegment)
	}
	wantBytes := HashmapMaxLen * ResourceMapHashLen
	// The last segment may legitimately be shorter than HashmapMaxLen
	// if numParts isn't a multiple of HashmapMaxLen.
	remainingMaxes := len(rr.parts) - rr.hashmapKnownPrefix
	if remainingMaxes < HashmapMaxLen {
		wantBytes = remainingMaxes * ResourceMapHashLen
	}
	if len(h.HashmapBytes) > wantBytes {
		return fmt.Errorf("HMU hashmap segment %d bytes > expected max %d", len(h.HashmapBytes), wantBytes)
	}
	off := rr.hashmapKnownPrefix * ResourceMapHashLen
	copy(rr.hashmap[off:], h.HashmapBytes)
	added := len(h.HashmapBytes) / ResourceMapHashLen
	rr.hashmapKnownPrefix += added
	return nil
}

// requestNextWindow builds and sends a RESOURCE_REQ for the next
// batch of unreceived map_hashes, capped at ReceiverWindowMaxOutstanding.
// Only requests parts within `hashmapKnownPrefix` — out-of-known-range
// parts must wait for an HMU first.
//
// If we've consumed all known map_hashes but more parts remain, emit
// an Exhausted REQ to prompt the sender for the next HMU segment.
func (rr *ResourceReceiver) requestNextWindow() error {
	rr.mu.Lock()
	scanLimit := rr.hashmapKnownPrefix
	requested := make([][]byte, 0, ReceiverWindowMaxOutstanding)
	for i := 0; i < scanLimit && len(requested) < ReceiverWindowMaxOutstanding; i++ {
		if rr.receivedFlags[i] {
			continue
		}
		off := i * ResourceMapHashLen
		mh := append([]byte(nil), rr.hashmap[off:off+ResourceMapHashLen]...)
		requested = append(requested, mh)
	}
	// Detect "exhausted within known prefix": every known map_hash
	// has been received, but we don't have all parts yet → ask for
	// next hashmap segment.
	allKnownReceived := true
	for i := 0; i < scanLimit; i++ {
		if !rr.receivedFlags[i] {
			allKnownReceived = false
			break
		}
	}
	exhausted := allKnownReceived && scanLimit < len(rr.parts) && scanLimit > 0
	var lastMapHash []byte
	if exhausted {
		off := (scanLimit - 1) * ResourceMapHashLen
		lastMapHash = append([]byte(nil), rr.hashmap[off:off+ResourceMapHashLen]...)
	}
	// Mark when this outstanding window will be satisfied: once
	// receivedCount climbs by len(requested), windowComplete fires and
	// the receive loop asks for the next window. Set under the lock so
	// it stays consistent with the receivedCount snapshot above.
	rr.pendingTarget = rr.receivedCount + len(requested)
	rr.mu.Unlock()
	if len(requested) == 0 && !exhausted {
		return nil
	}

	body, err := BuildResourceReq(&ResourceRequest{
		Exhausted:    exhausted,
		LastMapHash:  lastMapHash,
		ResourceHash: rr.resourceHash,
		RequestedMap: requested,
	})
	if err != nil {
		return fmt.Errorf("build REQ: %w", err)
	}
	ciphertext, err := LinkTokenEncrypt(body, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return fmt.Errorf("encrypt REQ: %w", err)
	}
	pkt, err := buildResourceCtxPacket(rr.link.ID, ciphertext, ContextResourceREQ, false)
	if err != nil {
		return err
	}
	applyMultihopRouting(pkt, rr.multihopID)
	return rr.transport.Broadcast(pkt)
}

// assemble concatenates the received parts in order, link-decrypts
// the result, strips the 4-byte body prefix, and verifies the SHA-256
// against the advertised hash. Returns the body or an error.
func (rr *ResourceReceiver) assemble() ([]byte, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	totalLen := 0
	for _, p := range rr.parts {
		totalLen += len(p)
	}
	if totalLen != rr.expectedSize {
		return nil, fmt.Errorf("%w: assembled %d bytes, ADV said %d",
			ErrResourceHashMismatch, totalLen, rr.expectedSize)
	}
	stream := make([]byte, 0, totalLen)
	for _, p := range rr.parts {
		stream = append(stream, p...)
	}
	plaintext, err := LinkTokenDecrypt(stream, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return nil, fmt.Errorf("link decrypt: %w", err)
	}
	if len(plaintext) < ResourceRandomHashSize {
		return nil, fmt.Errorf("decrypted %d bytes < prefix %d", len(plaintext), ResourceRandomHashSize)
	}
	body := plaintext[ResourceRandomHashSize:] // strip the 4-byte body prefix (SPEC §10.8 callout)

	// Belt-and-suspenders: compare actual body length to advertised.
	// dataSize is the original plaintext length per SPEC §10.4 `d`.
	if len(body) != rr.dataSize {
		return nil, fmt.Errorf("%w: body %d bytes, ADV.d said %d",
			ErrResourceHashMismatch, len(body), rr.dataSize)
	}

	// Hash check — exact match on advertised h.
	if calc := ResourceHash(body, rr.randomR); !bytesEqual(calc, rr.resourceHash) {
		return nil, ErrResourceHashMismatch
	}
	return body, nil
}

// broadcastProof emits the RESOURCE_PRF as a PROOF-type packet (NOT
// link-encrypted per SPEC §10.3).
func (rr *ResourceReceiver) broadcastProof() error {
	rr.mu.Lock()
	totalLen := 0
	for _, p := range rr.parts {
		totalLen += len(p)
	}
	stream := make([]byte, 0, totalLen)
	for _, p := range rr.parts {
		stream = append(stream, p...)
	}
	rr.mu.Unlock()

	plaintext, err := LinkTokenDecrypt(stream, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return fmt.Errorf("decrypt for PRF: %w", err)
	}
	body := plaintext[ResourceRandomHashSize:]
	fullProof := ResourceExpectedProof(body, rr.resourceHash)

	prfBody, err := BuildResourceProof(&ResourceProof{
		ResourceHash: rr.resourceHash,
		FullProof:    fullProof,
	})
	if err != nil {
		return err
	}
	pkt, err := buildResourceCtxPacket(rr.link.ID, prfBody, ContextResourcePRF, true /* PROOF type */)
	if err != nil {
		return err
	}
	applyMultihopRouting(pkt, rr.multihopID)
	return rr.transport.Broadcast(pkt)
}
