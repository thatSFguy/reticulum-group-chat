package rns

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Link state machine — SPEC §6 (state machine itself isn't formally
// specified; modeled after upstream RNS.Link). Tracks the lifecycle of
// an established or in-progress Link between us and a peer:
//
//	Pending  : we sent a LINKREQUEST, waiting for matching LRPROOF.
//	Active   : handshake complete; can send/receive DATA on the link.
//	Closed   : torn down, never reopens with this link_id.
//
// KEEPALIVE-driven Expired/Stale states are deferred to a follow-up;
// the basic state machine here is enough for opportunistic-vs-link
// fallback in Delivery.Send (PR 3 of the link-delivery work).
//
// All public methods on Link and LinkManager are safe to call from
// multiple goroutines.

// LinkState enumerates the link lifecycle.
type LinkState int

const (
	LinkPending LinkState = iota
	LinkActive
	LinkClosed
)

func (s LinkState) String() string {
	switch s {
	case LinkPending:
		return "pending"
	case LinkActive:
		return "active"
	case LinkClosed:
		return "closed"
	}
	return fmt.Sprintf("LinkState(%d)", int(s))
}

// Link is one in-flight or established Reticulum Link.
type Link struct {
	mu sync.Mutex

	ID    []byte // 16-byte link_id (SPEC §6.3)
	State LinkState

	// Session keys derived from the handshake (SPEC §6.4). 32 bytes each;
	// signing is also used as the Ed25519 seed for link-DATA proofs.
	Signing    []byte
	Encryption []byte

	// Initiator-side state used while Pending: ephemeral X25519 priv we
	// sent in the LINKREQUEST, plus the peer destination we addressed.
	// X25519 priv is cleared once the link transitions to Active; the
	// destination hash is retained for the lifetime of the link so we
	// can route outbound DATA without re-walking caller state.
	myEphemeralX25519Priv []byte
	peerDestHash          []byte

	// initiatorEd25519Priv is the ephemeral Ed25519 private key whose
	// public half we put in the LINKREQUEST body. Per upstream RNS this
	// is what an initiator uses to sign link DATA proofs for return-
	// direction traffic (responder → initiator) — the responder verifies
	// against initiatorEd25519Pub from the LINKREQUEST. Retained for the
	// life of the link. PR2 will add the signing path that consumes this.
	initiatorEd25519Priv []byte

	// peerEd25519Pub is the long-term Ed25519 public key of the responder.
	// Captured at HandleLRProof time when we are the initiator (not on
	// the LRPROOF wire — taken from the responder's prior announce). Used
	// by Transport.handleLinkProof to verify inbound link DATA proofs
	// the responder signs to ack our outbound DATA.
	peerEd25519Pub []byte

	// pendingProofs maps hex(packet_hash) → channel that SendOverLink
	// blocks on. handleLinkProof closes the channel (with nil) on
	// successful proof verification, or sends an error on bad-sig.
	// Senders MUST register the channel BEFORE broadcasting the link
	// DATA packet to avoid losing a fast proof.
	pendingProofs map[string]chan error

	// activatedCh is closed exactly once when the initiator-side link
	// transitions Pending → Active. Lets SendOverLink block on the
	// handshake completing without polling. Nil on the responder side.
	activatedCh chan struct{}

	// Responder-side state: the responder's ephemeral X25519 priv we
	// generated to derive session keys. Cleared once Active.
	myResponderEphPriv []byte

	// responderIdentity is the local destination identity that signs
	// outbound link DATA proofs when we are the responder (per upstream
	// RNS/Link.py:279, `self.sig_prv = self.owner.identity.sig_prv` on
	// the responder side). Nil when we are the initiator. The initiator
	// peer can verify our proof signatures because it cached our
	// long-term Ed25519 pubkey when it looked us up to send the
	// LINKREQUEST.
	responderIdentity *Identity

	CreatedAt    time.Time
	LastActivity time.Time

	// OnInboundData is called from the Transport's dispatcher with each
	// successfully decrypted link DATA payload. Non-nil during Active.
	OnInboundData func(plaintext []byte)
}

// IsInitiator returns true when this Link was opened locally (we sent
// the LINKREQUEST). Initiator-side links carry initiatorEd25519Priv
// and peerEd25519Pub; responder-side links carry responderIdentity.
func (l *Link) IsInitiator() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.responderIdentity == nil && l.peerDestHash != nil
}

// PeerDestHash returns a copy of the peer's destination hash for an
// initiator-side link, or nil for a responder-side link.
func (l *Link) PeerDestHash() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peerDestHash == nil {
		return nil
	}
	out := make([]byte, len(l.peerDestHash))
	copy(out, l.peerDestHash)
	return out
}

// AwaitActive blocks until the link transitions to Active (closing
// activatedCh) or until ctx fires. Returns nil on Active, the ctx
// error otherwise. Returns immediately if the link is already Active
// or Closed.
func (l *Link) AwaitActive(ctxDone <-chan struct{}) error {
	l.mu.Lock()
	state := l.State
	ch := l.activatedCh
	l.mu.Unlock()
	switch state {
	case LinkActive:
		return nil
	case LinkClosed:
		return errors.New("link closed before activation")
	}
	if ch == nil {
		// Responder-side link or one constructed without an activatedCh.
		return errors.New("link has no activation channel")
	}
	select {
	case <-ch:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.State != LinkActive {
			return fmt.Errorf("link not Active after activation signal (state=%s)", l.State)
		}
		return nil
	case <-ctxDone:
		return errors.New("link activation cancelled")
	}
}

// registerProofWaiter atomically inserts a fresh channel keyed by
// hex(packetHash) into pendingProofs and returns the channel. The
// caller MUST call clearProofWaiter when done (typically via defer).
//
// Returning a buffered channel makes handleLinkProof's signal a
// non-blocking send so a slow waiter doesn't deadlock the dispatcher.
func (l *Link) registerProofWaiter(packetHashHex string) chan error {
	ch := make(chan error, 1)
	l.mu.Lock()
	if l.pendingProofs == nil {
		l.pendingProofs = map[string]chan error{}
	}
	l.pendingProofs[packetHashHex] = ch
	l.mu.Unlock()
	return ch
}

func (l *Link) clearProofWaiter(packetHashHex string) {
	l.mu.Lock()
	delete(l.pendingProofs, packetHashHex)
	l.mu.Unlock()
}

// signalProof is used by Transport.handleLinkProof to wake a SendOverLink
// caller. Returns true if a waiter was found (and signalled), false if
// no one was waiting on this packet_hash. err may be nil to indicate
// success or non-nil for a bad-sig / wrong-link diagnostic the caller
// can surface.
func (l *Link) signalProof(packetHashHex string, err error) bool {
	l.mu.Lock()
	ch, ok := l.pendingProofs[packetHashHex]
	if ok {
		delete(l.pendingProofs, packetHashHex)
	}
	l.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- err:
	default:
	}
	return true
}

// IsActive returns true iff State == LinkActive.
func (l *Link) IsActive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.State == LinkActive
}

// LinkManager tracks links keyed by link_id. It does not own a Transport;
// callers (Delivery / Service) wire its outbound packets through their own
// Transport.Broadcast and route inbound LINKREQUEST/LRPROOF/link-addressed
// DATA/PROOF packets through the Handle* methods.
type LinkManager struct {
	mu    sync.Mutex
	links map[string]*Link // hex link_id -> *Link

	// Optional per-link callback. The application (Delivery) sets this
	// when it wants to receive plaintext payloads from inbound link
	// DATA. Default no-op.
	defaultOnInboundData func(linkID, plaintext []byte)
}

// NewLinkManager constructs an empty manager.
func NewLinkManager() *LinkManager {
	return &LinkManager{links: map[string]*Link{}}
}

// SetDefaultInboundDataHandler sets a fallback callback used by Active
// links that don't have a per-link OnInboundData set.
func (lm *LinkManager) SetDefaultInboundDataHandler(cb func(linkID, plaintext []byte)) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.defaultOnInboundData = cb
}

// Get returns the Link with the given link_id, or nil if unknown.
func (lm *LinkManager) Get(linkID []byte) *Link {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.links[hex.EncodeToString(linkID)]
}

// Active returns the active Link (if any) toward responderDestHash.
// Useful for "do I already have a link to this peer or do I need to
// open one?". Returns nil if no active link is known.
func (lm *LinkManager) ActiveTo(responderDestHash []byte) *Link {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for _, l := range lm.links {
		l.mu.Lock()
		match := l.State == LinkActive && len(l.peerDestHash) == len(responderDestHash) &&
			bytesEqual(l.peerDestHash, responderDestHash)
		l.mu.Unlock()
		if match {
			return l
		}
	}
	return nil
}

// StartLinkAsInitiator generates an ephemeral X25519 + Ed25519 keypair
// and returns:
//
//	link    -- a *Link in the Pending state (registered in the manager)
//	request -- the LINKREQUEST packet to broadcast on the wire.
//
// The caller is responsible for transmitting `request`. When the
// matching LRPROOF arrives, hand it to HandleLRProof to transition the
// link to Active.
func (lm *LinkManager) StartLinkAsInitiator(responderDestHash []byte, sig *LinkSignalling) (*Link, *Packet, error) {
	if len(responderDestHash) != IdentityHashLen {
		return nil, nil, fmt.Errorf("responder dest_hash must be %d bytes", IdentityHashLen)
	}

	ephPriv, ephPub, err := newClampedX25519()
	if err != nil {
		return nil, nil, err
	}
	// Initiator's ephemeral Ed25519 (per SPEC §6.1, both ephemerals are
	// fresh — they are NOT the long-term identity keys). Per upstream
	// RNS the initiator uses this priv to sign link DATA proofs for
	// return-direction traffic; the responder verifies against the pub
	// bytes carried in the LINKREQUEST. We retain the priv on the Link
	// for that purpose (PR2 wires the actual signing path).
	var ephEd25519Seed [32]byte
	if _, err := rand.Read(ephEd25519Seed[:]); err != nil {
		return nil, nil, fmt.Errorf("Ed25519 seed entropy: %w", err)
	}
	ephID, err := identityFromHalves([32]byte(ephPriv), ephEd25519Seed)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ephemeral identity: %w", err)
	}
	ephEd25519Priv := ed25519.NewKeyFromSeed(ephEd25519Seed[:])

	pkt, err := BuildLinkRequest(ephPub, ephID.PublicKey()[32:], responderDestHash, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("BuildLinkRequest: %w", err)
	}
	id, err := LinkID(pkt)
	if err != nil {
		return nil, nil, fmt.Errorf("LinkID: %w", err)
	}

	l := &Link{
		ID:                    id,
		State:                 LinkPending,
		myEphemeralX25519Priv: ephPriv,
		initiatorEd25519Priv:  ephEd25519Priv,
		peerDestHash:          append([]byte(nil), responderDestHash...),
		pendingProofs:         map[string]chan error{},
		activatedCh:           make(chan struct{}),
		CreatedAt:             time.Now(),
		LastActivity:          time.Now(),
	}
	lm.mu.Lock()
	lm.links[hex.EncodeToString(id)] = l
	lm.mu.Unlock()
	return l, pkt, nil
}

// HandleLRProof transitions a Pending initiator-side Link to Active by
// verifying the responder's LRPROOF and deriving session keys. The
// responder's long-term Ed25519 pub is supplied separately because both
// sides know it from the responder's prior announce — it's NOT on the
// LRPROOF wire (SPEC §6.2).
func (lm *LinkManager) HandleLRProof(p *Packet, responderEd25519Pub []byte) (*Link, error) {
	parsed, err := ParseLRProof(p)
	if err != nil {
		return nil, err
	}
	if err := parsed.Verify(responderEd25519Pub); err != nil {
		return nil, err
	}

	lm.mu.Lock()
	l, ok := lm.links[hex.EncodeToString(parsed.LinkID)]
	lm.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("LRPROOF for unknown link_id %x", parsed.LinkID)
	}

	l.mu.Lock()
	if l.State != LinkPending {
		state := l.State
		l.mu.Unlock()
		return nil, fmt.Errorf("LRPROOF for link in state %s, want pending", state)
	}
	signing, encryption, err := DeriveLinkSessionKeys(l.myEphemeralX25519Priv, parsed.ResponderX25519Pub, parsed.LinkID)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("derive session keys: %w", err)
	}
	l.Signing = signing
	l.Encryption = encryption
	l.State = LinkActive
	l.LastActivity = time.Now()
	l.myEphemeralX25519Priv = nil // no longer needed
	// Cache responder's long-term Ed25519 pubkey so handleLinkProof can
	// validate ack proofs against it without round-tripping through
	// Recall (which could miss if the known table evicted the entry).
	l.peerEd25519Pub = append([]byte(nil), responderEd25519Pub...)
	activated := l.activatedCh
	l.mu.Unlock()
	if activated != nil {
		// Close exactly once. Pending → Active transition is the only
		// place that closes; HandleLRProof guards on State == Pending so
		// we won't reach here twice.
		close(activated)
	}
	return l, nil
}

// AcceptIncomingLinkRequest is the responder-side counterpart to
// StartLinkAsInitiator. Given an inbound LINKREQUEST + the local
// destination's identity (which signs the LRPROOF), it generates an
// ephemeral X25519 keypair, derives session keys, registers an Active
// link in the manager, and returns the LRPROOF the caller should
// broadcast back.
//
// If sig is nil, the responder mirrors whatever signalling (if any)
// the initiator sent. This is the SPEC §6.6 symmetry requirement: the
// LRPROOF's signed_data MUST include the same signalling bytes the
// initiator put in their LINKREQUEST, otherwise the initiator's
// signature verification fails (their reconstructed signed_data has
// signalling, ours doesn't). Callers that want to clamp the MTU pass
// a non-nil sig with the clamped values; the typical caller (a leaf
// forwarder that doesn't negotiate MTU) passes nil and gets correct
// mirror behavior automatically.
func (lm *LinkManager) AcceptIncomingLinkRequest(reqPkt *Packet, localID *Identity, sig *LinkSignalling) (*Link, *Packet, error) {
	req, err := ParseLinkRequest(reqPkt)
	if err != nil {
		return nil, nil, err
	}
	id, err := LinkID(reqPkt)
	if err != nil {
		return nil, nil, err
	}

	respEphPriv, respEphPub, err := newClampedX25519()
	if err != nil {
		return nil, nil, err
	}
	signing, encryption, err := DeriveLinkSessionKeys(respEphPriv, req.InitiatorX25519Pub, id)
	if err != nil {
		return nil, nil, fmt.Errorf("derive session keys: %w", err)
	}

	// Mirror initiator's signalling presence when caller didn't override.
	// SPEC §6.6 trap: asymmetric signalling breaks the LRPROOF signature
	// because both sides must reconstruct the same signed_data.
	if sig == nil {
		sig = req.Signalling
	}

	proofPkt, err := BuildLRProof(localID, id, respEphPub, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("BuildLRProof: %w", err)
	}

	l := &Link{
		ID:                 id,
		State:              LinkActive,
		Signing:            signing,
		Encryption:         encryption,
		myResponderEphPriv: respEphPriv, // kept around in case we want to renegotiate
		responderIdentity:  localID,     // signs link DATA proofs (SPEC §6.5.6)
		CreatedAt:          time.Now(),
		LastActivity:       time.Now(),
	}
	lm.mu.Lock()
	lm.links[hex.EncodeToString(id)] = l
	lm.mu.Unlock()
	return l, proofPkt, nil
}

// HandleLinkData processes an inbound link DATA packet — verifies the
// outer wire shape, decrypts using the link's session keys, and routes
// the plaintext through OnInboundData (or the manager's default).
// Returns the plaintext and the original packet (so the caller can emit
// a link DATA proof against it).
func (lm *LinkManager) HandleLinkData(p *Packet) ([]byte, *Link, error) {
	if p == nil {
		return nil, nil, errors.New("nil packet")
	}
	l := lm.Get(p.DestHash)
	if l == nil {
		return nil, nil, fmt.Errorf("link DATA for unknown link_id %x", p.DestHash)
	}
	l.mu.Lock()
	if l.State != LinkActive {
		l.mu.Unlock()
		return nil, l, fmt.Errorf("link DATA on link in state %s", l.State)
	}
	signing := l.Signing
	encryption := l.Encryption
	cb := l.OnInboundData
	l.LastActivity = time.Now()
	l.mu.Unlock()

	plaintext, err := ParseLinkDataPacket(p, signing, encryption)
	if err != nil {
		return nil, l, err
	}
	if cb != nil {
		cb(plaintext)
	} else if lm.defaultOnInboundData != nil {
		lm.defaultOnInboundData(l.ID, plaintext)
	}
	return plaintext, l, nil
}

// CloseLink moves the link to Closed and removes it from the manager.
// Idempotent.
func (lm *LinkManager) CloseLink(linkID []byte) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	key := hex.EncodeToString(linkID)
	if l, ok := lm.links[key]; ok {
		l.mu.Lock()
		l.State = LinkClosed
		l.Signing = nil
		l.Encryption = nil
		l.mu.Unlock()
		delete(lm.links, key)
	}
}

// ActiveCount returns the number of links currently in Active state.
// Useful for tests and debug logs.
func (lm *LinkManager) ActiveCount() int {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	n := 0
	for _, l := range lm.links {
		l.mu.Lock()
		if l.State == LinkActive {
			n++
		}
		l.mu.Unlock()
	}
	return n
}

// newClampedX25519 generates a fresh X25519 keypair, applying RFC 7748
// scalar clamping to the priv before computing the pub. Returns
// (priv32, pub32). Both slices are freshly allocated.
func newClampedX25519() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, fmt.Errorf("X25519 priv entropy: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive X25519 pub: %w", err)
	}
	return priv, pub, nil
}
