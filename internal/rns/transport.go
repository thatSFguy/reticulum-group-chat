package rns

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transport is the in-memory glue between interfaces (TCPClient et al),
// local destinations (things we want inbound DATA packets routed to), and
// announce handlers (things that want notification when an announce is
// validated).
//
// The minimal-viable scope here matches what a leaf forwarder needs:
// - Receive announces, verify them, remember the announcer's identity so
//   we can encrypt Token replies to them later.
// - Receive DATA packets addressed to one of our local destinations and
//   hand them to the registered callback.
// - Broadcast our outbound packets on every connected interface.
//
// Out of scope (deferred): transit relaying (HEADER_1<->HEADER_2 conversion,
// path-table-driven next-hop selection, hop-count incrementing). A leaf
// forwarder simply broadcasts; relays in the network do the routing.
type Transport struct {
	mu sync.RWMutex

	interfaces       []Interface
	known            map[string]*KnownIdentity // key: hex dest_hash
	locals           map[string]*LocalDestination
	announceHandlers []AnnounceHandler

	pathRequestsSent map[string]time.Time // key: hex dest_hash, dedup window

	linkManager *LinkManager

	logger Logger
}

// PathRequestDedupWindow caps how often we re-issue a path? request for the
// same target. SPEC §7.2.2 has a much larger 32k-tag table at the relay
// side; we just want to avoid spamming when an unknown sender retransmits.
const PathRequestDedupWindow = 60 * time.Second

// Interface is anything that can ship Reticulum packets in both directions.
// TCPClient satisfies it; future LoRa or AutoInterface implementations
// would too.
type Interface interface {
	Send(packet []byte) error
	Inbox() <-chan []byte
	Done() <-chan struct{}
}

// Logger is a minimal logging seam so this package doesn't pin a log impl.
type Logger interface {
	Printf(format string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}

// KnownIdentity is what we remember after a verified announce. It lets the
// LXMF send path Token-encrypt to the recipient (we need their X25519 pub)
// and prove the source on inbound (we need their Ed25519 pub).
type KnownIdentity struct {
	DestHash   []byte
	PublicKey  []byte // 64 bytes (X25519 || Ed25519)
	NameHash   []byte
	AppData    []byte
	LastSeen   time.Time
	LastRandom []byte // last seen random_hash, for cheap replay-defence dedup
	Hops       byte

	// TransportID is the next-hop transport node's identity hash for
	// multi-hop sends, captured from the announce's outer packet header
	// when it arrived as HEADER_2. Nil if the destination announced
	// directly (HEADER_1). Used by Delivery.Send to decide whether to
	// emit HEADER_2 with TransportType=NetworkTransport (SPEC §2.3).
	TransportID []byte
}

// X25519Public returns the first 32 bytes of PublicKey — the X25519 half.
func (k *KnownIdentity) X25519Public() []byte { return k.PublicKey[:32] }

// Ed25519Public returns the last 32 bytes of PublicKey.
func (k *KnownIdentity) Ed25519Public() []byte { return k.PublicKey[32:] }

// LocalDestination is a destination we own (typically our LXMF delivery
// destination). Inbound DATA packets matching DestHash are handed to OnPacket.
// OnPacket is called from the transport's dispatcher goroutine; if the
// callback is slow it should hand the packet off to its own goroutine.
//
// If Identity is non-nil, the transport emits a PROOF packet (SPEC §6.5)
// acknowledging every received CTX_NONE DATA packet so the sender's
// PacketReceipt can resolve and retransmits stop. This is non-optional for
// interop with upstream Reticulum clients.
//
// OnLinkPlaintext, when set, receives the decrypted payload of inbound
// link DATA packets sent on a Link established to this destination. The
// link handshake (LINKREQUEST -> LRPROOF) is handled automatically by
// the Transport using the supplied Identity.
type LocalDestination struct {
	DestHash        []byte
	Identity        *Identity
	OnPacket        func(p *Packet)
	OnLinkPlaintext func(plaintext []byte)
}

// AnnounceHandler is called for every verified inbound announce whose
// announce.NameHash matches AspectMatch. Returning false from AspectMatch
// keeps the handler quiet for that announce.
type AnnounceHandler interface {
	AspectMatch(nameHash []byte) bool
	OnAnnounce(a *Announce)
}

// NewTransport builds an idle transport. Add interfaces and register
// destinations/handlers, then call Run.
func NewTransport(logger Logger) *Transport {
	if logger == nil {
		logger = noopLogger{}
	}
	return &Transport{
		known:            map[string]*KnownIdentity{},
		locals:           map[string]*LocalDestination{},
		pathRequestsSent: map[string]time.Time{},
		linkManager:      NewLinkManager(),
		logger:           logger,
	}
}

// LinkManager returns the per-Transport LinkManager. Application layer
// (lxmf.Delivery) reads this to send via Link or to register per-link
// inbound callbacks. Returned manager is shared and thread-safe.
func (t *Transport) LinkManager() *LinkManager { return t.linkManager }

// RequestPath broadcasts an SPEC §7.1 path? request for the given target
// destination hash. Used when we receive a message from a sender whose
// announce we don't have — path-aware relays respond with a path-response
// announce carrying the sender's public key.
//
// Deduplicates per-target within PathRequestDedupWindow (60 s) so a noisy
// retransmitter doesn't make us flood the network.
//
// Returns nil silently when a request was suppressed by dedup; the caller
// should treat this method as fire-and-forget.
func (t *Transport) RequestPath(targetDestHash []byte) error {
	if len(targetDestHash) != IdentityHashLen {
		return fmt.Errorf("target dest_hash must be %d bytes", IdentityHashLen)
	}
	key := hex.EncodeToString(targetDestHash)

	t.mu.Lock()
	if last, ok := t.pathRequestsSent[key]; ok && time.Since(last) < PathRequestDedupWindow {
		t.mu.Unlock()
		return nil
	}
	t.pathRequestsSent[key] = time.Now()
	t.mu.Unlock()

	pkt, err := BuildPathRequest(targetDestHash)
	if err != nil {
		return err
	}
	t.logger.Printf("path? request for %s", key[:8])
	return t.Broadcast(pkt)
}

// AddInterface plugs an Interface into the dispatcher. Must be called
// before Run.
func (t *Transport) AddInterface(i Interface) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.interfaces = append(t.interfaces, i)
}

// RegisterLocal claims a destination hash for inbound delivery.
func (t *Transport) RegisterLocal(d *LocalDestination) error {
	if d == nil || d.OnPacket == nil || len(d.DestHash) != IdentityHashLen {
		return errors.New("invalid local destination")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locals[hex.EncodeToString(d.DestHash)] = d
	return nil
}

// RegisterAnnounceHandler installs a handler for verified announces.
func (t *Transport) RegisterAnnounceHandler(h AnnounceHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.announceHandlers = append(t.announceHandlers, h)
}

// Recall returns the cached KnownIdentity for a destination hash, or
// nil if we've never heard them announce.
func (t *Transport) Recall(destHash []byte) *KnownIdentity {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.known[hex.EncodeToString(destHash)]
}

// Broadcast sends a packet on every interface. Errors per-interface are
// logged but don't abort the broadcast (other interfaces may still deliver).
func (t *Transport) Broadcast(p *Packet) error {
	wire, err := p.Pack()
	if err != nil {
		return err
	}
	t.mu.RLock()
	ifaces := append([]Interface(nil), t.interfaces...)
	t.mu.RUnlock()
	if len(ifaces) == 0 {
		return errors.New("transport: no interfaces")
	}
	var firstErr error
	for _, i := range ifaces {
		if err := i.Send(wire); err != nil {
			t.logger.Printf("send failed: %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Run blocks until ctx is cancelled, dispatching inbound packets from
// every registered interface.
func (t *Transport) Run(ctx context.Context) {
	t.mu.RLock()
	ifaces := append([]Interface(nil), t.interfaces...)
	t.mu.RUnlock()

	if len(ifaces) == 0 {
		t.logger.Printf("transport.Run: no interfaces — nothing to dispatch")
		<-ctx.Done()
		return
	}

	// Fan-in: each interface gets a goroutine that pumps its Inbox into a
	// shared channel. Run blocks on the shared channel.
	type incoming struct {
		raw []byte
		via Interface
	}
	merged := make(chan incoming, 256)
	var wg sync.WaitGroup
	for _, i := range ifaces {
		wg.Add(1)
		go func(iface Interface) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-iface.Done():
					return
				case raw, ok := <-iface.Inbox():
					if !ok {
						return
					}
					select {
					case merged <- incoming{raw: raw, via: iface}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case in := <-merged:
			t.dispatch(in.raw)
		}
	}
}

func (t *Transport) dispatch(raw []byte) {
	p, err := ParsePacket(raw)
	if err != nil {
		t.logger.Printf("parse packet: %v", err)
		return
	}
	switch p.PacketType {
	case PacketAnnounce:
		t.handleAnnounce(p)
	case PacketData:
		if p.DestinationType == DestinationLink {
			t.handleLinkData(p)
			return
		}
		t.handleData(p)
	case PacketLinkRequest:
		t.handleLinkRequest(p)
	case PacketProof:
		if p.DestinationType == DestinationLink && p.Context == ContextLRProof {
			t.handleLRProof(p)
			return
		}
		// Other proofs (opportunistic-DATA proofs we get back, or link
		// DATA proofs from the other end) — we don't track outstanding
		// PacketReceipts on our outbound packets, so we drop them silently
		// here. Future PR will validate them when we want delivery
		// confirmation on our own sends.
	}
}

func (t *Transport) handleAnnounce(p *Packet) {
	a, err := ParseAnnounce(p)
	if err != nil {
		t.logger.Printf("announce parse: %v", err)
		return
	}
	if err := a.Verify(); err != nil {
		t.logger.Printf("announce verify: %v", err)
		return
	}

	key := hex.EncodeToString(a.DestHash)
	now := time.Now()

	t.mu.Lock()
	prev := t.known[key]
	// Cheap replay-defence dedup: if the random_hash exactly matches what we
	// last saw, skip. SPEC §4.5 step 6.3 has a more elaborate cache; this
	// suffices for a leaf forwarder.
	if prev != nil && bytesEqual(prev.LastRandom, a.RandomHash) {
		t.mu.Unlock()
		return
	}
	if prev == nil {
		prev = &KnownIdentity{}
		t.known[key] = prev
	}
	prev.DestHash = a.DestHash
	prev.PublicKey = a.PublicKey
	prev.NameHash = a.NameHash
	prev.AppData = a.AppData
	prev.LastSeen = now
	prev.LastRandom = a.RandomHash
	prev.Hops = a.Hops
	if a.TransportID != nil {
		prev.TransportID = append([]byte(nil), a.TransportID...)
	} else {
		prev.TransportID = nil
	}
	handlers := append([]AnnounceHandler(nil), t.announceHandlers...)
	t.mu.Unlock()

	t.logger.Printf("announce verified: dest=%x name=%x hops=%d ctxFlag=%v", a.DestHash[:4], a.NameHash, a.Hops, a.ContextFlag)
	for _, h := range handlers {
		if h.AspectMatch(a.NameHash) {
			h.OnAnnounce(a)
		}
	}
}

func (t *Transport) handleData(p *Packet) {
	t.mu.RLock()
	dest := t.locals[hex.EncodeToString(p.DestHash)]
	t.mu.RUnlock()
	if dest == nil {
		// Not for us; in a transit relay we'd forward — out of scope here.
		return
	}

	// SPEC §6.5: emit a PROOF packet ACK-ing the inbound DATA before any
	// application-layer processing, so the sender's PacketReceipt can
	// resolve quickly even if our handler is slow. Skipped if the local
	// destination didn't supply an identity (e.g. some unit-test setups).
	if dest.Identity != nil && p.Context == ContextNone && p.DestinationType == DestinationSingle {
		if proof, err := ProveOpportunistic(dest.Identity, p); err != nil {
			t.logger.Printf("prove: %v", err)
		} else if err := t.Broadcast(proof); err != nil {
			t.logger.Printf("proof broadcast: %v", err)
		}
	}

	dest.OnPacket(p)
}

// handleLinkRequest is invoked for inbound LINKREQUEST packets addressed
// to one of our local destinations. We mint an ephemeral X25519 keypair,
// derive session keys via DeriveLinkSessionKeys, build + broadcast the
// LRPROOF, and register the link as Active in the manager.
func (t *Transport) handleLinkRequest(p *Packet) {
	t.mu.RLock()
	dest := t.locals[hex.EncodeToString(p.DestHash)]
	t.mu.RUnlock()
	if dest == nil {
		return // LINKREQUEST not for us
	}
	if dest.Identity == nil {
		t.logger.Printf("LINKREQUEST for local %x but no identity registered (cannot sign LRPROOF)", p.DestHash[:4])
		return
	}

	link, lrProof, err := t.linkManager.AcceptIncomingLinkRequest(p, dest.Identity, nil /* signalling */)
	if err != nil {
		t.logger.Printf("AcceptIncomingLinkRequest: %v", err)
		return
	}
	// Wire the local destination's OnLinkPlaintext callback if it has one.
	link.mu.Lock()
	link.OnInboundData = dest.OnLinkPlaintext
	link.mu.Unlock()

	t.logger.Printf("link established (responder): id=%x peer LRREQ from %x", link.ID[:4], p.DestHash[:4])
	if err := t.Broadcast(lrProof); err != nil {
		t.logger.Printf("broadcast LRPROOF: %v", err)
	}
}

// handleLRProof feeds an inbound LRPROOF (responder -> initiator) to the
// LinkManager, which transitions a Pending link to Active. We use the
// responder's long-term Ed25519 pub from KnownIdentity (cached when
// they previously announced).
func (t *Transport) handleLRProof(p *Packet) {
	parsed, err := ParseLRProof(p)
	if err != nil {
		t.logger.Printf("LRPROOF parse: %v", err)
		return
	}
	// We don't know the responder dest_hash from the LRPROOF outer header
	// (that's the link_id, not the responder's dest). So look up the
	// pending link to find which peer this proof is for.
	link := t.linkManager.Get(parsed.LinkID)
	if link == nil {
		t.logger.Printf("LRPROOF for unknown link_id %x", parsed.LinkID[:4])
		return
	}
	link.mu.Lock()
	peerDest := append([]byte(nil), link.peerDestHash...)
	link.mu.Unlock()
	if peerDest == nil {
		t.logger.Printf("LRPROOF for link without peerDestHash (we were the responder?)")
		return
	}
	known := t.Recall(peerDest)
	if known == nil {
		t.logger.Printf("LRPROOF received but responder %x not in known table — must have announced first", peerDest[:4])
		return
	}
	if _, err := t.linkManager.HandleLRProof(p, known.Ed25519Public()); err != nil {
		t.logger.Printf("HandleLRProof: %v", err)
		return
	}
	t.logger.Printf("link active (initiator): id=%x", parsed.LinkID[:4])
}

// handleLinkData processes inbound DATA packets addressed to a link_id.
// Decrypts via the LinkManager, emits the SPEC §6.5.6 explicit-form
// PROOF acknowledging the packet, then forwards plaintext to the link's
// OnInboundData callback (if set).
func (t *Transport) handleLinkData(p *Packet) {
	if p.Context == ContextKeepalive {
		// Just bump activity. SPEC: KEEPALIVE has body [0x00].
		if l := t.linkManager.Get(p.DestHash); l != nil {
			l.mu.Lock()
			l.LastActivity = time.Now()
			l.mu.Unlock()
		}
		return
	}
	if p.Context != ContextNone {
		// Link DATA on other contexts (resource transfer etc.) — out of scope.
		return
	}

	_, link, err := t.linkManager.HandleLinkData(p)
	if err != nil {
		t.logger.Printf("link data: %v", err)
		return
	}

	// Emit the explicit-form link DATA proof BEFORE returning so the
	// sender's PacketReceipt can resolve quickly. (SPEC §6.5.6 — without
	// this the sender retransmits and eventually tears the link down.)
	link.mu.Lock()
	signing := link.Signing
	linkID := link.ID
	link.mu.Unlock()
	if signing != nil {
		if proof, err := BuildLinkProof(linkID, signing, p); err != nil {
			t.logger.Printf("build link proof: %v", err)
		} else if err := t.Broadcast(proof); err != nil {
			t.logger.Printf("broadcast link proof: %v", err)
		}
	}
}

// AnnouncePeriodically re-broadcasts the announce returned by build() on
// every tick. Returns when ctx is cancelled.
func (t *Transport) AnnouncePeriodically(ctx context.Context, interval time.Duration, build func() (*Packet, error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	emit := func() {
		p, err := build()
		if err != nil {
			t.logger.Printf("announce build: %v", err)
			return
		}
		if err := t.Broadcast(p); err != nil {
			t.logger.Printf("announce broadcast: %v", err)
		}
	}
	emit() // immediate
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			emit()
		}
	}
}
