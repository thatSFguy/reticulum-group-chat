package rns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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

	pathRequestsSent     map[string]time.Time // key: hex dest_hash, dedup window for outbound
	pathResponseTagsSeen map[string]time.Time // key: hex tag, dedup for inbound path? we've already responded to

	linkManager *LinkManager

	// lifetime is the configurable timing for RunLinkSweeper. Lazily
	// initialised to defaults on first read so tests that never start
	// the sweeper don't have to set anything.
	lifetime *linkLifetime

	logger Logger
}

// PathRequestDedupWindow caps how often we re-issue a path? request for the
// same target. SPEC §7.2.2 has a much larger 32k-tag table at the relay
// side; we just want to avoid spamming when an unknown sender retransmits.
const PathRequestDedupWindow = 60 * time.Second

// AnnounceLogReturnThreshold is the silence window after which we log a
// repeat announce from a previously-known identity. Periodic re-announces
// arrive every AnnounceInterval (default 10 min) per peer per relay hop;
// on a busy public mesh this fills the log faster than anything else and
// drowns out the lines an operator actually wants to see (new peers,
// link state, errors). Above the threshold we still log once so absence-
// then-return is visible.
const AnnounceLogReturnThreshold = 6 * time.Hour

// PathResponseTagDedupWindow bounds how long we remember an inbound
// path? request's 16-byte random tag so we don't emit a path-response
// twice if the same request reaches us through multiple relay hops or
// re-broadcasts. Matches SPEC §7.2.5 PR_TAG_WINDOW.
const PathResponseTagDedupWindow = 30 * time.Second

// KnownIdentityCapacity caps the number of cached known identities to
// prevent a memory-DoS where an attacker on a public mesh broadcasts
// announces from many fresh identities. When at capacity, the entry with
// the oldest LastSeen is evicted. The cap is generous — enough for a
// large active mesh, small enough that even ~150 bytes/entry stays under
// 1 MB of heap.
const KnownIdentityCapacity = 4096

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
//
// The JSON tags exist so callers can persist the cache to disk and
// restore it on startup via Transport.Restore — without that, a service
// restart loses every learned peer until they re-announce (up to the
// configured AnnounceInterval, default 10 minutes).
type KnownIdentity struct {
	DestHash   []byte    `json:"dest_hash"`
	PublicKey  []byte    `json:"public_key"` // 64 bytes (X25519 || Ed25519)
	NameHash   []byte    `json:"name_hash"`
	AppData    []byte    `json:"app_data"`
	LastSeen   time.Time `json:"last_seen"`
	LastRandom []byte    `json:"last_random"` // last seen random_hash, for cheap replay-defence dedup
	Hops       byte      `json:"hops"`

	// TransportID is the next-hop transport node's identity hash for
	// multi-hop sends, captured from the announce's outer packet header
	// when it arrived as HEADER_2. Nil if the destination announced
	// directly (HEADER_1). Used by Delivery.Send to decide whether to
	// emit HEADER_2 with TransportType=NetworkTransport (SPEC §2.3).
	TransportID []byte `json:"transport_id,omitempty"`
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

	// BuildAnnounce, if non-nil, is called when the Transport receives
	// a SPEC §7.2 path? request whose target_dest_hash matches this
	// destination. The returned announce is broadcast as a path-response
	// (SPEC §7.2 — same wire body as a regular announce, with
	// context=ContextPathResponse so transit relays can short-circuit
	// re-broadcast). Without this, leaf clients can't bootstrap a path
	// to this destination via path? — they'd have to wait up to one
	// announce_interval for our periodic announce to arrive.
	BuildAnnounce func(context byte) (*Packet, error)
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
		pathRequestsSent:     map[string]time.Time{},
		pathResponseTagsSeen: map[string]time.Time{},
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
	now := time.Now()
	// Sweep expired entries while we're holding the lock — bounds the map
	// at roughly the number of distinct targets contacted within the dedup
	// window. Without this, an attacker generating fresh source_hashes
	// could grow this map without bound.
	for k, ts := range t.pathRequestsSent {
		if now.Sub(ts) > PathRequestDedupWindow {
			delete(t.pathRequestsSent, k)
		}
	}
	if last, ok := t.pathRequestsSent[key]; ok && now.Sub(last) < PathRequestDedupWindow {
		t.mu.Unlock()
		return nil
	}
	t.pathRequestsSent[key] = now
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

// Restore inserts a previously-verified KnownIdentity into the cache —
// used at startup to repopulate from a persistent store so a service
// restart doesn't have to wait for every peer to re-announce. Skips
// invalid entries (wrong-length DestHash or PublicKey) silently so a
// corrupt store can't crash the daemon. Deep-copies byte slices to
// avoid sharing storage with the caller.
func (t *Transport) Restore(k *KnownIdentity) {
	if k == nil ||
		len(k.DestHash) != IdentityHashLen ||
		len(k.PublicKey) != PublicKeyLen {
		return
	}
	cp := &KnownIdentity{
		DestHash:   append([]byte(nil), k.DestHash...),
		PublicKey:  append([]byte(nil), k.PublicKey...),
		NameHash:   append([]byte(nil), k.NameHash...),
		AppData:    append([]byte(nil), k.AppData...),
		LastSeen:   k.LastSeen,
		LastRandom: append([]byte(nil), k.LastRandom...),
		Hops:       k.Hops,
	}
	if k.TransportID != nil {
		cp.TransportID = append([]byte(nil), k.TransportID...)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.known[hex.EncodeToString(cp.DestHash)] = cp
}

// KnownSnapshot returns a deep copy of every cached KnownIdentity.
// Used by the persistence layer to serialize the announce cache on
// startup or before shutdown without holding the Transport lock during
// disk I/O.
func (t *Transport) KnownSnapshot() []*KnownIdentity {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*KnownIdentity, 0, len(t.known))
	for _, k := range t.known {
		cp := *k
		cp.DestHash = append([]byte(nil), k.DestHash...)
		cp.PublicKey = append([]byte(nil), k.PublicKey...)
		cp.NameHash = append([]byte(nil), k.NameHash...)
		cp.AppData = append([]byte(nil), k.AppData...)
		cp.LastRandom = append([]byte(nil), k.LastRandom...)
		if k.TransportID != nil {
			cp.TransportID = append([]byte(nil), k.TransportID...)
		}
		out = append(out, &cp)
	}
	return out
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
		if p.DestinationType == DestinationPlain && isPathRequestDestHash(p.DestHash) {
			t.handlePathRequest(p)
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
		if p.DestinationType == DestinationLink && p.Context == ContextResourcePRF {
			// RESOURCE_PRF — the receiver's final proof for one of our
			// outbound resources. Routed to the matching ResourceSender
			// by (link_id, resource_hash); a PRF for an unknown sender
			// is dropped silently (e.g. duplicate after we already
			// completed and unregistered).
			t.handleResourceProof(p)
			return
		}
		if p.DestinationType == DestinationLink && p.Context == ContextNone {
			// Explicit-form link DATA proof acknowledging an outbound
			// link DATA we sent as initiator. Validates the signature
			// against the responder's cached long-term Ed25519 pub and
			// signals the matching SendOverLink waiter.
			t.handleLinkProof(p)
			return
		}
		// Opportunistic-DATA proofs come back at us when we send
		// opportunistic LXMF, but we don't track outstanding
		// PacketReceipts there yet, so we drop them silently. Future PR
		// could plumb delivery confirmation through to Delivery.Send.
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
	// Snapshot prior-state fields BEFORE we update prev so the post-unlock
	// log decision can tell "new identity" / "returning after a long gap"
	// from "routine periodic re-announce". Skips the log line for the
	// common case (a known peer announcing on schedule).
	wasNewIdentity := prev == nil
	var prevLastSeen time.Time
	if prev != nil {
		prevLastSeen = prev.LastSeen
	}
	if prev == nil {
		// Bound the map: when at capacity, evict the entry with the oldest
		// LastSeen. O(N) but only runs at full capacity, which is rare.
		if len(t.known) >= KnownIdentityCapacity {
			var oldestKey string
			var oldestTime time.Time
			for k, v := range t.known {
				if oldestKey == "" || v.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.LastSeen
				}
			}
			delete(t.known, oldestKey)
		}
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

	switch {
	case wasNewIdentity:
		displayName, _ := DecodeLXMFAppDataDisplayName(a.AppData)
		t.logger.Printf("announce verified (new): dest=%x name=%x hops=%d ctxFlag=%v display=%q", a.DestHash[:4], a.NameHash, a.Hops, a.ContextFlag, string(displayName))
	case now.Sub(prevLastSeen) >= AnnounceLogReturnThreshold:
		displayName, _ := DecodeLXMFAppDataDisplayName(a.AppData)
		t.logger.Printf("announce verified (returning after %s): dest=%x name=%x hops=%d display=%q", now.Sub(prevLastSeen).Round(time.Minute), a.DestHash[:4], a.NameHash, a.Hops, string(displayName))
	}
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

// pathRequestWellKnownHash is the 16-byte well-known PLAIN destination
// path? requests are addressed to. Cached at package-init so we don't
// re-decode the hex on every inbound DATA packet.
var pathRequestWellKnownHash = mustDecodeHex(PathRequestDestHashHex)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex constant %q: %v", s, err))
	}
	return b
}

func isPathRequestDestHash(b []byte) bool {
	return bytes.Equal(b, pathRequestWellKnownHash)
}

// handlePathRequest is invoked for inbound DATA packets addressed to
// the well-known PLAIN path-request hash (SPEC §7.1). When the request
// targets one of our local destinations, we emit a path-response —
// a regular announce with context=ContextPathResponse — so the
// requester gets our public key + path table entry without waiting for
// our next periodic announce. Tag dedup (SPEC §7.2.5 PR_TAG_WINDOW)
// prevents responding twice if the same request reaches us via
// multiple relays.
func (t *Transport) handlePathRequest(p *Packet) {
	target, err := PathRequestTarget(p.Data)
	if err != nil {
		return
	}
	// Tag is the 16 bytes after target_dest_hash.
	if len(p.Data) < IdentityHashLen*2 {
		return // no tag, malformed leaf-form request
	}
	tag := p.Data[IdentityHashLen : IdentityHashLen*2]
	tagKey := hex.EncodeToString(tag)

	t.mu.Lock()
	// Sweep expired tags so the map can't grow unbounded under a flood.
	now := time.Now()
	for k, ts := range t.pathResponseTagsSeen {
		if now.Sub(ts) > PathResponseTagDedupWindow {
			delete(t.pathResponseTagsSeen, k)
		}
	}
	if last, ok := t.pathResponseTagsSeen[tagKey]; ok && now.Sub(last) < PathResponseTagDedupWindow {
		t.mu.Unlock()
		return // already responded recently
	}
	t.pathResponseTagsSeen[tagKey] = now

	local, isOurs := t.locals[hex.EncodeToString(target)]
	t.mu.Unlock()
	if !isOurs {
		// Not for us. A transit-mode node would forward; we're a leaf,
		// so drop silently.
		return
	}
	if local.BuildAnnounce == nil {
		t.logger.Printf("path? for %x but no BuildAnnounce on local destination — cannot respond", target[:4])
		return
	}
	pkt, err := local.BuildAnnounce(ContextPathResponse)
	if err != nil {
		t.logger.Printf("build path-response announce: %v", err)
		return
	}
	t.logger.Printf("path? answered for %x (tag %x)", target[:4], tag[:4])
	if err := t.Broadcast(pkt); err != nil {
		t.logger.Printf("broadcast path-response: %v", err)
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

	// Upstream RNS: after the initiator validates the LRPROOF, it sends
	// an LRRTT packet to the responder carrying the measured RTT (a
	// msgpack-packed float). The responder uses receipt of this packet
	// to transition its link from HANDSHAKE to ACTIVE and fire the
	// link_established_callback. Without it, LXMRouter never calls
	// `link.set_resource_strategy(ACCEPT_APP)`, so any subsequent
	// RESOURCE_ADV we send is silently dropped at the receiver because
	// resource_strategy stays at the default ACCEPT_NONE.
	//
	// We don't currently track LRREQ-send time per-link; estimate RTT
	// generously enough that the responder's max(measured, reported)
	// won't degrade keepalive cadence. 0.05s is roughly a single LAN
	// round-trip and matches what upstream typically computes for
	// localhost rnsd hops. The exact value is non-load-bearing — only
	// the act of sending the packet matters.
	if err := t.sendLRRTT(parsed.LinkID, link, 0.05); err != nil {
		t.logger.Printf("send LRRTT: %v", err)
	}
}

// sendLRRTT builds and broadcasts the post-handshake LRRTT packet.
// Snapshots the link's session keys under its mutex so we don't race
// a concurrent close.
func (t *Transport) sendLRRTT(linkID []byte, link *Link, rttSec float64) error {
	link.mu.Lock()
	signing := append([]byte(nil), link.Signing...)
	encryption := append([]byte(nil), link.Encryption...)
	link.mu.Unlock()
	if len(signing) == 0 || len(encryption) == 0 {
		return fmt.Errorf("link has no session keys")
	}
	pkt, err := BuildLinkRTT(linkID, signing, encryption, rttSec)
	if err != nil {
		return err
	}
	return t.Broadcast(pkt)
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
	switch p.Context {
	case ContextNone:
		// Fall through to the original direct-LXMF handler below.
	case ContextResourceADV, ContextResourceREQ, ContextResourceHMU,
		ContextResourceICL, ContextResourceRCL:
		// Resource control packets — bodies are link-encrypted (SPEC
		// §10.3 + upstream Packet.pack:212-215). Decrypt, then dispatch
		// by context. Resource part packets (ContextResource) are NOT
		// encrypted (raw slice of pre-encrypted blob) so they have
		// their own branch below.
		t.handleResourceControl(p)
		return
	case ContextResource:
		// RESOURCE part — body is a raw ciphertext slice, no per-
		// packet decrypt. The part doesn't carry resource_hash
		// in-band; we walk active receivers on this link and route
		// to whichever one has a matching map_hash slot. fwdsvc
		// usually has at most one inbound resource per link in
		// flight, so the walk is short.
		t.handleResourcePart(p)
		return
	default:
		// Other contexts (REQUEST/RESPONSE/etc) — out of scope for fwdsvc.
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
	//
	// Two paths depending on which side of the handshake we are:
	//
	//   responder side (responderIdentity != nil): sign with our
	//   destination identity's long-term Ed25519 priv per upstream
	//   RNS/Link.py:279. The initiator validates against our long-term
	//   pub (it cached that pub when it looked us up to send the
	//   LINKREQUEST).
	//
	//   initiator side (initiatorEd25519Priv != nil): sign with the
	//   ephemeral Ed25519 priv we generated at link-creation time. The
	//   responder validates against the ephemeral pub bytes carried in
	//   the LINKREQUEST body (which it already parsed and verified).
	//
	// A link should always have exactly one of these set; if neither
	// (test paths constructing Links manually), we skip and log.
	link.mu.Lock()
	signer := link.responderIdentity
	initPriv := link.initiatorEd25519Priv
	linkID := link.ID
	link.mu.Unlock()

	var sign func([]byte) []byte
	switch {
	case signer != nil:
		sign = signer.Sign
	case initPriv != nil:
		sign = func(msg []byte) []byte { return ed25519.Sign(initPriv, msg) }
	default:
		t.logger.Printf("link PROOF skipped: no signing key for link=%x", linkID[:4])
		return
	}
	proof, err := BuildLinkProof(linkID, sign, p)
	if err != nil {
		t.logger.Printf("build link proof: %v", err)
		return
	}
	if err := t.Broadcast(proof); err != nil {
		t.logger.Printf("broadcast link proof: %v", err)
	}
}

// Sentinel errors returned by SendOverLink so callers can branch on
// failure mode (timeout vs. peer-unknown vs. handshake failure) without
// string-matching.
var (
	ErrLinkPeerUnknown    = errors.New("link send: peer has not announced; cannot open link")
	ErrLinkHandshakeTimeout = errors.New("link send: LRPROOF did not arrive before timeout")
	ErrLinkProofTimeout   = errors.New("link send: link DATA proof did not arrive before timeout")
	ErrLinkSendFailed     = errors.New("link send: broadcast failed")
)

// DefaultLinkSendTimeout is the per-call ceiling for the entire
// SendOverLink operation: handshake (if any) + DATA broadcast + proof
// wait. Chosen to absorb a 2-hop relay round-trip on a slow LoRa segment
// without giving up too eagerly. Override per call by passing a smaller
// timeout when the caller knows the peer is direct.
const DefaultLinkSendTimeout = 30 * time.Second

// SendOverLink delivers `plaintext` to `responderDestHash` over a
// Reticulum Link, opening one lazily if no Active link to that peer
// exists. Blocks until the responder's explicit-form link DATA proof
// arrives, or until `timeout` elapses.
//
// Returns nil on successful proof receipt. ErrLinkPeerUnknown if the
// responder has never announced. ErrLinkHandshakeTimeout if the
// LINKREQUEST/LRPROOF round-trip doesn't complete in time.
// ErrLinkProofTimeout if the DATA went out but no proof returned.
//
// Concurrent SendOverLink calls to the same peer that find no Active
// link will each open their own Link — wasteful but not broken; PR3
// adds coalescing. Concurrent calls on the SAME Link are serialized
// inside the link's pendingProofs map (each send registers under its
// own packet_hash) and may proceed in parallel.
func (t *Transport) SendOverLink(responderDestHash []byte, plaintext []byte, timeout time.Duration) error {
	if len(responderDestHash) != IdentityHashLen {
		return fmt.Errorf("responder dest_hash must be %d bytes, got %d", IdentityHashLen, len(responderDestHash))
	}
	if timeout <= 0 {
		timeout = DefaultLinkSendTimeout
	}
	deadline := time.Now().Add(timeout)

	link, err := t.acquireLinkTo(responderDestHash, deadline)
	if err != nil {
		return err
	}

	// Snapshot session keys + peer-pub under the link mutex so a
	// concurrent teardown can't race with our broadcast.
	link.mu.Lock()
	if link.State != LinkActive {
		state := link.State
		link.mu.Unlock()
		return fmt.Errorf("link send: link state is %s, want active", state)
	}
	signing := append([]byte(nil), link.Signing...)
	encryption := append([]byte(nil), link.Encryption...)
	linkID := append([]byte(nil), link.ID...)
	link.mu.Unlock()

	// Size-driven dispatch: payloads that don't fit one Link DATA
	// packet (LinkMDU = 431 bytes plaintext) MUST go via the SPEC §10
	// Resource transfer protocol. Stuffing them into a single oversize
	// link DATA packet causes the receiver to drop them at MTU and
	// the proof never returns — that's the operator's "5/5 retries"
	// failure mode v1.3.x is built to fix.
	if len(plaintext) > LinkMDU {
		var transportID []byte
		if known := t.Recall(responderDestHash); known != nil {
			transportID = known.TransportID
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		return t.SendResourceOverLink(ctx, link, plaintext, transportID)
	}

	dataPkt, err := BuildLinkDataPacket(linkID, signing, encryption, plaintext)
	if err != nil {
		return fmt.Errorf("link send: build DATA: %w", err)
	}

	// Link DATA stays HEADER_1 even for multi-hop peers. Upstream RNS
	// routes link DATA via link_table (keyed on link_id), not path_table,
	// and relays forward link DATA UNCHANGED — they don't strip a
	// transport_id like they do for path_table forwarding. If we set
	// transport_id here, the relay forwards the HEADER_2 packet to the
	// final hop with transport_id intact, and the receiver's
	// packet_filter drops it as "for other transport instance" (RNS
	// Transport.py:1283-1285). Upstream's own Packet(link, data,
	// context=RESOURCE_ADV) constructor defaults to HEADER_1 + no
	// transport_id — we mirror that.

	// Compute the packet_hash the responder will sign. MUST use the SAME
	// hashable_part the responder sees — HashablePart is invariant under
	// HEADER_1↔HEADER_2 (it strips the transport_id slot), so this works
	// identically for direct and multi-hop peers.
	hashable, err := dataPkt.HashablePart()
	if err != nil {
		return fmt.Errorf("link send: hashable: %w", err)
	}
	digest := sha256SumLen32(hashable)
	hashHex := hex.EncodeToString(digest[:])

	// Register the waiter BEFORE broadcasting. If the responder is fast
	// enough to ack before we broadcast returns, the dispatcher would
	// otherwise drop the proof on the floor.
	waiter := link.registerProofWaiter(hashHex)
	defer link.clearProofWaiter(hashHex)

	if err := t.Broadcast(dataPkt); err != nil {
		return fmt.Errorf("%w: %v", ErrLinkSendFailed, err)
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return ErrLinkProofTimeout
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case proofErr := <-waiter:
		return proofErr
	case <-timer.C:
		return ErrLinkProofTimeout
	}
}

// acquireLinkTo returns an Active Link to peer. Reuses an existing
// Active link if one exists; otherwise opens a new one and waits for
// the LRPROOF to arrive. `deadline` bounds the handshake wait.
//
// If the responder is multi-hop (KnownIdentity.TransportID set from a
// HEADER_2 announce that arrived via a relay), the LINKREQUEST is
// emitted as HEADER_2 with that transport_id so transit relays can
// route it to the responder. The link_id derivation is invariant under
// HEADER_1↔HEADER_2 conversion (HashablePart strips the transport_id
// slot — see packet.go), so both sides agree on the link_id either way.
func (t *Transport) acquireLinkTo(responderDestHash []byte, deadline time.Time) (*Link, error) {
	if existing := t.linkManager.ActiveTo(responderDestHash); existing != nil {
		return existing, nil
	}
	known := t.Recall(responderDestHash)
	if known == nil {
		return nil, ErrLinkPeerUnknown
	}

	link, lrReq, err := t.linkManager.StartLinkAsInitiator(responderDestHash, nil /* signalling */)
	if err != nil {
		return nil, fmt.Errorf("start link: %w", err)
	}
	applyMultihopRouting(lrReq, known.TransportID)
	if err := t.Broadcast(lrReq); err != nil {
		t.linkManager.CloseLink(link.ID)
		return nil, fmt.Errorf("%w: broadcast LINKREQUEST: %v", ErrLinkSendFailed, err)
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		t.linkManager.CloseLink(link.ID)
		return nil, ErrLinkHandshakeTimeout
	}
	cancelled := make(chan struct{})
	timer := time.AfterFunc(remaining, func() { close(cancelled) })
	defer timer.Stop()

	if err := link.AwaitActive(cancelled); err != nil {
		// Whether we timed out or got a closed link, drop it from the
		// manager so a retry doesn't trip over a Pending stub.
		t.linkManager.CloseLink(link.ID)
		if !timer.Stop() && time.Now().After(deadline) {
			return nil, ErrLinkHandshakeTimeout
		}
		return nil, fmt.Errorf("link handshake: %w", err)
	}
	return link, nil
}

// handleLinkProof is invoked for inbound PROOF packets whose outer
// header has dest_type=LINK and context=NONE — the explicit-form link
// DATA proof a responder emits to ack our outbound link DATA. Validates
// the signature against the responder's cached long-term Ed25519 pub
// and signals the matching pendingProofs waiter (if any).
//
// Logged-but-not-errored on failure: dispatcher must keep going.
func (t *Transport) handleLinkProof(p *Packet) {
	link := t.linkManager.Get(p.DestHash)
	if link == nil {
		t.logger.Printf("link DATA proof for unknown link_id %x", p.DestHash[:4])
		return
	}
	link.mu.Lock()
	peerPub := link.peerEd25519Pub
	link.mu.Unlock()
	if peerPub == nil {
		// Responder side — they emit proofs but don't validate them. Or
		// a still-Pending initiator that somehow received a proof first
		// (shouldn't happen).
		return
	}

	packetHash, err := ValidateLinkProof(p, peerPub)
	if err != nil {
		t.logger.Printf("link DATA proof reject: %v", err)
		return
	}
	link.mu.Lock()
	link.LastActivity = time.Now()
	link.mu.Unlock()
	if !link.signalProof(hex.EncodeToString(packetHash), nil) {
		// No waiter — proof for a packet we didn't track (e.g. a
		// duplicate ack, or an ack that arrived after our wait timed
		// out). Logged at debug-equivalent so an operator chasing
		// retransmits can see them.
		t.logger.Printf("link DATA proof: no waiter for packet_hash %x (link=%x)", packetHash[:4], link.ID[:4])
	}
}

// sha256SumLen32 is a tiny helper that wraps sha256.Sum256 so callers
// don't need an extra import for one line.
func sha256SumLen32(b []byte) [32]byte { return sha256.Sum256(b) }

// applyMultihopRouting promotes a HEADER_1 broadcast packet to HEADER_2
// network-transport with the given transport_id, so transit relays can
// route it to a multi-hop peer. No-op when transportID is empty (the
// peer announced directly).
//
// Mutates the packet in place. The caller MUST have computed link_id /
// packet_hash from a HEADER_1 form OR be aware that HashablePart is
// invariant under HEADER_1↔HEADER_2 conversion (the transport_id slot
// is stripped before hashing — see packet.go HashablePart).
func applyMultihopRouting(p *Packet, transportID []byte) {
	if len(transportID) != IdentityHashLen {
		return
	}
	p.HeaderType = HeaderType2
	p.TransportType = NetworkTransport
	p.TransportID = append([]byte(nil), transportID...)
}

// Default lifetime parameters for outbound links. Conservative: KEEPALIVE
// often enough to keep upstream's STAY_TIME timer (~10 min) from firing,
// idle teardown long after a peer would have torn down on their own.
// Both can be overridden per-Transport via SetLinkLifetime.
const (
	DefaultLinkKeepaliveInterval = 4 * time.Minute
	DefaultLinkIdleTimeout       = 15 * time.Minute
	DefaultLinkSweepInterval     = 30 * time.Second
)

// linkLifetime carries the configurable timing for the link sweeper.
// Held inside Transport; immutable after Run starts to avoid surprises.
type linkLifetime struct {
	keepalive time.Duration
	idle      time.Duration
	sweep     time.Duration
}

// SetLinkLifetime overrides the default keepalive/idle/sweep parameters.
// Must be called before RunLinkSweeper. Zero values keep the defaults.
func (t *Transport) SetLinkLifetime(keepalive, idle, sweep time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lifetime == nil {
		t.lifetime = &linkLifetime{}
	}
	if keepalive > 0 {
		t.lifetime.keepalive = keepalive
	}
	if idle > 0 {
		t.lifetime.idle = idle
	}
	if sweep > 0 {
		t.lifetime.sweep = sweep
	}
}

// RunLinkSweeper periodically scans the LinkManager and:
//  1. Emits a KEEPALIVE packet on Active outbound (initiator-side) links
//     whose LastActivity is older than the keepalive interval, so the
//     responder doesn't tear them down for inactivity.
//  2. Closes any Active link (initiator OR responder side) idle longer
//     than the idle timeout, freeing state.
//
// Run as a goroutine alongside Transport.Run. Returns when ctx is done.
func (t *Transport) RunLinkSweeper(ctx context.Context) {
	t.mu.Lock()
	if t.lifetime == nil {
		t.lifetime = &linkLifetime{}
	}
	if t.lifetime.keepalive == 0 {
		t.lifetime.keepalive = DefaultLinkKeepaliveInterval
	}
	if t.lifetime.idle == 0 {
		t.lifetime.idle = DefaultLinkIdleTimeout
	}
	if t.lifetime.sweep == 0 {
		t.lifetime.sweep = DefaultLinkSweepInterval
	}
	sweepInterval := t.lifetime.sweep
	t.mu.Unlock()

	tick := time.NewTicker(sweepInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.sweepLinks()
		}
	}
}

// sweepLinks is one pass of the link housekeeping loop. Exposed so
// tests can drive it deterministically without depending on the ticker.
func (t *Transport) sweepLinks() {
	t.mu.RLock()
	keepalive := t.lifetime.keepalive
	idle := t.lifetime.idle
	t.mu.RUnlock()

	now := time.Now()
	type action struct {
		linkID    []byte
		keepalive bool
		close     bool
	}
	var actions []action

	t.linkManager.mu.Lock()
	for _, l := range t.linkManager.links {
		l.mu.Lock()
		if l.State != LinkActive {
			l.mu.Unlock()
			continue
		}
		isInitiator := l.responderIdentity == nil && l.peerDestHash != nil
		idleFor := now.Sub(l.LastActivity)
		linkID := append([]byte(nil), l.ID...)
		l.mu.Unlock()

		switch {
		case idleFor >= idle:
			actions = append(actions, action{linkID: linkID, close: true})
		case isInitiator && idleFor >= keepalive:
			actions = append(actions, action{linkID: linkID, keepalive: true})
		}
	}
	t.linkManager.mu.Unlock()

	for _, a := range actions {
		if a.close {
			t.logger.Printf("link sweep: closing idle link %x", a.linkID[:4])
			t.linkManager.CloseLink(a.linkID)
			continue
		}
		if a.keepalive {
			pkt, err := BuildLinkKeepalive(a.linkID)
			if err != nil {
				t.logger.Printf("link sweep: build keepalive: %v", err)
				continue
			}
			// Re-route via HEADER_2 if the peer is multi-hop.
			if l := t.linkManager.Get(a.linkID); l != nil {
				peer := l.PeerDestHash()
				if peer != nil {
					if known := t.Recall(peer); known != nil {
						applyMultihopRouting(pkt, known.TransportID)
					}
				}
			}
			if err := t.Broadcast(pkt); err != nil {
				t.logger.Printf("link sweep: broadcast keepalive: %v", err)
				continue
			}
			// Bump LastActivity so we don't immediately re-emit on the
			// next tick if keepalive is short and broadcast takes time.
			if l := t.linkManager.Get(a.linkID); l != nil {
				l.mu.Lock()
				l.LastActivity = time.Now()
				l.mu.Unlock()
			}
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
