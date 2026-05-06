package rns

import (
	"context"
	"encoding/hex"
	"errors"
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

	logger Logger
}

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
type LocalDestination struct {
	DestHash []byte
	OnPacket func(p *Packet)
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
		known:  map[string]*KnownIdentity{},
		locals: map[string]*LocalDestination{},
		logger: logger,
	}
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
		t.handleData(p)
	default:
		// LinkRequest, Proof — out of scope.
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
	dest.OnPacket(p)
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
