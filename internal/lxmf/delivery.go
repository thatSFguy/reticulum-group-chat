package lxmf

import (
	"errors"
	"fmt"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// ErrRecipientUnknown is returned by Send when the recipient hasn't
// announced yet, so we have no public key to encrypt to. Callers wrapping
// Send in a retry loop should treat this as a recoverable error: issue a
// path request to the recipient and try again later, since an inbound
// announce can populate the public key out-of-band.
var ErrRecipientUnknown = errors.New("recipient has not announced; cannot encrypt")

// ErrPropagationNodeUnknown is returned by SendPropagated when the
// propagation node hasn't announced yet — without its announce we have
// neither its public key (link handshake) nor its app_data (stamp cost,
// transfer limits). Recoverable the same way as ErrRecipientUnknown:
// request a path and retry.
var ErrPropagationNodeUnknown = errors.New("propagation node has not announced; cannot open link")

// ErrPropagationNodeDisabled is returned by SendPropagated when the
// node's most recent announce says it is not currently accepting
// messages (§5.8.5 element [2] false).
var ErrPropagationNodeDisabled = errors.New("propagation node is not accepting messages")

// ErrPropagationTransferTooLarge is returned when the packed bundle
// exceeds the per-transfer limit the node announced (§5.8.5 element [3]).
var ErrPropagationTransferTooLarge = errors.New("message exceeds propagation node per-transfer limit")

// ErrDeliveryProofTimeout is returned by Send when an opportunistic DATA
// packet went out but the recipient's SPEC §6.5 delivery proof never
// arrived — the LXMF-level signal for "recipient is offline or
// unreachable". Callers with a retry queue treat it like any transient
// failure; with propagation fallback configured, exhausting the retry
// budget on this error re-routes the message via a propagation node.
var ErrDeliveryProofTimeout = errors.New("no delivery proof from recipient")

// DefaultDeliveryProofTimeout is how long Send waits for the recipient's
// §6.5 proof of an opportunistic DATA packet before reporting the
// attempt failed. Long enough for a multi-hop testnet round trip; short
// enough that five retries + backoff resolve to the propagation
// fallback within ~2 minutes.
const DefaultDeliveryProofTimeout = 15 * time.Second

// Delivery is an LXMF "delivery destination" registered on a Transport.
// Inbound opportunistic LXMF messages addressed to its destination hash are
// Token-decrypted, parsed, signature-verified, and handed to OnMessage.
// Outbound messages are built, signed, Token-encrypted, and broadcast via
// the same Transport.
//
// One Delivery wraps one identity. Multi-tenant deployments would
// instantiate multiple Deliveries on the same Transport.
type Delivery struct {
	transport *rns.Transport
	identity  *rns.Identity
	destHash  []byte

	// OnMessage is called from the Transport's dispatcher goroutine for
	// each verified inbound message. If processing is non-trivial, the
	// callback should hand off to its own goroutine.
	OnMessage func(*Message)

	// OnError is called when an inbound packet can't be decrypted, parsed,
	// or verified. Implementations typically log.
	OnError func(error)

	// LinkSendTimeout caps the total elapsed time SendLink (or Send when
	// it falls through to link delivery) will spend on a single message:
	// LINKREQUEST/LRPROOF round-trip + DATA broadcast + DATA proof wait.
	// Defaults to rns.DefaultLinkSendTimeout (30s) when zero.
	LinkSendTimeout time.Duration

	// DeliveryProofTimeout caps how long an opportunistic Send waits for
	// the recipient's SPEC §6.5 delivery proof before returning
	// ErrDeliveryProofTimeout. 0 = DefaultDeliveryProofTimeout (15s).
	// Negative = fire-and-forget (return as soon as Broadcast does) —
	// the pre-v1.13 behavior, kept for tests and for callers that do
	// their own confirmation.
	DeliveryProofTimeout time.Duration
}

// NewDelivery registers the LXMF delivery destination for `identity` on
// `transport` and returns the wrapper. OnMessage and OnError can be set
// before or after this call (we check at dispatch time).
//
// `buildAnnounce`, if non-nil, lets the Transport answer SPEC §7.2
// path? requests targeting this destination. Pass a closure that
// produces a fresh announce with the given context byte (typically
// rns.ContextPathResponse). When nil, path? requests for our delivery
// destination go unanswered and clients have to wait for our periodic
// announce instead.
func NewDelivery(transport *rns.Transport, identity *rns.Identity, buildAnnounce func(context byte) (*rns.Packet, error)) (*Delivery, error) {
	if transport == nil || identity == nil {
		return nil, errors.New("nil transport or identity")
	}
	d := &Delivery{
		transport: transport,
		identity:  identity,
		destHash:  identity.DestinationHashFor(FullName()),
	}
	if err := transport.RegisterLocal(&rns.LocalDestination{
		DestHash:        d.destHash,
		Identity:        d.identity, // enables SPEC §6.5 PROOF emission on inbound DATA
		OnPacket:        d.handleInbound,
		OnLinkPlaintext: d.handleInboundLinkPlaintext,
		BuildAnnounce:   buildAnnounce,
	}); err != nil {
		return nil, err
	}
	return d, nil
}

// Hash returns this delivery destination's 16-byte hash.
func (d *Delivery) Hash() []byte {
	out := make([]byte, len(d.destHash))
	copy(out, d.destHash)
	return out
}

// Identity returns the underlying identity.
func (d *Delivery) Identity() *rns.Identity { return d.identity }

// Send delivers an LXMF message to `recipientDestHash`. Routes
// automatically:
//
//   - If the message fits the opportunistic single-packet cap
//     (MaxOpportunisticPayload, 295 bytes msgpack), it is sent in one
//     Token-encrypted Reticulum DATA packet, then BLOCKS until the
//     recipient's SPEC §6.5 delivery proof arrives or
//     DeliveryProofTimeout (15s default) elapses — an unreachable
//     recipient surfaces as ErrDeliveryProofTimeout instead of a
//     silent success.
//   - If it would overflow that cap, falls through to link delivery:
//     opens a Reticulum Link to the recipient (handshake) if no Active
//     one exists, then sends the LXMF body in direct form on the link
//     and BLOCKS until the responder's link DATA proof arrives or the
//     LinkSendTimeout elapses.
//
// The recipient MUST have announced previously, since we need their
// X25519 public key to encrypt opportunistically and their long-term
// Ed25519 public key to verify the LRPROOF + link DATA proofs. An
// unknown recipient yields an error before any wire activity.
func (d *Delivery) Send(recipientDestHash []byte, title, content []byte, fields map[any]any) error {
	_, err := d.SendWithID(recipientDestHash, title, content, fields)
	return err
}

// SendWithID is Send but also returns the 32-byte LXMF message_id the
// recipient will compute on parse (SPEC §5.4: H(dest||source||payload)).
// Returned on success; on error the returned msgID is nil. Used by the
// forwarding service to register the per-recipient view of a relayed
// bubble so reactions / reply-to fields can be rewritten to bind on the
// receiving client.
func (d *Delivery) SendWithID(recipientDestHash []byte, title, content []byte, fields map[any]any) (msgID []byte, err error) {
	if len(recipientDestHash) != rns.IdentityHashLen {
		return nil, fmt.Errorf("recipient dest_hash must be %d bytes", rns.IdentityHashLen)
	}
	known := d.transport.Recall(recipientDestHash)
	if known == nil {
		return nil, fmt.Errorf("%w: %x", ErrRecipientUnknown, recipientDestHash[:4])
	}

	// Try opportunistic first. signAndPackOpportunisticAt fails fast with
	// ErrPayloadTooLarge before doing any crypto if the payload won't
	// fit, so this branch costs at most one msgpack marshal for messages
	// that route to link delivery.
	body, packedID, err := SignAndPackOpportunistic(d.identity, d.destHash, recipientDestHash, title, content, fields)
	if err != nil {
		if errors.Is(err, ErrPayloadTooLarge) {
			return d.sendOverLink(recipientDestHash, title, content, fields)
		}
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Recipient's identity hash drives the Token HKDF salt (SPEC §3.2).
	recipientIdentityHash := identityHashFromPublic(known.PublicKey)
	ciphertext, err := rns.TokenEncrypt(body, known.X25519Public(), recipientIdentityHash)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	pkt := buildOutboundPacket(recipientDestHash, ciphertext, known.TransportID)

	// Delivery confirmation (SPEC §6.5): register for the recipient's
	// proof BEFORE broadcasting — a fast/local recipient can ack before
	// Broadcast returns. Without this wait, opportunistic Send is
	// fire-and-forget: it reports success the moment the packet leaves
	// our interface, an offline recipient never surfaces as a failure,
	// and retry/propagation-fallback logic upstream of us never engages.
	// HashablePart is invariant under the HEADER_1↔HEADER_2 rewriting
	// relays do in flight, so our hash matches what the recipient signs.
	hashable, err := pkt.HashablePart()
	if err != nil {
		return nil, fmt.Errorf("hashable: %w", err)
	}
	packetHash := sha256Sum(hashable)
	proofCh, cancelWaiter, err := d.transport.RegisterPacketProofWaiter(packetHash, known.Ed25519Public())
	if err != nil {
		return nil, fmt.Errorf("register proof waiter: %w", err)
	}
	defer cancelWaiter()

	if err := d.transport.Broadcast(pkt); err != nil {
		return nil, err
	}

	wait := d.DeliveryProofTimeout
	if wait < 0 {
		return packedID, nil // explicit fire-and-forget
	}
	if wait == 0 {
		wait = DefaultDeliveryProofTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case proofErr := <-proofCh:
		if proofErr != nil {
			return nil, proofErr
		}
		return packedID, nil
	case <-timer.C:
		return nil, fmt.Errorf("%w: %x after %s", ErrDeliveryProofTimeout, recipientDestHash[:4], wait)
	}
}

// sendOverLink is the link-delivery fallback path used by Send when the
// opportunistic msgpack payload would exceed MaxOpportunisticPayload.
// Builds the LXMF body in direct form (SPEC §5.2 — destination_hash is
// in the body because the outer Reticulum packet is addressed to a
// link_id, not the recipient destination), then hands the bytes to
// rns.Transport.SendOverLink which manages the link state machine and
// blocks for the responder's proof. Returns the LXMF message_id alongside
// the error so SendWithID can register the recipient view for cross-
// client reaction / reply rewriting.
func (d *Delivery) sendOverLink(recipientDestHash, title, content []byte, fields map[any]any) (msgID []byte, err error) {
	directBody, packedID, err := SignAndPackDirect(d.identity, d.destHash, recipientDestHash, title, content, fields)
	if err != nil {
		return nil, fmt.Errorf("pack direct: %w", err)
	}
	timeout := d.LinkSendTimeout
	if timeout <= 0 {
		timeout = rns.DefaultLinkSendTimeout
	}
	if err := d.transport.SendOverLink(recipientDestHash, directBody, timeout); err != nil {
		return nil, fmt.Errorf("link send: %w", err)
	}
	return packedID, nil
}

// SendPropagated submits an LXMF message for `recipientDestHash` to the
// propagation node at `nodeDestHash` for store-and-forward delivery
// (SPEC §5.8, flows/send-propagated-lxmf.md). The recipient fetches it
// later via /get; this call succeeds when the NODE has the message, not
// when the recipient does.
//
// Pipeline: pack the propagated form (encrypted to the RECIPIENT — the
// node never decrypts), grind a §5.7 propagation stamp if the node's
// announce demands one, wrap in the msgpack upload envelope, and ship it
// over a Link to the node's lxmf.propagation destination —
// Transport.SendOverLink picks single link DATA or a Resource transfer
// by size and blocks for the node's proof.
//
// Both the recipient AND the node must have announced: the recipient for
// the encryption keys, the node for the link handshake + its §5.8.5
// app_data (enabled state, stamp cost, transfer limit — all enforced
// here). Returns the recipient-view message_id, same as SendWithID.
func (d *Delivery) SendPropagated(nodeDestHash, recipientDestHash []byte, title, content []byte, fields map[any]any) (msgID []byte, err error) {
	if len(nodeDestHash) != rns.IdentityHashLen {
		return nil, fmt.Errorf("propagation node dest_hash must be %d bytes", rns.IdentityHashLen)
	}
	if len(recipientDestHash) != rns.IdentityHashLen {
		return nil, fmt.Errorf("recipient dest_hash must be %d bytes", rns.IdentityHashLen)
	}
	recipient := d.transport.Recall(recipientDestHash)
	if recipient == nil {
		return nil, fmt.Errorf("%w: %x", ErrRecipientUnknown, recipientDestHash[:4])
	}
	node := d.transport.Recall(nodeDestHash)
	if node == nil {
		return nil, fmt.Errorf("%w: %x", ErrPropagationNodeUnknown, nodeDestHash[:4])
	}
	info, err := ParsePropagationNodeAppData(node.AppData)
	if err != nil {
		return nil, fmt.Errorf("node %x: %w", nodeDestHash[:4], err)
	}
	if !info.Enabled {
		return nil, fmt.Errorf("%w: %x", ErrPropagationNodeDisabled, nodeDestHash[:4])
	}

	lxmfData, transientID, packedID, err := SignAndPackPropagated(
		d.identity, d.destHash, recipientDestHash,
		recipient.X25519Public(), identityHashFromPublic(recipient.PublicKey),
		title, content, fields)
	if err != nil {
		return nil, fmt.Errorf("pack propagated: %w", err)
	}

	if info.StampCost > 0 {
		stamp, err := GeneratePropagationStamp(transientID, info.StampCost)
		if err != nil {
			return nil, fmt.Errorf("node %x: %w", nodeDestHash[:4], err)
		}
		// Appended AFTER the transient_id is computed — the stamp is
		// derived from it (flows/send-propagated-lxmf.md step 5).
		lxmfData = append(lxmfData, stamp...)
	}

	bundle, err := PackPropagationBundle(time.Now(), lxmfData)
	if err != nil {
		return nil, err
	}
	if info.PerTransferLimitKB > 0 && int64(len(bundle)) > info.PerTransferLimitKB*1000 {
		return nil, fmt.Errorf("%w: bundle is %d B, node cap is %d KB",
			ErrPropagationTransferTooLarge, len(bundle), info.PerTransferLimitKB)
	}

	timeout := d.LinkSendTimeout
	if timeout <= 0 {
		timeout = rns.DefaultLinkSendTimeout
	}
	if err := d.transport.SendOverLink(nodeDestHash, bundle, timeout); err != nil {
		return nil, fmt.Errorf("propagation upload: %w", err)
	}
	return packedID, nil
}

// buildOutboundPacket frames the encrypted LXMF body as a Reticulum DATA
// packet. If a transport_id is known (the recipient announced via a
// HEADER_2 relay), we emit HEADER_2 with TransportType=NetworkTransport
// per SPEC §2.3 so relays can route the packet to the multi-hop recipient.
// Otherwise we emit HEADER_1 broadcast — sufficient for direct neighbors
// and for cases where the receiving rnsd auto-fills transport_id for a
// 1-hop local client.
func buildOutboundPacket(recipientDestHash, ciphertext, transportID []byte) *rns.Packet {
	if len(transportID) == rns.IdentityHashLen {
		return &rns.Packet{
			HeaderType:      rns.HeaderType2,
			ContextFlag:     false,
			TransportType:   rns.NetworkTransport,
			DestinationType: rns.DestinationSingle,
			PacketType:      rns.PacketData,
			Hops:            0,
			TransportID:     transportID,
			DestHash:        recipientDestHash,
			Context:         rns.ContextNone,
			Data:            ciphertext,
		}
	}
	return &rns.Packet{
		HeaderType:      rns.HeaderType1,
		ContextFlag:     false,
		TransportType:   rns.BroadcastTransport,
		DestinationType: rns.DestinationSingle,
		PacketType:      rns.PacketData,
		Hops:            0,
		DestHash:        recipientDestHash,
		Context:         rns.ContextNone,
		Data:            ciphertext,
	}
}

// handleInbound is invoked by the Transport for each DATA packet
// addressed to our destination hash. It does Token decrypt + LXMF parse
// + signature verify, then fires OnMessage on success.
func (d *Delivery) handleInbound(p *rns.Packet) {
	plain, err := rns.TokenDecrypt(d.identity, p.Data)
	if err != nil {
		d.errorf("decrypt: %w", err)
		return
	}

	msg, err := ParseOpportunisticBody(plain, p.DestHash)
	if err != nil {
		d.errorf("parse: %w", err)
		return
	}

	sender := d.transport.Recall(msg.SourceHash)
	if sender == nil {
		d.errorf("sender %x unknown — must announce first", msg.SourceHash[:4])
		// Ask the network for their announce. Future messages from this
		// sender will succeed once a path-response announce arrives and
		// populates Transport.known. The current message stays dropped —
		// PROOF was already emitted so the mobile client won't retry it.
		if err := d.transport.RequestPath(msg.SourceHash); err != nil {
			d.errorf("path? request: %w", err)
		}
		return
	}
	if err := msg.Verify(sender.Ed25519Public()); err != nil {
		d.errorf("verify: %w", err)
		return
	}

	if d.OnMessage != nil {
		// CRITICAL: dispatch on a goroutine so a slow OnMessage cannot
		// block the Transport dispatcher. The forwarder calls
		// Delivery.Send from within OnMessage, and Send may block on a
		// Reticulum Link handshake (LRPROOF round-trip) — which arrives
		// on the SAME dispatcher goroutine. Running OnMessage inline
		// causes a deadlock: dispatch is stuck in Send waiting for an
		// LRPROOF that's queued waiting for dispatch. Spawning here
		// turns Send's blocking semantics back into the per-call wait
		// it's documented to be, without holding the dispatcher.
		go d.OnMessage(msg)
	}
}

// handleInboundLinkPlaintext is invoked by the Transport when a link
// DATA packet addressed to our destination has been decrypted on an
// active Link. The plaintext is the FULL LXMF body in direct form
// (SPEC §5.2): dest_hash || source_hash || sig || msgpack — unlike
// opportunistic, the dest_hash is in the body itself because the outer
// Reticulum packet was addressed to a link_id rather than our
// destination.
//
// The link layer has already done its own authenticated decryption +
// per-packet PROOF; this function just extracts the LXMF semantics and
// fires the application-level OnMessage callback.
func (d *Delivery) handleInboundLinkPlaintext(plaintext []byte) {
	msg, err := ParseDirectBody(plaintext)
	if err != nil {
		d.errorf("link LXMF parse: %w", err)
		return
	}
	sender := d.transport.Recall(msg.SourceHash)
	if sender == nil {
		d.errorf("link sender %x unknown — must announce first", msg.SourceHash[:4])
		if err := d.transport.RequestPath(msg.SourceHash); err != nil {
			d.errorf("path? request: %w", err)
		}
		return
	}
	if err := msg.Verify(sender.Ed25519Public()); err != nil {
		d.errorf("link LXMF verify: %w", err)
		return
	}
	if d.OnMessage != nil {
		// CRITICAL: dispatch on a goroutine so a slow OnMessage cannot
		// block the Transport dispatcher. The forwarder calls
		// Delivery.Send from within OnMessage, and Send may block on a
		// Reticulum Link handshake (LRPROOF round-trip) — which arrives
		// on the SAME dispatcher goroutine. Running OnMessage inline
		// causes a deadlock: dispatch is stuck in Send waiting for an
		// LRPROOF that's queued waiting for dispatch. Spawning here
		// turns Send's blocking semantics back into the per-call wait
		// it's documented to be, without holding the dispatcher.
		go d.OnMessage(msg)
	}
}

func (d *Delivery) errorf(format string, args ...any) {
	if d.OnError != nil {
		d.OnError(fmt.Errorf(format, args...))
	}
}

// identityHashFromPublic recomputes the recipient's identity hash from
// their announced public key. Needed because Transport.Recall holds the
// public key + dest_hash, but the Token cipher's HKDF salt is the
// identity hash (SPEC §3.2).
func identityHashFromPublic(publicKey []byte) []byte {
	h := sha256Sum(publicKey)
	return h[:rns.IdentityHashLen]
}

// sha256Sum is a trivial wrapper to avoid an import cycle in the body of
// identityHashFromPublic above.
func sha256Sum(b []byte) []byte {
	hash := newSHA256()
	hash.Write(b)
	return hash.Sum(nil)
}
