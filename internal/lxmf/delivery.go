package lxmf

import (
	"errors"
	"fmt"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

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
}

// NewDelivery registers the LXMF delivery destination for `identity` on
// `transport` and returns the wrapper. OnMessage and OnError can be set
// before or after this call (we check at dispatch time).
func NewDelivery(transport *rns.Transport, identity *rns.Identity) (*Delivery, error) {
	if transport == nil || identity == nil {
		return nil, errors.New("nil transport or identity")
	}
	d := &Delivery{
		transport: transport,
		identity:  identity,
		destHash:  identity.DestinationHashFor(FullName()),
	}
	if err := transport.RegisterLocal(&rns.LocalDestination{
		DestHash: d.destHash,
		OnPacket: d.handleInbound,
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

// Send builds an opportunistic LXMF message, Token-encrypts it for
// `recipientDestHash`, wraps it in a Reticulum DATA packet, and broadcasts
// it. The recipient MUST have announced previously, since we need their
// X25519 public key to encrypt; otherwise this returns an error.
func (d *Delivery) Send(recipientDestHash []byte, title, content []byte, fields map[any]any) error {
	if len(recipientDestHash) != rns.IdentityHashLen {
		return fmt.Errorf("recipient dest_hash must be %d bytes", rns.IdentityHashLen)
	}
	known := d.transport.Recall(recipientDestHash)
	if known == nil {
		return fmt.Errorf("recipient %x has not announced; cannot encrypt", recipientDestHash[:4])
	}

	// Recipient's identity hash drives the Token HKDF salt (SPEC §3.2).
	recipientIdentityHash := identityHashFromPublic(known.PublicKey)

	body, err := SignAndPackOpportunistic(d.identity, d.destHash, recipientDestHash, title, content, fields)
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	ciphertext, err := rns.TokenEncrypt(body, known.X25519Public(), recipientIdentityHash)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	pkt := buildOutboundPacket(recipientDestHash, ciphertext, known.TransportID)
	return d.transport.Broadcast(pkt)
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
		return
	}
	if err := msg.Verify(sender.Ed25519Public()); err != nil {
		d.errorf("verify: %w", err)
		return
	}

	if d.OnMessage != nil {
		d.OnMessage(msg)
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
