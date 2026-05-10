package rns

import (
	"context"
	"errors"
	"fmt"
)

// Transport-level dispatch for inbound RESOURCE_* packets. Lives
// here (not in transport.go) so the resource state machine and its
// dispatcher routing stay grouped — easier to find when chasing a
// resource bug, easier to delete the whole feature if it ever needs
// to be ripped out.

// handleResourceControl decrypts the body of an inbound link DATA
// packet whose context is one of the encrypted RESOURCE_* control
// types (ADV, REQ, HMU, ICL, RCL), then routes by context to the
// matching sender or receiver.
//
// Decryption uses the link's session keys, same form as a normal
// link DATA packet — only the context byte differs. A failure to
// decrypt is logged and dropped; we don't tear down the link, since
// transit relays may legitimately deliver a stale packet from a
// previous link incarnation.
func (t *Transport) handleResourceControl(p *Packet) {
	link := t.linkManager.Get(p.DestHash)
	if link == nil {
		t.logger.Printf("resource control 0x%02x for unknown link_id %x", p.Context, p.DestHash[:4])
		return
	}
	link.mu.Lock()
	state := link.State
	signing := link.Signing
	encryption := link.Encryption
	link.mu.Unlock()
	if state != LinkActive {
		t.logger.Printf("resource control 0x%02x on link in state %s", p.Context, state)
		return
	}
	plaintext, err := LinkTokenDecrypt(p.Data, signing, encryption)
	if err != nil {
		t.logger.Printf("resource control decrypt: %v", err)
		return
	}

	switch p.Context {
	case ContextResourceADV:
		t.handleResourceAdv(link, plaintext)
	case ContextResourceREQ:
		t.handleResourceReq(link, plaintext)
	case ContextResourceHMU:
		t.handleResourceHmu(link, plaintext)
	case ContextResourceICL:
		t.handleResourceCancelInbound(link, plaintext, true /* initiator-side cancel → tells receiver */)
	case ContextResourceRCL:
		t.handleResourceCancelInbound(link, plaintext, false /* receiver-side cancel → tells sender */)
	default:
		t.logger.Printf("resource control: unexpected context 0x%02x", p.Context)
	}
}

// handleResourceAdv parses an inbound RESOURCE_ADV body. Stage-4
// territory — for now this validates the wire format so a malformed
// ADV doesn't go unnoticed in the logs, and emits a receiver-cancel
// so the sender stops retransmitting instead of timing out.
func (t *Transport) handleResourceAdv(link *Link, plaintext []byte) {
	adv, err := ParseResourceAdv(plaintext)
	if err != nil {
		t.logger.Printf("resource ADV parse: %v", err)
		// If the ADV was structurally malformed we can't even RCL
		// (no resource_hash to cite). The sender's watchdog will give
		// up on its own.
		return
	}
	t.logger.Printf("resource ADV inbound link=%x resource=%s parts=%d t=%d d=%d",
		link.ID[:4], ResourceHashShortHex(adv.Hash), adv.NumParts, adv.TransferSize, adv.DataSize)

	if err := t.openResourceReceiver(link, adv); err != nil {
		t.logger.Printf("resource ADV open receiver: %v", err)
		// Politely reject so the sender stops retransmitting.
		if rcErr := t.broadcastResourceCancel(link, adv.Hash, false /* RCL */); rcErr != nil {
			t.logger.Printf("resource RCL emit: %v", rcErr)
		}
	}
}

// handleResourceReq routes an inbound RESOURCE_REQ to the sender
// matching (link_id, resource_hash). Drops silently if no sender
// matches — most likely cause is a duplicate REQ arriving after the
// transfer already completed and the sender unregistered.
func (t *Transport) handleResourceReq(link *Link, plaintext []byte) {
	req, err := ParseResourceReq(plaintext)
	if err != nil {
		t.logger.Printf("resource REQ parse: %v", err)
		return
	}
	rs := t.linkManager.lookupResourceSender(link.ID, req.ResourceHash)
	if rs == nil {
		t.logger.Printf("resource REQ for unknown sender link=%x resource=%s",
			link.ID[:4], ResourceHashShortHex(req.ResourceHash))
		return
	}
	rs.HandleRequest(req)
}

// handleResourceHmu routes an inbound RESOURCE_HMU to the receiver
// matching (link_id, resource_hash). The receiver extends its
// hashmap and continues requesting parts in the new range.
func (t *Transport) handleResourceHmu(link *Link, plaintext []byte) {
	h, err := ParseResourceHmu(plaintext)
	if err != nil {
		t.logger.Printf("resource HMU parse: %v", err)
		return
	}
	rr := t.linkManager.lookupResourceReceiver(link.ID, h.ResourceHash)
	if rr == nil {
		t.logger.Printf("resource HMU for unknown receiver link=%x resource=%s",
			link.ID[:4], ResourceHashShortHex(h.ResourceHash))
		return
	}
	rr.HandleHmu(h)
}

// handleResourceCancelInbound routes an inbound RESOURCE_ICL or
// RESOURCE_RCL. ICL (initiator cancel) terminates a receiver; RCL
// (receiver cancel) terminates a sender.
func (t *Transport) handleResourceCancelInbound(link *Link, plaintext []byte, isICL bool) {
	resourceHash, err := ParseResourceCancel(plaintext)
	if err != nil {
		t.logger.Printf("resource cancel parse: %v", err)
		return
	}
	if isICL {
		// Initiator cancelled → tell the local receiver.
		if rr := t.linkManager.lookupResourceReceiver(link.ID, resourceHash); rr != nil {
			rr.HandleCancel()
			return
		}
	} else {
		// Receiver cancelled → tell the local sender.
		if rs := t.linkManager.lookupResourceSender(link.ID, resourceHash); rs != nil {
			rs.HandleCancel()
			return
		}
	}
	t.logger.Printf("resource cancel for unknown transfer link=%x resource=%s isICL=%v",
		link.ID[:4], ResourceHashShortHex(resourceHash), isICL)
}

// handleResourcePart routes an inbound RESOURCE-context packet (a
// raw ciphertext slice of one part) to the matching receiver on
// this link. Parts don't carry resource_hash in-band — the matching
// is by map_hash, which the receiver computes once it has the part.
// We delegate to whichever receiver on this link can place it; in
// fwdsvc that's almost always the single in-flight inbound resource.
func (t *Transport) handleResourcePart(p *Packet) {
	// Walk receivers registered on this link. We scan the registry
	// once (under its own lock) and dispatch outside.
	t.linkManager.mu.Lock()
	prefix := resourceKey(p.DestHash, nil)[:len(resourceKey(p.DestHash, nil))-1] // hex(link_id) + ":"
	receivers := make([]*ResourceReceiver, 0, 1)
	for k, rr := range t.linkManager.receivers {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			receivers = append(receivers, rr)
		}
	}
	t.linkManager.mu.Unlock()

	if len(receivers) == 0 {
		// No active receiver — stale part from a completed transfer.
		// Drop quietly.
		return
	}
	// Hand the part to every receiver; only the one whose hashmap
	// matches will actually place it (others reject internally).
	for _, rr := range receivers {
		rr.HandlePart(p.Data)
	}
}

// handleResourceProof routes an inbound RESOURCE_PRF (PROOF-type
// packet) to the matching sender. PRF body is NOT encrypted (SPEC
// §10.3 + upstream Packet.pack:195-197).
func (t *Transport) handleResourceProof(p *Packet) {
	link := t.linkManager.Get(p.DestHash)
	if link == nil {
		t.logger.Printf("resource PRF for unknown link_id %x", p.DestHash[:4])
		return
	}
	prf, err := ParseResourceProof(p.Data)
	if err != nil {
		t.logger.Printf("resource PRF parse: %v", err)
		return
	}
	rs := t.linkManager.lookupResourceSender(link.ID, prf.ResourceHash)
	if rs == nil {
		// Likely duplicate or late PRF after sender already exited.
		// Drop silently — no retry semantics required.
		return
	}
	rs.HandleProof(prf)
}

// broadcastResourceCancel emits an ICL or RCL on `link` for
// `resourceHash`. Body is link-encrypted (it's a control packet, not
// a part). isICL=true → initiator cancel; false → receiver cancel.
func (t *Transport) broadcastResourceCancel(link *Link, resourceHash []byte, isICL bool) error {
	link.mu.Lock()
	state := link.State
	signing := link.Signing
	encryption := link.Encryption
	linkID := append([]byte(nil), link.ID...)
	link.mu.Unlock()
	if state != LinkActive {
		return fmt.Errorf("cannot cancel: link state %s", state)
	}
	body, err := BuildResourceCancel(resourceHash)
	if err != nil {
		return err
	}
	ciphertext, err := LinkTokenEncrypt(body, signing, encryption)
	if err != nil {
		return fmt.Errorf("encrypt cancel: %w", err)
	}
	context := ContextResourceRCL
	if isICL {
		context = ContextResourceICL
	}
	pkt, err := buildResourceCtxPacket(linkID, ciphertext, context, false)
	if err != nil {
		return err
	}
	return t.Broadcast(pkt)
}

// SendResourceOverLink builds a ResourceSender for `body` on `link`,
// registers it with the LinkManager so inbound REQ/PRF/RCL route to
// it, and runs the transfer to completion. Blocks until success,
// timeout, or peer cancellation.
//
// `body` is the FULL plaintext to deliver — for an LXMF DIRECT
// resource that's the direct-form body (dest_hash || source_hash ||
// sig || msgpack). The sender link-encrypts it before slicing.
//
// Returns nil on RESOURCE_PRF receipt + validation. Otherwise:
//   - context.DeadlineExceeded / context.Canceled — caller-side
//   - ErrResourceTimeout — ADV retries exhausted
//   - ErrResourceProofMismatch — PRF returned but didn't validate
//   - ErrResourceCancelled — peer sent RCL or link was torn down
func (t *Transport) SendResourceOverLink(ctx context.Context, link *Link, body []byte, transportID []byte) error {
	if link == nil {
		return errors.New("SendResourceOverLink: nil link")
	}
	rs, err := NewResourceSender(t, link, body, transportID, t.logger)
	if err != nil {
		return err
	}
	if err := t.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
		return err
	}
	return rs.Run(ctx)
}
