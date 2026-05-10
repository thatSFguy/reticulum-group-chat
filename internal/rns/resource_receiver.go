package rns

// ResourceReceiver: stage-4 implementation. The type is declared here
// so Stage 2's LinkManager registry methods can reference it without
// a forward-declaration trick. Stage 4 fills in the state machine.
//
// fwdsvc only needs an inbound Receiver when something larger than
// Link.MDU is sent TO us — that's any LXMF DM with body > ~431 bytes.
// Today no such DMs reach the relay (the daemon only does control
// commands and forwards), but interop completeness demands we
// implement and test this side too.

// ResourceReceiver collects the parts of an inbound resource,
// reassembles them, validates the hash, and emits the final proof.
// Construction happens lazily in Transport.handleLinkData when an
// ADV arrives on an active link.
type ResourceReceiver struct {
	// stub — populated in Stage 4
}

// HandleCancel is the receiver-side counterpart of
// ResourceSender.HandleCancel — invoked by LinkManager.closeResourcesForLink
// during link teardown. Stage 4 wires this to actually terminate the
// receive goroutine.
func (rr *ResourceReceiver) HandleCancel() {
	// stub
}
