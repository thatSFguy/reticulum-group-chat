package service

import "github.com/svanichkin/go-reticulum/rns"

// announceTap is an rns announce handler that updates a roster member's
// last_announce_at whenever we hear them announce on the lxmf.delivery
// aspect. We do NOT auto-add new users from announces alone — only message
// senders join.
//
// destinationHash here is the announcer's lxmf.delivery destination hash,
// which is the same identifier we get back as msg.SourceHash on inbound
// LXMF messages. Storing destination hashes (not identity hashes) is what
// lets the two paths converge on a single roster key.
type announceTap struct {
	svc *Service
}

func (t *announceTap) AspectFilter() string {
	return "lxmf.delivery"
}

func (t *announceTap) ReceivePathResponses() bool { return true }

func (t *announceTap) ReceivedAnnounce(destinationHash []byte, announcedIdentity *rns.Identity, appData []byte) {
	if len(destinationHash) != 16 {
		return
	}
	if err := t.svc.roster.UpdateLastAnnounce(destinationHash, t.svc.now()); err != nil {
		t.svc.logger.Printf("announce update failed: %v", err)
	}
}
