package service

import (
	"github.com/svanichkin/go-lxmf/lxmf"
	"github.com/svanichkin/go-reticulum/rns"
)

// sendDirect builds an opportunistic LXMF message addressed to the given
// 16-byte recipient identity hash and queues it through our LXMRouter.
// title may be empty.
func (s *Service) sendDirect(recipientHash []byte, title, content string) {
	if len(recipientHash) != 16 {
		s.logger.Printf("sendDirect: bad recipient hash length %d", len(recipientHash))
		return
	}

	recipientID := rns.IdentityRecall(recipientHash)
	if recipientID == nil {
		// We've never seen the recipient announce. We can't sign/encrypt to
		// an unknown identity. The message is dropped silently; a future
		// announce will let them receive subsequent messages.
		s.logger.Printf("dropping send to unknown identity %x (no announce seen)", recipientHash[:4])
		return
	}

	recipientDest, err := rns.NewDestination(
		recipientID,
		rns.DestinationOUT,
		rns.DestinationSINGLE,
		"lxmf", "delivery",
	)
	if err != nil {
		s.logger.Printf("destination build failed for %x: %v", recipientHash[:4], err)
		return
	}

	msg, err := lxmf.NewLXMessage(
		recipientDest,    // destination (outbound)
		s.destination,    // source (our delivery destination)
		content,
		title,
		nil,              // fields
		lxmf.MethodOpportunistic,
		recipientHash,
		s.destination.Hash,
		nil,              // stampCost
		false,            // includeTicket
	)
	if err != nil {
		s.logger.Printf("compose failed for %x: %v", recipientHash[:4], err)
		return
	}
	s.router.HandleOutbound(msg)
}
