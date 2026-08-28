package service

import (
	"testing"

	"github.com/thatSFguy/reticulum-go/rns"
)

// announcedStampCost drives the real announce builder and reads element
// [1] back off the wire, so these tests fail if the app_data encoding
// changes shape — not just if the config field stops being copied.
func announcedStampCost(t *testing.T, svc *Service) int {
	t.Helper()
	pkt, err := svc.buildAnnounce()
	if err != nil {
		t.Fatalf("buildAnnounce: %v", err)
	}
	a, err := rns.ParseAnnounce(pkt)
	if err != nil {
		t.Fatalf("ParseAnnounce: %v", err)
	}
	cost, err := rns.DecodeLXMFAppDataStampCost(a.AppData)
	if err != nil {
		t.Fatalf("DecodeLXMFAppDataStampCost: %v", err)
	}
	// The display name shares the app_data array with the cost, so check
	// it here too: a bad encoding that still yields the right cost would
	// otherwise pass while making us anonymous to every client.
	name, err := rns.DecodeLXMFAppDataDisplayName(a.AppData)
	if err != nil {
		t.Fatalf("DecodeLXMFAppDataDisplayName: %v", err)
	}
	if string(name) != "test" {
		t.Errorf("display name = %q, want %q", name, "test")
	}
	return cost
}

func TestAnnounceOmitsStampCostByDefault(t *testing.T) {
	svc := newTestService(t, "")
	if cost := announcedStampCost(t, svc); cost != 0 {
		t.Errorf("announced stamp_cost = %d, want 0 (no demand)", cost)
	}
	// The announce and the validator must agree; both off is the
	// pre-existing behaviour and must survive an upgrade untouched.
	if svc.delivery.InboundStampCost != 0 {
		t.Errorf("delivery.InboundStampCost = %d, want 0", svc.delivery.InboundStampCost)
	}
	if svc.delivery.EnforceStamps {
		t.Error("delivery.EnforceStamps = true, want false by default")
	}
}

func TestAnnouncePublishesConfiguredStampCost(t *testing.T) {
	svc := newTestService(t, "inbound_stamp_cost = 8\n")
	if cost := announcedStampCost(t, svc); cost != 8 {
		t.Errorf("announced stamp_cost = %d, want 8", cost)
	}
	// Charging a cost we never announced would drop senders who had no
	// way to know it existed, so the two must be wired from one value.
	if svc.delivery.InboundStampCost != 8 {
		t.Errorf("delivery.InboundStampCost = %d, want 8", svc.delivery.InboundStampCost)
	}
	if svc.delivery.EnforceStamps {
		t.Error("delivery.EnforceStamps = true, want false without enforce_inbound_stamps")
	}
}

func TestEnforceInboundStampsReachesDelivery(t *testing.T) {
	svc := newTestService(t, "inbound_stamp_cost = 8\nenforce_inbound_stamps = true\n")
	if !svc.delivery.EnforceStamps {
		t.Error("delivery.EnforceStamps = false, want true")
	}
	if cost := announcedStampCost(t, svc); cost != 8 {
		t.Errorf("announced stamp_cost = %d, want 8", cost)
	}
}
