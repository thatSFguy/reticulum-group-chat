package service

import (
	"bytes"
	"io"
	"log"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

func pnAnnounce(t *testing.T, destByte byte, enabled bool) *rns.Announce {
	t.Helper()
	appData, err := msgpack.Marshal([]any{
		false, time.Now().Unix(), enabled, 256, 256,
		[]any{0, 0, 0}, map[any]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rns.Announce{
		DestHash: bytes.Repeat([]byte{destByte}, 16),
		NameHash: lxmfPropagationNameHash,
		AppData:  appData,
	}
}

func pnAppData(t *testing.T, enabled bool, transferLimitKB, stampCost int) []byte {
	t.Helper()
	data, err := msgpack.Marshal([]any{
		false, time.Now().Unix(), enabled, transferLimitKB, transferLimitKB,
		[]any{stampCost, 0, 0}, map[any]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestTracker(pinned []byte) *propagationTracker {
	return newPropagationTracker(log.New(io.Discard, "", 0), pinned)
}

func TestTrackerAspectMatch(t *testing.T) {
	tr := newTestTracker(nil)
	if !tr.AspectMatch(lxmfPropagationNameHash) {
		t.Error("lxmf.propagation name hash should match")
	}
	if tr.AspectMatch(lxmfDeliveryNameHash) {
		t.Error("lxmf.delivery name hash should NOT match")
	}
}

func TestTrackerPrefersLongestKnownNode(t *testing.T) {
	// Selection must NOT be "most recently heard": announces are free
	// and unauthenticated, so that policy let an attacker announcing
	// rapidly seize the role from established nodes. Longest-known wins.
	tr := newTestTracker(nil)
	if tr.Current() != nil {
		t.Fatal("empty tracker should have no current node")
	}

	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	tr.OnAnnounce(pnAnnounce(t, 0xaa, true)) // established node
	clock = base.Add(time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true)) // newcomer

	// Newcomer announces again, most recently — must NOT win.
	clock = base.Add(2 * time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true))
	// Established node re-announces to stay fresh.
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))

	got := tr.Current()
	want := bytes.Repeat([]byte{0xaa}, 16)
	if !bytes.Equal(got, want) {
		t.Errorf("Current() = %x, want longest-known node %x", got, want)
	}
}

func TestTrackerDropsStaleNodes(t *testing.T) {
	tr := newTestTracker(nil)
	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	if tr.Current() == nil {
		t.Fatal("fresh node should be selectable")
	}
	// Past the staleness window with no re-announce.
	clock = base.Add(nodeStaleAfter + time.Minute)
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x, want nil for a stale node", got)
	}
}

func TestTrackerRejectsHostileParameters(t *testing.T) {
	// A node announcing parameters we cannot satisfy must be filtered
	// at SELECTION time. Discovering this at send time instead made the
	// error terminal for the MESSAGE (it is neither errNoPropagationNode
	// nor transient), so one hostile announce destroyed all fallback mail.
	for name, appData := range map[string][]byte{
		"stamp cost above local limit": pnAppData(t, true, 256, lxmf.MaxPropagationStampCost+1),
		"absurd stamp cost":            pnAppData(t, true, 256, 200),
		"implausible transfer limit":   pnAppData(t, true, 1, 0),
	} {
		tr := newTestTracker(nil)
		tr.OnAnnounce(&rns.Announce{
			DestHash: bytes.Repeat([]byte{0xee}, 16),
			NameHash: lxmfPropagationNameHash,
			AppData:  appData,
		})
		if got := tr.Current(); got != nil {
			t.Errorf("%s: node selected (%x); want rejected", name, got)
		}
	}
}

func TestTrackerNodeMapIsBounded(t *testing.T) {
	tr := newTestTracker(nil)
	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	// More distinct announcers than the cap, all fresh.
	for i := 0; i < maxTrackedNodes+100; i++ {
		clock = base.Add(time.Duration(i) * time.Second)
		tr.OnAnnounce(&rns.Announce{
			DestHash: bytes.Repeat([]byte{byte(i % 256), byte(i / 256)}, 8),
			NameHash: lxmfPropagationNameHash,
			AppData:  pnAppData(t, true, 256, 0),
		})
	}
	tr.mu.Lock()
	n := len(tr.nodes)
	tr.mu.Unlock()
	if n > maxTrackedNodes {
		t.Errorf("tracker holds %d nodes, want <= %d", n, maxTrackedNodes)
	}
}

func TestTrackerNodeStateFlipDeselects(t *testing.T) {
	tr := newTestTracker(nil)
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	tr.OnAnnounce(pnAnnounce(t, 0xaa, false))
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x after node flipped to not-accepting, want nil", got)
	}
}

func TestTrackerPinnedNodeWins(t *testing.T) {
	pinned := bytes.Repeat([]byte{0x11}, 16)
	tr := newTestTracker(pinned)

	// Pinned wins even before any announce, and even when a different
	// node has announced more recently.
	if got := tr.Current(); !bytes.Equal(got, pinned) {
		t.Errorf("Current() = %x, want pinned %x (before any announce)", got, pinned)
	}
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	if got := tr.Current(); !bytes.Equal(got, pinned) {
		t.Errorf("Current() = %x, want pinned %x (after other announce)", got, pinned)
	}
}

func TestTrackerIgnoresMalformedAppData(t *testing.T) {
	tr := newTestTracker(nil)
	tr.OnAnnounce(&rns.Announce{
		DestHash: bytes.Repeat([]byte{0xee}, 16),
		NameHash: lxmfPropagationNameHash,
		AppData:  []byte{0x01, 0x02},
	})
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x after malformed announce, want nil", got)
	}
}
