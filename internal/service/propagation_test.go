package service

import (
	"bytes"
	"io"
	"log"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

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

func TestTrackerSelectsMostRecentEnabledNode(t *testing.T) {
	tr := newTestTracker(nil)
	if tr.Current() != nil {
		t.Fatal("empty tracker should have no current node")
	}

	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	clock = base.Add(time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true))
	clock = base.Add(2 * time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xcc, false)) // most recent but not accepting

	got := tr.Current()
	want := bytes.Repeat([]byte{0xbb}, 16)
	if !bytes.Equal(got, want) {
		t.Errorf("Current() = %x, want most recent ENABLED node %x", got, want)
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
