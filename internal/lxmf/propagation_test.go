package lxmf

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// validPNAppData builds a well-formed §5.8.5 announce payload the way
// upstream LXMRouter.get_propagation_node_app_data does.
func validPNAppData(t *testing.T, enabled bool, transferLimitKB int, stampCost int) []byte {
	t.Helper()
	data, err := msgpack.Marshal([]any{
		false,                  // [0] legacy flag
		time.Now().Unix(),      // [1] timebase
		enabled,                // [2] node_state
		transferLimitKB,        // [3] per-transfer limit KB
		transferLimitKB,        // [4] per-sync limit KB
		[]any{stampCost, 0, 0}, // [5] [stamp_cost, flexibility, peering_cost]
		map[any]any{},          // [6] metadata
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParsePropagationNodeAppData(t *testing.T) {
	info, err := ParsePropagationNodeAppData(validPNAppData(t, true, 256, 8))
	if err != nil {
		t.Fatalf("valid app_data rejected: %v", err)
	}
	if !info.Enabled {
		t.Error("Enabled = false, want true")
	}
	if info.PerTransferLimitKB != 256 {
		t.Errorf("PerTransferLimitKB = %d, want 256", info.PerTransferLimitKB)
	}
	if info.StampCost != 8 {
		t.Errorf("StampCost = %d, want 8", info.StampCost)
	}
}

func TestParsePropagationNodeAppDataToleratesNilLimits(t *testing.T) {
	// Older LXMF announces None for unset limits/costs.
	data, _ := msgpack.Marshal([]any{
		false, int64(1700000000), true, nil, nil,
		[]any{nil, nil, nil}, map[any]any{},
	})
	info, err := ParsePropagationNodeAppData(data)
	if err != nil {
		t.Fatalf("nil limits rejected: %v", err)
	}
	if info.PerTransferLimitKB != 0 || info.StampCost != 0 {
		t.Errorf("nil limits should decode as 0, got %+v", info)
	}
}

func TestParsePropagationNodeAppDataRejectsMalformed(t *testing.T) {
	scalar5, _ := msgpack.Marshal([]any{ // [5] as scalar — the §5.8.5 documented interop break
		false, int64(1), true, 0, 0, 8, map[any]any{},
	})
	short, _ := msgpack.Marshal([]any{false, int64(1), true})
	twoCosts, _ := msgpack.Marshal([]any{
		false, int64(1), true, 0, 0, []any{1, 2}, map[any]any{},
	})
	for name, data := range map[string][]byte{
		"empty":            nil,
		"not msgpack":      {0xff, 0x01},
		"3 elements":       short,
		"[5] scalar":       scalar5,
		"[5] two elements": twoCosts,
	} {
		if _, err := ParsePropagationNodeAppData(data); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestSignAndPackPropagatedRoundtrip(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	lxmfData, transientID, msgID, err := SignAndPackPropagated(
		sender, senderDest, recipientDest,
		recipient.X25519Public(), recipient.Hash(),
		[]byte("title"), []byte("store and forward"), nil)
	if err != nil {
		t.Fatalf("SignAndPackPropagated: %v", err)
	}

	// The recipient dest_hash rides in the clear so the node can key the
	// message without decrypting.
	if !bytes.Equal(lxmfData[:rns.IdentityHashLen], recipientDest) {
		t.Errorf("lxmf_data prefix = %x, want recipient dest %x",
			lxmfData[:rns.IdentityHashLen], recipientDest)
	}
	wantTID := sha256.Sum256(lxmfData)
	if !bytes.Equal(transientID, wantTID[:]) {
		t.Errorf("transientID = %x, want SHA256(lxmf_data) = %x", transientID, wantTID)
	}

	// The encrypted interior must be byte-compatible with the
	// opportunistic receive path — that's what the recipient's client
	// runs after fetching from the node.
	plain, err := rns.TokenDecrypt(recipient, lxmfData[rns.IdentityHashLen:])
	if err != nil {
		t.Fatalf("recipient TokenDecrypt: %v", err)
	}
	msg, err := ParseOpportunisticBody(plain, recipientDest)
	if err != nil {
		t.Fatalf("ParseOpportunisticBody: %v", err)
	}
	if err := msg.Verify(sender.PublicKey()[32:]); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(msg.Content) != "store and forward" {
		t.Errorf("Content = %q", msg.Content)
	}
	if !bytes.Equal(msg.MessageID(), msgID) {
		t.Errorf("recipient-view message_id %x != packed %x", msg.MessageID(), msgID)
	}
}

func TestPackPropagationBundle(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	ts := time.Unix(1700000000, 500000000)
	bundle, err := PackPropagationBundle(ts, body)
	if err != nil {
		t.Fatal(err)
	}

	var outer []msgpack.RawMessage
	if err := msgpack.Unmarshal(bundle, &outer); err != nil {
		t.Fatalf("bundle is not a msgpack array: %v", err)
	}
	if len(outer) != 2 {
		t.Fatalf("bundle has %d elements, want 2", len(outer))
	}
	var timebase float64
	if err := msgpack.Unmarshal(outer[0], &timebase); err != nil {
		t.Fatalf("timebase: %v", err)
	}
	if timebase < 1699999999 || timebase > 1700000001 {
		t.Errorf("timebase = %f, want ~1700000000.5", timebase)
	}
	var bodies [][]byte
	if err := msgpack.Unmarshal(outer[1], &bodies); err != nil {
		t.Fatalf("bodies: %v", err)
	}
	if len(bodies) != 1 || !bytes.Equal(bodies[0], body) {
		t.Errorf("bodies = %x, want [%x]", bodies, body)
	}

	if _, err := PackPropagationBundle(ts); err == nil {
		t.Error("empty bundle should be rejected")
	}
}

func TestParsePropagationNodeAppDataToleratesFloatLimits(t *testing.T) {
	// Observed live: real propagation nodes announce per-transfer /
	// per-sync limits as msgpack float64 (Python config arithmetic),
	// e.g. node 1f981b6e on the michmesh testnet. Must decode, not
	// reject the node.
	data, _ := msgpack.Marshal([]any{
		false, int64(1700000000), true, float64(256.0), float64(1000.5),
		[]any{float64(8), 0, 0}, map[any]any{},
	})
	info, err := ParsePropagationNodeAppData(data)
	if err != nil {
		t.Fatalf("float limits rejected: %v", err)
	}
	if info.PerTransferLimitKB != 256 || info.PerSyncLimitKB != 1000 {
		t.Errorf("limits = %d/%d, want 256/1000", info.PerTransferLimitKB, info.PerSyncLimitKB)
	}
	if info.StampCost != 8 {
		t.Errorf("StampCost = %d, want 8", info.StampCost)
	}
}
