package rns

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeTestReceiver constructs a ResourceReceiver directly (bypassing
// openResourceReceiver so the test controls the Run context). The
// hashmap covers numParts entries but only knownPrefix of them are
// marked known — the shape of a multi-segment transfer waiting on an
// HMU when knownPrefix < numParts.
func makeTestReceiver(t *testing.T, numParts, knownPrefix int) (*ResourceReceiver, *captureIface) {
	t.Helper()
	link, tp, iface := makeActiveTestLink(t)

	hashmap := make([]byte, numParts*ResourceMapHashLen)
	for i := range hashmap {
		hashmap[i] = byte(i)
	}
	rr := &ResourceReceiver{
		transport:          tp,
		link:               link,
		logger:             noopLogger{},
		resourceHash:       bytes.Repeat([]byte{0xCD}, 32),
		randomR:            bytes.Repeat([]byte{0xEE}, 32),
		hashmap:            hashmap,
		hashmapKnownPrefix: knownPrefix,
		consecutiveHeight:  -1,
		parts:              make([][]byte, numParts),
		receivedFlags:      make([]bool, numParts),
		partCh:             make(chan []byte, 32),
		cancelCh:           make(chan struct{}, 1),
		hmuCh:              make(chan *ResourceHmu, 4),
		done:               make(chan struct{}),
		linkSigning:        append([]byte(nil), link.Signing...),
		linkEncryption:     append([]byte(nil), link.Encryption...),
	}
	rr.state.Store(int32(ResourceStateTransferring))
	return rr, iface
}

// findRcl scans captured wire packets for a RESOURCE_RCL and verifies
// its decrypted body names the receiver's resource_hash.
func findRcl(t *testing.T, rr *ResourceReceiver, iface *captureIface) bool {
	t.Helper()
	for _, raw := range iface.Snapshot() {
		pkt, err := ParsePacket(raw)
		if err != nil || pkt.Context != ContextResourceRCL {
			continue
		}
		plain, err := LinkTokenDecrypt(pkt.Data, rr.linkSigning, rr.linkEncryption)
		if err != nil {
			t.Errorf("RCL body did not decrypt: %v", err)
			return false
		}
		if !bytes.Contains(plain, rr.resourceHash) {
			t.Errorf("RCL body %x does not carry resource_hash", plain)
			return false
		}
		return true
	}
	return false
}

// SPEC §10.7 (RNS ≥ 1.3.9): an HMU whose hashmap segment decodes to
// zero map-hashes cancels the transfer — the receiver must RCL and
// fail, not re-request forever.
func TestReceiverEmptyHmuCancels(t *testing.T) {
	// First hashmap segment fully known, more parts beyond it — the
	// state in which the receiver legitimately waits for segment 1.
	rr, iface := makeTestReceiver(t, HashmapMaxLen+6, HashmapMaxLen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rr.Run(ctx) }()

	// Initial (exhausted-capable) REQ goes out first.
	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("receiver did not emit initial REQ")
	}

	rr.HandleHmu(&ResourceHmu{
		ResourceHash: rr.resourceHash,
		SegmentIndex: 1,
		HashmapBytes: nil, // empty continuation
	})

	select {
	case err := <-runDone:
		if !errors.Is(err, ErrResourceEmptyHmu) {
			t.Errorf("Run returned %v, want ErrResourceEmptyHmu", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after empty HMU")
	}
	if got := ResourceState(rr.state.Load()); got != ResourceStateFailed {
		t.Errorf("state = %s, want failed", got)
	}
	if !findRcl(t, rr, iface) {
		t.Error("no RESOURCE_RCL was broadcast after empty HMU")
	}
}

// SPEC §10.7 (RNS ≥ 1.3.9): an out-of-turn HMU (wrong segment_index)
// is ignored — the transfer keeps running.
func TestReceiverOutOfTurnHmuIgnored(t *testing.T) {
	rr, _ := makeTestReceiver(t, HashmapMaxLen+6, HashmapMaxLen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rr.Run(ctx) }()

	rr.HandleHmu(&ResourceHmu{
		ResourceHash: rr.resourceHash,
		SegmentIndex: 3, // expected segment is 1
		HashmapBytes: bytes.Repeat([]byte{0x01}, ResourceMapHashLen),
	})

	select {
	case err := <-runDone:
		t.Fatalf("Run exited (%v) on out-of-turn HMU; it should be ignored", err)
	case <-time.After(200 * time.Millisecond):
		// still running — correct
	}

	rr.HandleCancel()
	select {
	case err := <-runDone:
		if !errors.Is(err, ErrResourceCancelled) {
			t.Errorf("Run returned %v, want ErrResourceCancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// SPEC §10.9 (RNS ≥ 1.3.9): a receiver-side abort while the link is
// active puts a RESOURCE_RCL on the wire so the sender stops
// retransmitting.
func TestReceiverTimeoutSendsRcl(t *testing.T) {
	rr, iface := makeTestReceiver(t, 2, 2)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- rr.Run(ctx) }()

	// Let the initial REQ go out, then abort the transfer.
	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("receiver did not emit initial REQ")
	}
	cancel()

	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
	if !findRcl(t, rr, iface) {
		t.Error("no RESOURCE_RCL was broadcast on receiver-side abort")
	}
}

// TestDecompressBombIsBounded is the replacement defense for the c=1
// rejection lifted in v1.14.1. The fixture is 49 bytes of real Python
// bz2 output that expands to 10 MiB — a ~214,000x amplification — so
// the decompressor's OUTPUT must be bounded. The ADV's declared `d` is
// attacker-supplied and cannot be trusted on its own.
func TestDecompressBombIsBounded(t *testing.T) {
	bomb, err := os.ReadFile(filepath.Join("testdata", "bz2_bomb_10mib.bin"))
	if err != nil {
		t.Fatal(err)
	}

	// A sender that LIES about d: declares a tiny body, ships a bomb.
	rr := &ResourceReceiver{flags: int(ResourceFlagCompressed), dataSize: 1024}
	if _, err := rr.decompressIfNeeded(bomb); err == nil {
		t.Fatal("bomb accepted; the output bound is not enforced")
	} else if !errors.Is(err, ErrResourceTooLarge) {
		t.Errorf("err = %v, want ErrResourceTooLarge", err)
	}

	// And an honest-but-oversized d is still clamped by the absolute cap.
	rr2 := &ResourceReceiver{flags: int(ResourceFlagCompressed), dataSize: 10 << 20}
	if _, err := rr2.decompressIfNeeded(bomb); err == nil {
		t.Fatal("bomb accepted when d exceeds MaxDecompressedResourceLen")
	}
}

// TestDecompressRoundTrip is the functional half: legitimate compressed
// bodies — the ordinary prose that RNS compresses and that this service
// was silently dropping — must survive intact.
func TestDecompressRoundTrip(t *testing.T) {
	compressed, err := os.ReadFile(filepath.Join("testdata", "bz2_prose.bin"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join("testdata", "bz2_prose.expected"))
	if err != nil {
		t.Fatal(err)
	}

	rr := &ResourceReceiver{flags: int(ResourceFlagCompressed), dataSize: len(original)}
	got, err := rr.decompressIfNeeded(compressed)
	if err != nil {
		t.Fatalf("legitimate compressed body rejected: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(original))
	}

	// Uncompressed bodies must pass through untouched.
	rr.flags = 0
	if got, err := rr.decompressIfNeeded(original); err != nil || !bytes.Equal(got, original) {
		t.Errorf("uncompressed passthrough broken: %v", err)
	}
}
