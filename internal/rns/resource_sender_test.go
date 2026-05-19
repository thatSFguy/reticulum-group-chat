package rns

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// --- test harness ----------------------------------------------------

// captureIface is an Interface that records every wire packet sent
// for later inspection. Done() never closes; tests cancel via ctx.
type captureIface struct {
	mu      sync.Mutex
	packets [][]byte
	inbox   chan []byte
	done    chan struct{}
}

func newCaptureIface() *captureIface {
	return &captureIface{
		inbox: make(chan []byte, 64),
		done:  make(chan struct{}),
	}
}

func (c *captureIface) Send(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, append([]byte(nil), b...))
	return nil
}

func (c *captureIface) Inbox() <-chan []byte    { return c.inbox }
func (c *captureIface) Done() <-chan struct{}   { return c.done }
func (c *captureIface) Snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.packets))
	for i, p := range c.packets {
		out[i] = append([]byte(nil), p...)
	}
	return out
}
func (c *captureIface) WaitForN(n int, deadline time.Time) bool {
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.packets)
		c.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// makeActiveTestLink creates a Link in Active state with random
// session keys so encrypt/decrypt round-trips. Bypasses the LR
// handshake for unit-test setup speed.
func makeActiveTestLink(t *testing.T) (*Link, *Transport, *captureIface) {
	t.Helper()
	iface := newCaptureIface()
	tp := NewTransport(noopLogger{})
	tp.AddInterface(iface)

	link := &Link{
		ID:           bytes.Repeat([]byte{0xAB}, IdentityHashLen),
		State:        LinkActive,
		Signing:      bytes.Repeat([]byte{0x11}, 32),
		Encryption:   bytes.Repeat([]byte{0x22}, 32),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	tp.linkManager.mu.Lock()
	tp.linkManager.links[bytesHexEncode(link.ID)] = link
	tp.linkManager.mu.Unlock()

	return link, tp, iface
}

func bytesHexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0F]
	}
	return string(out)
}

// --- sender construction --------------------------------------------

func TestSenderBuildsValidADV(t *testing.T) {
	link, tp, _ := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0x42}, 600) // big enough to need 2 parts
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	adv, err := rs.ParseAdvertisement()
	if err != nil {
		t.Fatal(err)
	}
	if adv.DataSize != len(body) {
		t.Errorf("d=%d, want %d", adv.DataSize, len(body))
	}
	if adv.NumParts < 2 {
		t.Errorf("n=%d, expected at least 2 parts for 600-byte body", adv.NumParts)
	}
	if !adv.HasFlag(ResourceFlagEncrypted) {
		t.Errorf("encrypted flag not set")
	}
	if !bytes.Equal(adv.Hash, rs.resourceHash) {
		t.Errorf("ADV.h != sender.resourceHash")
	}
	expectedHashmapBytes := adv.NumParts * ResourceMapHashLen
	if len(adv.Hashmap) != expectedHashmapBytes {
		t.Errorf("hashmap %d bytes, want %d", len(adv.Hashmap), expectedHashmapBytes)
	}
}

func TestSenderRejectsEmptyBody(t *testing.T) {
	link, tp, _ := makeActiveTestLink(t)
	if _, err := NewResourceSender(tp, link, nil, nil, noopLogger{}); err == nil {
		t.Error("expected error for nil body")
	}
	if _, err := NewResourceSender(tp, link, []byte{}, nil, noopLogger{}); err == nil {
		t.Error("expected error for empty body")
	}
}

func TestSenderRejectsInactiveLink(t *testing.T) {
	link, tp, _ := makeActiveTestLink(t)
	link.mu.Lock()
	link.State = LinkClosed
	link.mu.Unlock()
	if _, err := NewResourceSender(tp, link, []byte("hello"), nil, noopLogger{}); err == nil {
		t.Error("expected error for closed link")
	}
}

// --- sender state machine -------------------------------------------

// TestSenderHappyPath drives the full ADV → REQ → PARTS → PRF cycle
// against a captured-byte interface and asserts wire emissions in
// order. The ADV broadcast must come first; the parts must arrive
// after the REQ; PRF terminates the loop.
func TestSenderHappyPath(t *testing.T) {
	link, tp, iface := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0x42}, 600) // 2 parts after framing
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()

	// Wait for ADV broadcast.
	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("sender did not broadcast ADV within 2s")
	}
	advWire := iface.Snapshot()[0]
	advPkt, err := ParsePacket(advWire)
	if err != nil {
		t.Fatalf("parse ADV wire: %v", err)
	}
	if advPkt.Context != ContextResourceADV {
		t.Errorf("first packet context = 0x%02x, want RESOURCE_ADV (0x02)", advPkt.Context)
	}
	if advPkt.PacketType != PacketData {
		t.Errorf("ADV packet_type = %d, want PacketData", advPkt.PacketType)
	}
	// ADV body is link-Token-encrypted on the wire — decrypt before
	// parsing.
	advPlain, err := LinkTokenDecrypt(advPkt.Data, link.Signing, link.Encryption)
	if err != nil {
		t.Fatalf("decrypt ADV: %v", err)
	}
	advParsed, err := ParseResourceAdv(advPlain)
	if err != nil {
		t.Fatalf("parse ADV body: %v", err)
	}

	// Construct a REQ asking for both parts. Use the actual map_hashes
	// from the ADV so the sender's findPartByMapHash matches.
	requestedMap := [][]byte{}
	for i := 0; i < advParsed.NumParts; i++ {
		requestedMap = append(requestedMap, advParsed.MapHashAt(i))
	}
	rs.HandleRequest(&ResourceRequest{
		ResourceHash: advParsed.Hash,
		RequestedMap: requestedMap,
	})

	// Sender should emit one part packet per requested map_hash.
	wantTotal := 1 + advParsed.NumParts
	if !iface.WaitForN(wantTotal, time.Now().Add(2*time.Second)) {
		t.Fatalf("sender did not broadcast %d packets total within 2s (got %d)", wantTotal, len(iface.Snapshot()))
	}
	all := iface.Snapshot()
	for i, raw := range all[1:] {
		pkt, err := ParsePacket(raw)
		if err != nil {
			t.Errorf("part %d parse: %v", i, err)
			continue
		}
		if pkt.Context != ContextResource {
			t.Errorf("part %d context = 0x%02x, want RESOURCE (0x01)", i, pkt.Context)
		}
	}

	// Send the final proof.
	rs.HandleProof(&ResourceProof{
		ResourceHash: advParsed.Hash,
		FullProof:    rs.ExpectedProof(),
	})

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after PRF")
	}
	if rs.State() != ResourceStateComplete {
		t.Errorf("state = %s, want complete", rs.State())
	}
}

// TestSenderProofMismatchFails confirms that a forged/wrong
// expected_proof returns ErrResourceProofMismatch.
func TestSenderProofMismatchFails(t *testing.T) {
	link, tp, iface := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0x33}, 600)
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()

	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("sender did not broadcast ADV")
	}
	advWire := iface.Snapshot()[0]
	advPkt, _ := ParsePacket(advWire)
	advPlain, err := LinkTokenDecrypt(advPkt.Data, link.Signing, link.Encryption)
	if err != nil {
		t.Fatalf("decrypt ADV: %v", err)
	}
	advParsed, _ := ParseResourceAdv(advPlain)

	// Send REQ for all parts, then a BAD proof.
	requestedMap := [][]byte{}
	for i := 0; i < advParsed.NumParts; i++ {
		requestedMap = append(requestedMap, advParsed.MapHashAt(i))
	}
	rs.HandleRequest(&ResourceRequest{
		ResourceHash: advParsed.Hash,
		RequestedMap: requestedMap,
	})

	rs.HandleProof(&ResourceProof{
		ResourceHash: advParsed.Hash,
		FullProof:    bytes.Repeat([]byte{0x00}, 32), // wrong
	})

	select {
	case err := <-runDone:
		if !errors.Is(err, ErrResourceProofMismatch) {
			t.Errorf("Run returned %v, want ErrResourceProofMismatch", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after bad PRF")
	}
}

// TestSenderCancelExitsCleanly confirms a peer-side RCL terminates the
// sender with ErrResourceCancelled.
func TestSenderCancelExitsCleanly(t *testing.T) {
	link, tp, iface := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0x99}, 600)
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()

	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("sender did not broadcast ADV")
	}
	rs.HandleCancel()

	select {
	case err := <-runDone:
		if !errors.Is(err, ErrResourceCancelled) {
			t.Errorf("Run returned %v, want ErrResourceCancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// TestSenderContextCancelExitsCleanly confirms ctx cancel propagates.
func TestSenderContextCancelExitsCleanly(t *testing.T) {
	link, tp, _ := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0xAA}, 600)
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}

// TestSenderCloseLinkCancelsTransfer confirms LinkManager.CloseLink
// cancels in-flight resource transfers — preventing goroutine leaks
// when a peer tears down a link mid-transfer.
func TestSenderCloseLinkCancelsTransfer(t *testing.T) {
	link, tp, iface := makeActiveTestLink(t)
	body := bytes.Repeat([]byte{0xBB}, 600)
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()

	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("sender did not broadcast ADV")
	}
	tp.linkManager.CloseLink(link.ID)

	select {
	case err := <-runDone:
		if !errors.Is(err, ErrResourceCancelled) {
			t.Errorf("Run returned %v, want ErrResourceCancelled after CloseLink", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after CloseLink")
	}
}

// TestSenderExhaustedReqAlsoServesBundledParts is the regression guard
// for the 2026-05-19 incident (playbook §7): an exhausted RESOURCE_REQ
// may still carry a requested_map_hashes trailer, and the sender MUST
// serve those parts in ADDITION to the RESOURCE_HMU — not instead of
// it. Upstream Resource.request() fulfils parts unconditionally, then
// sends the HMU. A sender that skips part fulfilment for exhausted
// REQs silently drops every bundled part (the bug fixed here).
func TestSenderExhaustedReqAlsoServesBundledParts(t *testing.T) {
	link, tp, iface := makeActiveTestLink(t)

	// Body large enough to span more than one hashmap segment, so an
	// exhausted REQ followed by a RESOURCE_HMU is meaningful
	// (HashmapMaxLen = 74 parts per segment).
	body := bytes.Repeat([]byte{0x42}, 40*1024)
	rs, err := NewResourceSender(tp, link, body, nil, noopLogger{})
	if err != nil {
		t.Fatalf("NewResourceSender: %v", err)
	}
	if len(rs.parts) <= HashmapMaxLen {
		t.Fatalf("test needs a multi-segment resource: got %d parts, need > %d", len(rs.parts), HashmapMaxLen)
	}
	if err := tp.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- rs.Run(ctx) }()

	if !iface.WaitForN(1, time.Now().Add(2*time.Second)) {
		t.Fatal("sender did not broadcast ADV")
	}

	// map_hashes taken straight from the sender's full hashmap. Bundle
	// one segment-0 part (index 10) into an exhausted REQ whose
	// last_map_hash is the final entry of segment 0 (index
	// HashmapMaxLen-1) — that lands the next part index on a segment
	// boundary so serveHmu produces segment 1 cleanly.
	mapHashAt := func(i int) []byte {
		return append([]byte(nil), rs.hashmap[i*ResourceMapHashLen:(i+1)*ResourceMapHashLen]...)
	}
	rs.HandleRequest(&ResourceRequest{
		Exhausted:    true,
		LastMapHash:  mapHashAt(HashmapMaxLen - 1),
		ResourceHash: rs.ResourceHash(),
		RequestedMap: [][]byte{mapHashAt(10)},
	})

	// Expect ADV + the bundled part + the HMU = 3 wire packets. With
	// the pre-fix `continue`, the part was never emitted (only 2).
	if !iface.WaitForN(3, time.Now().Add(2*time.Second)) {
		t.Fatalf("sender emitted %d packets, want 3 (ADV + part + HMU) — bundled part likely dropped", len(iface.Snapshot()))
	}

	var sawPart, sawHMU bool
	for i, raw := range iface.Snapshot()[1:] {
		pkt, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("parse packet %d: %v", i+1, err)
		}
		switch pkt.Context {
		case ContextResource:
			sawPart = true
		case ContextResourceHMU:
			sawHMU = true
		}
	}
	if !sawPart {
		t.Error("sender did not emit the part bundled into the exhausted REQ")
	}
	if !sawHMU {
		t.Error("sender did not emit the RESOURCE_HMU for the exhausted REQ")
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}
