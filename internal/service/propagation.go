package service

import (
	"bytes"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

var lxmfPropagationNameHash = rns.NameHash(lxmf.PropagationFullName())

// propagationTracker watches lxmf.propagation announces (SPEC §5.8.5)
// and answers "which propagation node should outbound store-and-forward
// submissions go to right now?".
//
// Selection policy: a pinned node from config always wins — even before
// its first announce is heard, so the send path can surface
// ErrPropagationNodeUnknown and trigger a path request rather than
// silently using a different node than the operator chose. With no pin,
// the most recently heard node currently announcing itself as accepting
// (§5.8.5 element [2] true) is used; nodes announcing "not accepting"
// are remembered but never selected.
type propagationTracker struct {
	logger *log.Logger
	pinned []byte // nil when auto-discovering
	now    func() time.Time

	mu    sync.Mutex
	nodes map[string]*propagationNodeState // dest_hash hex → state
}

type propagationNodeState struct {
	destHash  []byte
	lastHeard time.Time
	enabled   bool
	stampCost int
}

func newPropagationTracker(logger *log.Logger, pinned []byte) *propagationTracker {
	return &propagationTracker{
		logger: logger,
		pinned: append([]byte(nil), pinned...),
		now:    time.Now,
		nodes:  map[string]*propagationNodeState{},
	}
}

// AspectMatch implements rns.AnnounceHandler — only lxmf.propagation
// announces reach OnAnnounce.
func (t *propagationTracker) AspectMatch(nameHash []byte) bool {
	return bytes.Equal(nameHash, lxmfPropagationNameHash)
}

// OnAnnounce parses the §5.8.5 app_data and records the node. Malformed
// app_data is logged and skipped — a node we can't parse is a node we
// can't negotiate stamps/limits with, so it is never a send candidate.
func (t *propagationTracker) OnAnnounce(a *rns.Announce) {
	info, err := lxmf.ParsePropagationNodeAppData(a.AppData)
	if err != nil {
		t.logger.Printf("propagation: ignoring node %x: %v", a.DestHash[:4], err)
		return
	}
	key := hex.EncodeToString(a.DestHash)
	now := t.now()

	t.mu.Lock()
	prev := t.nodes[key]
	t.nodes[key] = &propagationNodeState{
		destHash:  append([]byte(nil), a.DestHash...),
		lastHeard: now,
		enabled:   info.Enabled,
		stampCost: info.StampCost,
	}
	t.mu.Unlock()

	switch {
	case prev == nil:
		t.logger.Printf("propagation: discovered node %s (accepting=%v stamp_cost=%d transfer_limit=%dKB)",
			key[:8], info.Enabled, info.StampCost, info.PerTransferLimitKB)
	case prev.enabled != info.Enabled:
		t.logger.Printf("propagation: node %s now accepting=%v", key[:8], info.Enabled)
	}
}

// Current returns the destination hash of the node outbound submissions
// should use, or nil when none is available. See type docs for policy.
func (t *propagationTracker) Current() []byte {
	if len(t.pinned) > 0 {
		return append([]byte(nil), t.pinned...)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *propagationNodeState
	for _, n := range t.nodes {
		if !n.enabled {
			continue
		}
		if best == nil || n.lastHeard.After(best.lastHeard) {
			best = n
		}
	}
	if best == nil {
		return nil
	}
	return append([]byte(nil), best.destHash...)
}

// Compile-time guard: propagationTracker implements rns.AnnounceHandler.
var _ rns.AnnounceHandler = (*propagationTracker)(nil)
