package lxmf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// This file implements the SENDER side of the SPEC §5.8 propagation-node
// protocol: packing a message in propagated form and bundling it for
// upload to a propagation node. The server role (storing and serving
// messages) and client retrieval (/get) are out of scope — recipients of
// this service run full clients (Sideband et al.) that fetch their own
// mail.

// PropagationNodeInfo is the parsed lxmf.propagation announce app_data
// (SPEC §5.8.5) — a strict 7-element msgpack array. Element [6]
// (operator metadata dict) is intentionally not surfaced; nothing in the
// send path needs it.
type PropagationNodeInfo struct {
	Timebase           int64 // [1] node clock, unix seconds
	Enabled            bool  // [2] accepting messages right now?
	PerTransferLimitKB int64 // [3] per-transfer cap in KB (0 = unlimited)
	PerSyncLimitKB     int64 // [4] per-sync incoming cap in KB
	StampCost          int   // [5][0] PoW cost required on submitted messages (0 = none)
	StampCostFlex      int   // [5][1] tolerance below StampCost still accepted
	PeeringCost        int   // [5][2] PoW cost for node-to-node peering keys
}

// ErrPropagationAppData is wrapped by every ParsePropagationNodeAppData
// failure so callers can errors.Is a malformed announce without matching
// message text.
var ErrPropagationAppData = errors.New("invalid lxmf.propagation announce app_data")

// ParsePropagationNodeAppData decodes the §5.8.5 announce payload,
// mirroring upstream pn_announce_data_is_valid: exactly 7 elements with
// type-correct positions. Element [5] MUST be a 3-element list — the
// spec calls out misparsing it as a single integer as the most common
// interop break, so we reject that shape explicitly rather than
// tolerating it.
func ParsePropagationNodeAppData(appData []byte) (*PropagationNodeInfo, error) {
	if len(appData) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrPropagationAppData)
	}
	var elems []msgpack.RawMessage
	if err := safeUnmarshal(appData, &elems); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPropagationAppData, err)
	}
	if len(elems) != 7 {
		return nil, fmt.Errorf("%w: %d elements, want 7", ErrPropagationAppData, len(elems))
	}

	info := &PropagationNodeInfo{}
	if err := safeUnmarshal(elems[1], &info.Timebase); err != nil {
		return nil, fmt.Errorf("%w: timebase: %v", ErrPropagationAppData, err)
	}
	if err := safeUnmarshal(elems[2], &info.Enabled); err != nil {
		return nil, fmt.Errorf("%w: node_state: %v", ErrPropagationAppData, err)
	}
	// [3]/[4] are ints in current upstream but were None in older
	// releases; tolerate nil as 0 (no declared limit).
	if err := decodeOptionalInt(elems[3], &info.PerTransferLimitKB); err != nil {
		return nil, fmt.Errorf("%w: per_transfer_limit: %v", ErrPropagationAppData, err)
	}
	if err := decodeOptionalInt(elems[4], &info.PerSyncLimitKB); err != nil {
		return nil, fmt.Errorf("%w: per_sync_limit: %v", ErrPropagationAppData, err)
	}

	var costs []msgpack.RawMessage
	if err := safeUnmarshal(elems[5], &costs); err != nil {
		return nil, fmt.Errorf("%w: element [5] must be a 3-element list, not a scalar: %v", ErrPropagationAppData, err)
	}
	if len(costs) != 3 {
		return nil, fmt.Errorf("%w: element [5] has %d entries, want 3", ErrPropagationAppData, len(costs))
	}
	for i, dst := range []*int{&info.StampCost, &info.StampCostFlex, &info.PeeringCost} {
		var v int64
		if err := decodeOptionalInt(costs[i], &v); err != nil {
			return nil, fmt.Errorf("%w: element [5][%d]: %v", ErrPropagationAppData, i, err)
		}
		*dst = int(v)
	}
	return info, nil
}

// decodeOptionalInt decodes a msgpack numeric, treating nil as 0. Older
// LXMF releases announce None for unset limits/costs, and live nodes
// have been observed announcing limits as msgpack float64 (Python
// config arithmetic like `limit_mb * 1000` produces a float) — accept
// int, float (truncated), and nil. A msgpack nil element surfaces
// either as the 0xc0 marker or as an empty RawMessage, depending on
// the decoder path — accept both.
func decodeOptionalInt(raw msgpack.RawMessage, out *int64) error {
	if len(raw) == 0 || (len(raw) == 1 && raw[0] == msgpackNil) {
		*out = 0
		return nil
	}
	if err := safeUnmarshal(raw, out); err == nil {
		return nil
	}
	var f float64
	if err := safeUnmarshal(raw, &f); err != nil {
		return err
	}
	*out = int64(f)
	return nil
}

// SignAndPackPropagated builds the propagated-form LXMF wire body
// (SPEC §5.8 / flows/send-propagated-lxmf.md step 2):
//
//	lxmf_data = dest_hash(16) || TokenEncrypt(source_hash(16) || sig(64) || msgpack_payload)
//
// The encrypted plaintext is byte-identical to the opportunistic form —
// the recipient runs the same decrypt+parse+verify path regardless of
// how the message arrived — but there is no single-packet size cap; the
// bundle rides a Link (packet or Resource) to the propagation node.
// The recipient's dest_hash is prepended in the clear so the node can
// key the message to its intended recipient; the node never decrypts.
//
// transientID is SHA256(lxmf_data) — the propagation store key and the
// workblock material for an optional propagation stamp (append the stamp
// to lxmf_data AFTER computing transientID; the stamp is derived from
// it). msgID is the recipient-view LXMF message_id, same as the other
// pack variants.
func SignAndPackPropagated(senderID *rns.Identity, senderDestHash, destHash, recipientX25519Pub, recipientIdentityHash []byte, title, content []byte, fields map[any]any) (lxmfData, transientID, msgID []byte, err error) {
	return signAndPackPropagatedAt(senderID, senderDestHash, destHash, recipientX25519Pub, recipientIdentityHash, title, content, fields, time.Now())
}

func signAndPackPropagatedAt(senderID *rns.Identity, senderDestHash, destHash, recipientX25519Pub, recipientIdentityHash []byte, title, content []byte, fields map[any]any, ts time.Time) (lxmfData, transientID, msgID []byte, err error) {
	payload, sig, id, err := buildSignedPayload(senderID, senderDestHash, destHash, title, content, fields, ts)
	if err != nil {
		return nil, nil, nil, err
	}

	plain := make([]byte, 0, rns.IdentityHashLen+len(sig)+len(payload))
	plain = append(plain, senderDestHash...)
	plain = append(plain, sig...)
	plain = append(plain, payload...)

	ciphertext, err := rns.TokenEncrypt(plain, recipientX25519Pub, recipientIdentityHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt propagated body: %w", err)
	}

	lxmfData = make([]byte, 0, rns.IdentityHashLen+len(ciphertext))
	lxmfData = append(lxmfData, destHash...)
	lxmfData = append(lxmfData, ciphertext...)

	tid := sha256.Sum256(lxmfData)
	return lxmfData, tid[:], id, nil
}

// PackPropagationBundle wraps one or more propagated-form bodies in the
// outer envelope a propagation node expects on upload (SPEC §5.8 /
// flows/send-propagated-lxmf.md step 2):
//
//	msgpack.packb([timebase_seconds(float64), [lxmf_data_1, ...]])
func PackPropagationBundle(ts time.Time, lxmfData ...[]byte) ([]byte, error) {
	if len(lxmfData) == 0 {
		return nil, errors.New("propagation bundle needs at least one message")
	}
	bodies := make([]any, len(lxmfData))
	for i, d := range lxmfData {
		bodies[i] = d
	}
	tsSeconds := float64(ts.UnixMicro()) / 1_000_000.0
	out, err := msgpack.Marshal([]any{tsSeconds, bodies})
	if err != nil {
		return nil, fmt.Errorf("marshal propagation bundle: %w", err)
	}
	return out, nil
}
