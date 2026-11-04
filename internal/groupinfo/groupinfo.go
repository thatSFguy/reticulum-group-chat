// Package groupinfo holds the two pieces of operator-authored, group-scoped
// text that outlive any single message: the instance description surfaced by
// /info, and the pinned-message list surfaced by /pins and replayed to a
// joiner after their history catch-up.
//
// It is deliberately its own store rather than fields on roster.State or a
// second history.Log. The roster is per-user state that the prune sweep
// rewrites constantly, and the history log is a fixed-capacity ring the
// forwarder appends to on every inbound message — folding rarely-written,
// operator-authored text into either would mean a description surviving or
// vanishing as a side effect of unrelated churn. A separate file also means
// an operator can seed a group's description and pins by dropping in a JSON
// file before first start.
package groupinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxInfoBytes caps the stored /info description. It is a storage ceiling,
// not the wire limit.
//
// /info answers anyone who can reach the destination — that is its point —
// so its reply has to be bounded or a 6-byte request becomes an
// amplifier. The real bound is that the WHOLE reply (display name,
// description, join hint) fits one opportunistic packet, and that is
// enforced by commands.Dispatcher.InfoOverflow, measured against the LXMF
// library, because the display name it shares the packet with is config
// this package never sees. With any non-trivial display name the room left
// is well under this constant. What this constant still does is bound a
// hand-edited groupinfo.json on load, independent of config.
const MaxInfoBytes = 256

// MaxPins caps how many pinned messages the group keeps, and MaxPinBytes
// caps each one. Together they bound the rendered block at roughly 2 KiB.
//
// The pins block is sent to every joiner (see the join catch-up in
// internal/service/replay.go), so an unbounded list would turn /join into an
// amplifier in exactly the way the replay cooldown exists to prevent — the
// cooldown bounds the RATE of that fan-out, these bound its SIZE. Pinning is
// mod-only, so the limits are not defending against an outsider; they are
// there so that "a mod pinned one too many things two years ago" cannot
// quietly make every join expensive on a LoRa segment.
const (
	MaxPins     = 10
	MaxPinBytes = 200
)

// ErrPinsFull is returned by AddPin when the list is already at MaxPins.
// Callers surface it to the mod as a "unpin something first" reply rather
// than silently evicting the oldest pin — a pin is a deliberate act, and
// dropping one on someone else's behalf is not ours to do.
var ErrPinsFull = fmt.Errorf("pin list is full (max %d)", MaxPins)

// Pin is one pinned message. By/ByNick record who pinned it, captured at
// pin time: the nickname is a snapshot rather than a live roster lookup so
// that a pin still says who made it after that mod leaves the group.
type Pin struct {
	At     time.Time `json:"at"`
	By     string    `json:"by"`      // lowercase hex dest hash of the pinner
	ByNick string    `json:"by_nick"` // nickname at pin time; may be empty
	Text   string    `json:"text"`
}

type Store struct {
	mu   sync.Mutex
	path string
	info string
	pins []Pin
}

type fileFormat struct {
	Info string `json:"info"`
	Pins []Pin  `json:"pins"`
}

// New loads the store from path, creating nothing on disk until the first
// write. A missing or empty file is not an error — that is the state every
// group starts in.
func New(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load applies the same limits enforced on the write path. The file is
// operator-editable by design, so anything read back is treated as untrusted
// input: over-long text is truncated, surplus pins are dropped, and control
// bytes are scrubbed at render time.
func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	s.info = TruncateText(f.Info, MaxInfoBytes)
	if len(f.Pins) > MaxPins {
		f.Pins = f.Pins[:MaxPins]
	}
	for i := range f.Pins {
		f.Pins[i].Text = TruncateText(f.Pins[i].Text, MaxPinBytes)
	}
	s.pins = f.Pins
	return nil
}

// Info returns the group description, or "" when none is set.
func (s *Store) Info() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// SetInfo replaces the description. An empty string clears it. Text longer
// than MaxInfoBytes is truncated rather than rejected — the caller is
// expected to have refused it already with a byte count, so reaching here
// over-length means a hand-edited file, and truncating keeps the /info reply
// inside its packet budget regardless.
func (s *Store) SetInfo(text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = TruncateText(text, MaxInfoBytes)
	return s.persistLocked()
}

// Pins returns a copy of the pin list, oldest first.
func (s *Store) Pins() []Pin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pin, len(s.pins))
	copy(out, s.pins)
	return out
}

// PinCount is Pins() without the copy, for callers that only need the size.
func (s *Store) PinCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pins)
}

// AddPin appends a pin, returning ErrPinsFull when the list is at capacity.
func (s *Store) AddPin(p Pin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pins) >= MaxPins {
		return ErrPinsFull
	}
	p.Text = TruncateText(p.Text, MaxPinBytes)
	s.pins = append(s.pins, p)
	return s.persistLocked()
}

// RemovePin drops the pin at the 1-based index n — the same number /pins
// displays, so a mod can unpin what they just read off the list without
// translating indices. Reports false when n is out of range.
func (s *Store) RemovePin(n int) (Pin, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 1 || n > len(s.pins) {
		return Pin{}, false, nil
	}
	removed := s.pins[n-1]
	s.pins = append(s.pins[:n-1], s.pins[n:]...)
	return removed, true, s.persistLocked()
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Info: s.info, Pins: s.pins}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data, 0o600)
}

// atomicWrite renames a tempfile in the same directory so a crash mid-write
// can never leave a partial file behind. Mirrors roster.atomicWrite and
// history.atomicWrite; duplicated rather than shared for the same reason
// they are — these three stores are independent and a shared helper would be
// the only thing coupling them.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// TruncateText cuts s to at most max BYTES without splitting a UTF-8
// sequence. Byte-oriented because every limit downstream of here — the
// opportunistic packet cap, the Link DATA cap, the Resource threshold — is
// counted in bytes on the wire, not in runes.
func TruncateText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	// Back off over continuation bytes (0b10xxxxxx) to the start of the
	// rune we landed inside, so a multi-byte character is dropped whole
	// rather than left as a replacement glyph on the recipient's client.
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
