package rns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// HDLC byte-stuffing framing as used by TCPClientInterface (SPEC §8.2).
// FLAG delimits frames. ESC + (byte XOR MASK) escapes any in-band FLAG or
// ESC byte. Unlike KISS framing on serial lines, there is no leading
// command byte on the TCP wire — frames are raw Reticulum packets.
const (
	hdlcFlag    = 0x7E
	hdlcEsc     = 0x7D
	hdlcEscMask = 0x20
)

// EncodeHDLC wraps a packet in HDLC framing: FLAG || escape(p) || FLAG.
func EncodeHDLC(p []byte) []byte {
	out := make([]byte, 0, len(p)+2)
	out = append(out, hdlcFlag)
	for _, b := range p {
		if b == hdlcFlag || b == hdlcEsc {
			out = append(out, hdlcEsc, b^hdlcEscMask)
		} else {
			out = append(out, b)
		}
	}
	out = append(out, hdlcFlag)
	return out
}

// MaxHDLCFrameLen bounds the un-escaped payload of a single inbound
// frame. Without it, NextFrame grows its buffer until it sees a FLAG
// byte, so a peer that streams non-FLAG bytes forever drives allocation
// until the process is OOM-killed — remote, pre-auth, before any parse
// or crypto.
//
// One frame carries exactly one Reticulum packet, so the protocol
// ceiling is ReticulumMTU (500). 8 KiB leaves 16x headroom for a
// future negotiated-MTU path (SPEC §6.6 signals up to 21 bits) while
// still bounding a hostile peer to a trivial allocation.
const MaxHDLCFrameLen = 8192

// HDLCDecoder reads HDLC-framed frames from an underlying byte stream.
// Empty frames (two consecutive FLAGs with nothing between) are silently
// skipped; a stray ESC at end of stream returns ErrTruncatedEscape.
type HDLCDecoder struct {
	r *bufio.Reader

	// maxFrameLen defaults to MaxHDLCFrameLen; overridable in tests.
	maxFrameLen int

	// onFrameStart / onFrameEnd, when set, bracket the assembly of a
	// single frame. TCPClient uses them to arm a read deadline for the
	// duration of a partial frame ONLY — a connection-wide read
	// deadline would kill legitimately idle links, but a peer that
	// opens a frame and then stalls mid-frame must not pin the buffer
	// (and the reader goroutine) indefinitely.
	onFrameStart func() error
	onFrameEnd   func()
}

// ErrTruncatedEscape is returned if an ESC byte is followed immediately by
// EOF — the stream lost a byte.
var ErrTruncatedEscape = errors.New("hdlc: truncated escape sequence at end of stream")

// ErrFrameTooLarge is returned when an inbound frame exceeds
// maxFrameLen before its closing FLAG arrives. The stream is not
// resynchronized — the caller is expected to drop the connection, since
// an oversize frame means the peer is either broken or hostile.
var ErrFrameTooLarge = errors.New("hdlc: inbound frame exceeds maximum length")

func NewHDLCDecoder(r io.Reader) *HDLCDecoder {
	return &HDLCDecoder{r: bufio.NewReader(r), maxFrameLen: MaxHDLCFrameLen}
}

// NextFrame reads one HDLC frame and returns its un-escaped payload. The
// returned slice is freshly allocated. io.EOF is returned only on a clean
// stream end (no partial frame).
func (d *HDLCDecoder) NextFrame() ([]byte, error) {
	for {
		// Skip leading flags / junk until we have at least one non-flag byte.
		first, err := d.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if first == hdlcFlag {
			continue
		}

		// A frame is now in progress: arm the assembly deadline (if the
		// caller set one) and disarm it on every exit path below.
		if d.onFrameStart != nil {
			if err := d.onFrameStart(); err != nil {
				return nil, err
			}
		}
		frame, err := d.readFrame(first)
		if d.onFrameEnd != nil {
			d.onFrameEnd()
		}
		if err != nil {
			return nil, err
		}
		return frame, nil
	}
}

// readFrame assembles one frame body, starting from the already-read
// first (non-FLAG) byte, up to the closing FLAG. Bounded by maxFrameLen.
func (d *HDLCDecoder) readFrame(first byte) ([]byte, error) {
	limit := d.maxFrameLen
	if limit <= 0 {
		limit = MaxHDLCFrameLen
	}
	out := make([]byte, 0, header1MinLen)
	b := first
	for {
		if b == hdlcFlag {
			return out, nil
		}
		if len(out) >= limit {
			return nil, fmt.Errorf("%w: exceeded %d bytes with no closing flag", ErrFrameTooLarge, limit)
		}
		if b == hdlcEsc {
			next, err := d.r.ReadByte()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil, ErrTruncatedEscape
				}
				return nil, err
			}
			out = append(out, next^hdlcEscMask)
		} else {
			out = append(out, b)
		}
		nb, err := d.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrTruncatedEscape
			}
			return nil, err
		}
		b = nb
	}
}
