package rns

import (
	"bytes"
	"io"
	"testing"
)

func TestHDLCRoundTripSimple(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		{0x00, 0x01, 0x02, 0xFF},
		{hdlcFlag, hdlcEsc, hdlcFlag, hdlcEsc}, // all escape-needing
		bytes.Repeat([]byte{0x42}, 4096),
	}
	for _, in := range cases {
		framed := EncodeHDLC(in)
		dec := NewHDLCDecoder(bytes.NewReader(framed))
		out, err := dec.NextFrame()
		if err != nil {
			t.Fatalf("decode %d-byte: %v", len(in), err)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("round-trip mismatch\n got %x\nwant %x", out, in)
		}
	}
}

func TestHDLCEscapesFlagByte(t *testing.T) {
	in := []byte{hdlcFlag}
	got := EncodeHDLC(in)
	want := []byte{hdlcFlag, hdlcEsc, hdlcFlag ^ hdlcEscMask, hdlcFlag}
	if !bytes.Equal(got, want) {
		t.Errorf("flag-byte encoding\n got %x\nwant %x", got, want)
	}
}

func TestHDLCMultipleFramesInStream(t *testing.T) {
	frames := [][]byte{
		[]byte("first"),
		[]byte("second"),
		{0x7E, 0x7D, 0x00},
	}
	var stream bytes.Buffer
	for _, f := range frames {
		stream.Write(EncodeHDLC(f))
	}
	dec := NewHDLCDecoder(&stream)
	for i, want := range frames {
		got, err := dec.NextFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("frame %d mismatch\n got %x\nwant %x", i, got, want)
		}
	}
	if _, err := dec.NextFrame(); err != io.EOF {
		t.Errorf("expected EOF after last frame, got %v", err)
	}
}

func TestHDLCSkipsJunkAndEmptyFrames(t *testing.T) {
	// Encoder rules say a stream starts with a FLAG; some peers emit
	// extra FLAG bytes between frames as keepalive padding. The decoder
	// must skip them, not return empty payloads.
	stream := []byte{hdlcFlag, hdlcFlag, hdlcFlag}
	stream = append(stream, EncodeHDLC([]byte("payload"))...)
	stream = append(stream, hdlcFlag, hdlcFlag) // trailing padding

	dec := NewHDLCDecoder(bytes.NewReader(stream))
	got, err := dec.NextFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("got %q, want payload", got)
	}
	if _, err := dec.NextFrame(); err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestHDLCTruncatedEscape(t *testing.T) {
	// ESC followed by stream end — corrupted frame.
	stream := []byte{hdlcFlag, 0x41, hdlcEsc}
	dec := NewHDLCDecoder(bytes.NewReader(stream))
	if _, err := dec.NextFrame(); err != ErrTruncatedEscape {
		t.Errorf("got %v, want ErrTruncatedEscape", err)
	}
}
