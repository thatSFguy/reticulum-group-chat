package rns

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTCPClientRoundTripOverPipe(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	client := NewTCPClient(clientConn)
	defer client.Close()

	// Build a minimum-valid Reticulum packet (HEADER_1, 19 bytes plus 1B data).
	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        newDummyHash(0xAA),
		Context:         ContextNone,
		Data:            []byte{0x42},
	}
	wire, _ := pkt.Pack()

	// Peer sends a frame; client receives it.
	go func() {
		framed := EncodeHDLC(wire)
		peerConn.Write(framed)
	}()

	select {
	case got := <-client.Inbox():
		if !bytes.Equal(got, wire) {
			t.Errorf("inbox bytes mismatch\n got %x\nwant %x", got, wire)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for inbox frame")
	}
}

func TestTCPClientSendIsHDLCFramed(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	client := NewTCPClient(clientConn)
	defer client.Close()

	// A simple-but-non-trivial payload (matches a min Reticulum header).
	payload := append(make([]byte, 0, 19), 0x00, 0x00)
	for i := 0; i < 16; i++ {
		payload = append(payload, byte(i))
	}
	payload = append(payload, 0x00) // context

	got := make(chan []byte, 1)
	go func() {
		dec := NewHDLCDecoder(peerConn)
		f, err := dec.NextFrame()
		if err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		got <- f
	}()

	if err := client.Send(payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f, payload) {
			t.Errorf("framed payload mismatch\n got %x\nwant %x", f, payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("peer never received frame")
	}
}

func TestTCPClientCloseShutsReader(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	client := NewTCPClient(c1)

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-client.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reader didn't exit after Close")
	}
}
