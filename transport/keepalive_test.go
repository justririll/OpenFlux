package transport

import (
	"bytes"
	"testing"
	"time"
)

// Real packets must survive the framing unchanged.
func TestKeepAliveTransportRoundTripsData(t *testing.T) {
	wire := &testTransport{}
	ka := NewKeepAliveTransport(wire, 0)

	var got []byte
	ka.Receive(func(b []byte) { got = append([]byte(nil), b...) })

	payload := []byte{0x45, 0x00, 0x00, 0x28, 0xde, 0xad}
	if err := ka.Send(payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	if wire.lastSent()[0] != frameData {
		t.Errorf("wire byte 0 = %#x, want the data frame %#x", wire.lastSent()[0], frameData)
	}

	wire.deliver(wire.lastSent())
	if !bytes.Equal(got, payload) {
		t.Errorf("received %#v, want %#v", got, payload)
	}
}

// A keep-alive must be dropped rather than injected into the network stack.
func TestKeepAliveFramesAreDropped(t *testing.T) {
	wire := &testTransport{}
	ka := NewKeepAliveTransport(wire, 0)

	delivered := 0
	ka.Receive(func([]byte) { delivered++ })

	wire.deliver(ka.keepAlivePacket())
	if delivered != 0 {
		t.Errorf("keep-alive was passed up %d times, want 0", delivered)
	}
}

// A peer on an older build sends unframed IPv4 packets. Those must still be
// delivered: an IPv4 header never starts with a frame byte.
func TestUnframedLegacyPacketPassesThrough(t *testing.T) {
	wire := &testTransport{}
	ka := NewKeepAliveTransport(wire, 0)

	var got []byte
	ka.Receive(func(b []byte) { got = append([]byte(nil), b...) })

	legacy := []byte{0x45, 0x00, 0x00, 0x3c}
	wire.deliver(legacy)
	if !bytes.Equal(got, legacy) {
		t.Errorf("legacy packet came through as %#v, want %#v", got, legacy)
	}
}

func TestEmptyPacketIsIgnored(t *testing.T) {
	wire := &testTransport{}
	ka := NewKeepAliveTransport(wire, 0)

	delivered := 0
	ka.Receive(func([]byte) { delivered++ })

	wire.deliver(nil)
	wire.deliver([]byte{})
	if delivered != 0 {
		t.Errorf("empty packets were passed up %d times, want 0", delivered)
	}
}

// Neither the contents nor the length of a keep-alive may repeat, or it
// becomes the same fingerprint the fixed marker was.
func TestKeepAlivePacketsVary(t *testing.T) {
	ka := NewKeepAliveTransport(&testTransport{}, 0)

	lengths := make(map[int]bool)
	bodies := make(map[string]bool)
	for i := 0; i < 64; i++ {
		p := ka.keepAlivePacket()
		if p[0] != frameKeepAlive {
			t.Fatalf("byte 0 = %#x, want the keep-alive frame %#x", p[0], frameKeepAlive)
		}
		if len(p) > keepAlivePadMax+1 {
			t.Fatalf("keep-alive is %d bytes, over the %d cap", len(p), keepAlivePadMax+1)
		}
		lengths[len(p)] = true
		bodies[string(p)] = true
	}

	if len(lengths) < 2 {
		t.Error("keep-alive length never varied")
	}
	if len(bodies) < 2 {
		t.Error("keep-alive contents never varied")
	}
}

// A keep-alive must not be emitted while the transport is down, and must be
// framed as a keep-alive when it is.
func TestKeepAliveLoopEmitsOnlyWhileConnected(t *testing.T) {
	wire := &testTransport{}
	ka := NewKeepAliveTransport(wire, 20*time.Millisecond)

	wire.setConnected(false)
	if err := ka.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer ka.Stop()

	time.Sleep(100 * time.Millisecond)
	if wire.lastSent() != nil {
		t.Fatalf("keep-alive was sent while disconnected: %#v", wire.lastSent())
	}

	wire.setConnected(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if wire.lastSent() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wire.lastSent() == nil {
		t.Fatal("no keep-alive after the transport came up")
	}
	if wire.lastSent()[0] != frameKeepAlive {
		t.Errorf("byte 0 = %#x, want the keep-alive frame %#x", wire.lastSent()[0], frameKeepAlive)
	}
}

// Stop must be safe to call twice, like the transports it wraps.
func TestKeepAliveStopIsIdempotent(t *testing.T) {
	ka := NewKeepAliveTransport(&testTransport{}, time.Hour)
	if err := ka.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := ka.Stop(); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := ka.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}
