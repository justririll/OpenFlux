package transport

import (
	"crypto/rand"
	"sync"
	"time"

	"universal-bypass-tool/utils"
)

const (
	// ipv4Version is the value of the high nibble of an IPv4 header's first
	// byte. Every packet the tunnel carries is IPv4 (the stack is built with
	// only ipv4.NewProtocol, and the client refuses IPv6), so that nibble
	// tells a real packet apart from a keep-alive with no framing of its own.
	ipv4Version = 4

	// keepAliveTag is the first byte of a keep-alive. Any value whose high
	// nibble is not 4 works; 0x00 can never begin an IPv4 header.
	keepAliveTag = byte(0x00)

	// keepAlivePadMax bounds the random padding on a keep-alive, so keep-alives
	// do not stand out from real traffic by having one constant length.
	keepAlivePadMax = 64
)

// KeepAliveTransport keeps the underlying connection warm from the OUTERMOST
// edge of the stack, so its traffic passes through exactly the same
// compression and encryption as real packets.
//
// The keep-alive used to be emitted by the transport itself, below both
// layers, as a fixed marker string. That put a constant, unencrypted token on
// the wire at a fixed interval - a reliable fingerprint of the tunnel that
// survived turning encryption on. Here it is just another opaque packet.
//
// Real packets are forwarded byte for byte, with no framing added, so a peer
// running an older build interoperates in both directions: it still receives
// exactly the packets it expects, and this side still understands everything
// it sends.
type KeepAliveTransport struct {
	Transport

	interval time.Duration
	stopped  chan struct{}
	stopOnce sync.Once
}

// NewKeepAliveTransport wraps inner. A non-positive interval disables the
// keep-alive but leaves the receive-side filtering in place.
func NewKeepAliveTransport(inner Transport, interval time.Duration) *KeepAliveTransport {
	return &KeepAliveTransport{
		Transport: inner,
		interval:  interval,
		stopped:   make(chan struct{}),
	}
}

func (k *KeepAliveTransport) Start() error {
	if err := k.Transport.Start(); err != nil {
		return err
	}
	if k.interval > 0 {
		utils.SafeGo("transport.keepAlive", k.loop)
	}
	return nil
}

func (k *KeepAliveTransport) Stop() error {
	k.stopOnce.Do(func() { close(k.stopped) })
	return k.Transport.Stop()
}

// Send forwards the packet untouched. Adding a frame byte here would be
// tidier, but it would also break every peer that has not been upgraded yet.
func (k *KeepAliveTransport) Send(data []byte) error {
	return k.Transport.Send(data)
}

func (k *KeepAliveTransport) Receive(callback func([]byte)) {
	k.Transport.Receive(func(packet []byte) {
		// Anything that is not an IPv4 header is either one of our
		// keep-alives or corruption. Both are dropped rather than handed to
		// the network stack.
		if len(packet) == 0 || packet[0]>>4 != ipv4Version {
			return
		}
		callback(packet)
	})
}

func (k *KeepAliveTransport) loop() {
	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()

	for {
		select {
		case <-k.stopped:
			return
		case <-ticker.C:
		}

		if !k.Transport.IsConnected() {
			continue
		}
		if err := k.Transport.Send(k.keepAlivePacket()); err != nil {
			utils.Debugf("[KEEPALIVE] send failed: %v", err)
		}
	}
}

// keepAlivePacket builds one keep-alive: the tag byte plus a random amount of
// random padding, so neither its contents nor its length repeat.
func (k *KeepAliveTransport) keepAlivePacket() []byte {
	var sizePick [1]byte
	if _, err := rand.Read(sizePick[:]); err != nil {
		sizePick[0] = 0
	}
	padding := make([]byte, int(sizePick[0])%(keepAlivePadMax+1))
	if _, err := rand.Read(padding); err != nil {
		// Padding is cosmetic; an empty keep-alive still does its job.
		padding = nil
	}
	return append([]byte{keepAliveTag}, padding...)
}
