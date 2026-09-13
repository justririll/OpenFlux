package transport

import (
	"crypto/rand"
	"sync"
	"time"

	"universal-bypass-tool/utils"
)

const (
	// frameData marks a packet carrying a real tunnelled IPv4 packet.
	frameData = byte(0x00)
	// frameKeepAlive marks a packet the peer discards on arrival.
	frameKeepAlive = byte(0x01)

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
// survived turning encryption on. Framing it here means an observer sees only
// another opaque packet.
type KeepAliveTransport struct {
	Transport

	interval time.Duration
	stopped  chan struct{}
	stopOnce sync.Once
}

// NewKeepAliveTransport wraps inner. A non-positive interval disables the
// keep-alive but still applies the framing, which both peers must agree on.
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

func (k *KeepAliveTransport) Send(data []byte) error {
	framed := make([]byte, 0, len(data)+1)
	framed = append(framed, frameData)
	framed = append(framed, data...)
	return k.Transport.Send(framed)
}

func (k *KeepAliveTransport) Receive(callback func([]byte)) {
	k.Transport.Receive(func(packet []byte) {
		if len(packet) == 0 {
			return
		}
		switch packet[0] {
		case frameKeepAlive:
			return
		case frameData:
			callback(packet[1:])
		default:
			// An unframed packet comes from a peer running an older build.
			// An IPv4 header always starts with 0x45 or higher (version 4 in
			// the high nibble), so it can never be mistaken for a frame byte
			// and it is safe to pass straight through.
			callback(packet)
		}
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

// keepAlivePacket builds one keep-alive: the frame byte plus a random amount
// of random padding, so neither its contents nor its length repeat.
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
	return append([]byte{frameKeepAlive}, padding...)
}
