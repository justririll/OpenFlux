package yandex

import (
	"context"
	"sync"
	"testing"

	"universal-bypass-tool/transport"
)

// TestRelayStopIsSendSafe reproduces the intermittent crash on Disconnect: the
// transport keep-alive and the tunnel both call relay.Send, and Stop used to
// close the channel Send writes to, so a send racing the close panicked with
// "send on closed channel". Stop must now cancel via context only, leaving the
// channel open, so concurrent and post-Stop sends are safe.
func TestRelayStopIsSendSafe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &relayClient{
		config:     DefaultVolgaConfig(),
		stats:      &VolgaStats{},
		queue:      make(chan []byte, 16),
		batchQueue: make(chan []byte, 16),
		ctx:        ctx,
		cancel:     cancel,
	}
	// No workers are started, so Stop just cancels the context and joins an
	// empty WaitGroup -- exactly the teardown window the crash happened in.

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				// A panic here (send on closed channel) fails the test by
				// crashing the process; the point is that it must not happen.
				_ = r.Send([]byte{0x00})
			}
		}()
	}

	r.Stop()
	wg.Wait()

	// Sends after Stop are still safe and simply report the relay is stopped.
	if err := r.Send([]byte{0x01}); err == nil {
		t.Fatal("expected an error from Send after Stop, got nil")
	}
}

// compile-time reminder that DefaultVolgaConfig stays usable from tests.
var _ = transport.DefaultConfig
