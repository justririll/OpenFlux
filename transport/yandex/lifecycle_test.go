package yandex

import (
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

func testConfig() transport.TransportConfig {
	c := transport.DefaultConfig()
	c.MaxQueueSize = 4
	c.KeepAliveInterval = time.Hour // keep the keep-alive out of these tests
	return c
}

func TestSendWithoutConnectionFails(t *testing.T) {
	tr := NewYandexDocsTransport("https://docs.example.invalid/d", testConfig())
	if err := tr.Send([]byte("packet")); err == nil {
		t.Fatal("Send must fail while the transport is not connected")
	}
}

// A full queue must be reported, never block the caller: Send sits on the
// tunnel's packet path, so blocking there would stall the whole stack.
func TestSendReportsFullQueueWithoutBlocking(t *testing.T) {
	cfg := testConfig()
	tr := NewYandexDocsTransport("https://docs.example.invalid/d", cfg)
	tr.SetConnected(true)

	for i := 0; i < cfg.MaxQueueSize; i++ {
		if err := tr.Send([]byte("packet")); err != nil {
			t.Fatalf("Send %d should have been queued: %v", i, err)
		}
	}

	done := make(chan error, 1)
	go func() { done <- tr.Send([]byte("one too many")) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Send should report a full queue")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send blocked on a full queue instead of returning an error")
	}
}

// The queue belongs to the transport, not to a single WebSocket session, so
// packets queued during an outage survive until a session is back.
func TestQueuedPacketsSurviveWithoutASession(t *testing.T) {
	tr := NewYandexDocsTransport("https://docs.example.invalid/d", testConfig())
	tr.SetConnected(true)

	if err := tr.Send([]byte("queued during an outage")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if tr.currentSession() != nil {
		t.Fatal("no session should exist yet")
	}
	if got := len(tr.writeQueue); got != 1 {
		t.Fatalf("queue holds %d packets, want 1", got)
	}
}

// Stop must be safe to call twice: the mobile bridges stop the transport on
// teardown and again on the next start.
func TestStopIsIdempotent(t *testing.T) {
	// Port 1 refuses immediately, so the connect loop fails fast rather than
	// doing real network work.
	tr := NewYandexDocsTransport("http://127.0.0.1:1/doc", testConfig())
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := tr.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if tr.IsRunning() {
		t.Error("transport still reports running after Stop")
	}
	if err := tr.Send([]byte("packet")); err == nil {
		t.Error("Send must fail after Stop")
	}
}

// dropSession must ignore a session that has already been replaced, so a late
// write error cannot tear down the connection that succeeded it.
func TestDropSessionIgnoresStaleSession(t *testing.T) {
	tr := NewYandexDocsTransport("https://docs.example.invalid/d", testConfig())
	current := &DocSession{UserID: "current"}
	tr.setSession(current)

	stale := &DocSession{UserID: "stale"}
	tr.dropSession(stale, "stale write error") // must not panic on a nil Conn

	if tr.currentSession() != current {
		t.Error("dropping a stale session replaced the live one")
	}
	if !tr.IsConnected() {
		t.Error("dropping a stale session marked the transport disconnected")
	}
}

// The user id identifies this peer inside the document and must not change
// across reconnects, or the exit node sees a new collaborator every time.
func TestSessionUserIDIsStableAcrossReconnects(t *testing.T) {
	tr := NewYandexDocsTransport("https://docs.example.invalid/d", testConfig())
	first := tr.sessionUserID()
	if first == "" {
		t.Fatal("user id must not be empty")
	}
	if second := tr.sessionUserID(); second != first {
		t.Errorf("user id changed across reconnects: %q then %q", first, second)
	}
}

func TestReconnectBackoffIsBoundedAndGrows(t *testing.T) {
	const cap = 15 * time.Second
	// Jitter adds up to +50%, so the hard ceiling is 1.5x the cap.
	const ceiling = cap + cap/2

	for _, attempt := range []int{-1, 0, 1, 2, 5, 10, 1000} {
		d := reconnectBackoff(attempt)
		if d <= 0 {
			t.Errorf("attempt %d: backoff %v must be positive", attempt, d)
		}
		if d > ceiling {
			t.Errorf("attempt %d: backoff %v exceeds the ceiling %v", attempt, d, ceiling)
		}
	}

	// A later attempt must not wait less than the first one's floor.
	if reconnectBackoff(6) < reconnectBackoff(1) {
		t.Error("backoff should grow with the attempt count")
	}
}
