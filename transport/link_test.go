package transport

import (
	"bytes"
	"testing"
)

func TestParseLinkPlainURLStaysUnencrypted(t *testing.T) {
	link, err := ParseLink("https://docs.yandex.ru/docs/view?id=abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.URL != "https://docs.yandex.ru/docs/view?id=abc123" {
		t.Errorf("URL was rewritten: %q", link.URL)
	}
	if link.Encrypted() {
		t.Error("a plain URL must not enable encryption")
	}
}

func TestParseLinkSplitsSecret(t *testing.T) {
	link, err := ParseLink("ydocs://docs.yandex.ru/docs/view?id=abc123#my-shared-secret-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://docs.yandex.ru/docs/view?id=abc123"; link.URL != want {
		t.Errorf("URL = %q, want %q", link.URL, want)
	}
	if link.Secret != "my-shared-secret-value" {
		t.Errorf("Secret = %q", link.Secret)
	}
	if !link.Encrypted() {
		t.Error("link with a secret must be encrypted")
	}
}

// The document URL may already spell out https://; the scheme must not double it.
func TestParseLinkToleratesExplicitScheme(t *testing.T) {
	link, err := ParseLink("ydocs://https://docs.yandex.ru/d?id=1#another-long-enough-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://docs.yandex.ru/d?id=1"; link.URL != want {
		t.Errorf("URL = %q, want %q", link.URL, want)
	}
}

// A query string is part of the URL; only the final "#" separates the secret.
func TestParseLinkSplitsOnFinalHash(t *testing.T) {
	link, err := ParseLink("ydocs://host/p?a=1&b=2#sixteen-characters-long")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://host/p?a=1&b=2"; link.URL != want {
		t.Errorf("URL = %q, want %q", link.URL, want)
	}
	if link.Secret != "sixteen-characters-long" {
		t.Errorf("Secret = %q", link.Secret)
	}
}

func TestParseLinkWithoutSecretIsValid(t *testing.T) {
	link, err := ParseLink("ydocs://docs.yandex.ru/docs/view?id=abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.Encrypted() {
		t.Error("no # means no encryption")
	}
	if want := "https://docs.yandex.ru/docs/view?id=abc"; link.URL != want {
		t.Errorf("URL = %q, want %q", link.URL, want)
	}
}

// A secret too short for NewEncryptedTransport must be rejected at parse time,
// not silently at transport construction.
func TestParseLinkRejectsShortSecret(t *testing.T) {
	if _, err := ParseLink("ydocs://docs.yandex.ru/d#short"); err == nil {
		t.Fatal("expected an error for a secret under the minimum length")
	}
}

func TestParseLinkRejectsMalformed(t *testing.T) {
	for _, raw := range []string{"", "   ", "ydocs://", "ydocs://#a-long-enough-secret"} {
		if _, err := ParseLink(raw); err == nil {
			t.Errorf("ParseLink(%q) should have failed", raw)
		}
	}
}

func TestLinkRoundTrips(t *testing.T) {
	original := "ydocs://docs.yandex.ru/docs/view?id=abc123#my-shared-secret-value"
	link, err := ParseLink(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.String() != original {
		t.Errorf("String() = %q, want %q", link.String(), original)
	}
}

func TestLinkRedactedHidesSecret(t *testing.T) {
	link, err := ParseLink("ydocs://docs.yandex.ru/d?id=1#my-shared-secret-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	redacted := link.Redacted()
	if want := "ydocs://docs.yandex.ru/d?id=1#***"; redacted != want {
		t.Errorf("Redacted() = %q, want %q", redacted, want)
	}
}

// The two peers must derive the same keys from the same link.
func TestLinkWrapPairsClientAndExitNode(t *testing.T) {
	link, err := ParseLink("ydocs://docs.yandex.ru/d?id=1#my-shared-secret-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clientWire, exitWire := &testTransport{}, &testTransport{}
	client, err := link.Wrap(clientWire, DefaultConfig(), "yandex", false)
	if err != nil {
		t.Fatalf("wrap client: %v", err)
	}
	exit, err := link.Wrap(exitWire, DefaultConfig(), "yandex", true)
	if err != nil {
		t.Fatalf("wrap exit node: %v", err)
	}

	var got []byte
	exit.Receive(func(b []byte) { got = append([]byte(nil), b...) })

	payload := []byte("hello through the document")
	if err := client.Send(payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	if bytes.Contains(clientWire.lastSent(), payload) {
		t.Error("plaintext appeared on the wire")
	}

	// Pipe what the client put on the wire into the exit node's side.
	exitWire.deliver(clientWire.lastSent())
	if !bytes.Equal(got, payload) {
		t.Fatalf("exit node decoded %q, want %q", got, payload)
	}
}

// A link with no secret must leave the stack unencrypted, unchanged from the
// behaviour before ydocs:// existed.
func TestLinkWrapWithoutSecretIsPlaintext(t *testing.T) {
	link, err := ParseLink("https://docs.yandex.ru/d?id=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wire := &testTransport{}
	stack, err := link.Wrap(wire, DefaultConfig(), "yandex", false)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	payload := []byte("this small packet is not compressed")
	if err := stack.Send(payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !bytes.Contains(wire.lastSent(), payload) {
		t.Error("expected the unencrypted stack to put plaintext on the wire")
	}
}
