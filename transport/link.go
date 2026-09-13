package transport

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// LinkScheme is the OpenFlux connection-string scheme. It packs the document
// URL and the shared encryption secret into a single token that can be copied
// verbatim between the client and the exit node:
//
//	ydocs://docs.yandex.ru/docs/view?id=abc123#my-shared-secret
//
// Everything between the scheme and the FINAL "#" is the document URL (https
// is implied); everything after that "#" is the shared secret. A ydocs:// link
// with no "#" is just a document URL and stays unencrypted, and plain
// http(s):// URLs are accepted unchanged so existing setups keep working.
//
// The secret never travels over the transport - it is only a local input to
// the key derivation, and both peers must be given the same link out of band.
const LinkScheme = "ydocs://"

// MinSecretLen mirrors the minimum accepted by NewEncryptedTransport.
const MinSecretLen = 16

// Link is a parsed OpenFlux connection string.
type Link struct {
	// URL is the https document URL both peers share.
	URL string
	// Secret is the shared AES-256-GCM secret, empty when the link carries none.
	Secret string
}

// Encrypted reports whether the link asks for transport encryption.
func (l Link) Encrypted() bool { return l.Secret != "" }

// ParseLink accepts either a ydocs:// link or a plain document URL. It never
// fails on a missing secret - an unencrypted link is a valid link.
func ParseLink(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Link{}, errors.New("empty document link")
	}

	if !strings.HasPrefix(strings.ToLower(raw), LinkScheme) {
		return Link{URL: raw}, nil
	}

	body := raw[len(LinkScheme):]
	var secret string
	// A Yandex document URL carries a query string but no fragment, so the
	// last "#" is unambiguously the secret separator.
	if hash := strings.LastIndex(body, "#"); hash >= 0 {
		secret = strings.TrimSpace(body[hash+1:])
		body = body[:hash]
	}
	if body == "" {
		return Link{}, errors.New("ydocs:// link carries no document URL")
	}

	// The scheme implies https; tolerate an explicitly spelled-out one so
	// "ydocs://https://docs.yandex.ru/..." also works.
	docURL := body
	lower := strings.ToLower(body)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		docURL = "https://" + body
	}
	parsed, err := url.Parse(docURL)
	if err != nil {
		return Link{}, fmt.Errorf("ydocs:// link has an invalid document URL: %w", err)
	}
	if parsed.Host == "" {
		return Link{}, errors.New("ydocs:// link has no host in its document URL")
	}
	if secret != "" && len(secret) < MinSecretLen {
		return Link{}, fmt.Errorf("ydocs:// secret must be at least %d characters, got %d",
			MinSecretLen, len(secret))
	}

	return Link{URL: docURL, Secret: secret}, nil
}

// NewLink builds a shareable connection string from a document URL and an
// optional secret. The result round-trips through ParseLink.
func NewLink(docURL, secret string) Link {
	return Link{URL: strings.TrimSpace(docURL), Secret: strings.TrimSpace(secret)}
}

// String renders the link in ydocs:// form. It contains the secret in the
// clear, so it is for handing to the operator - never for logs. Use Redacted
// for anything that gets printed.
func (l Link) String() string {
	body := strings.TrimPrefix(strings.TrimPrefix(l.URL, "https://"), "http://")
	if l.Secret == "" {
		return LinkScheme + body
	}
	return LinkScheme + body + "#" + l.Secret
}

// Redacted renders the link with the secret masked, safe for logs.
func (l Link) Redacted() string {
	if l.Secret == "" {
		return l.String()
	}
	return NewLink(l.URL, "***").String()
}

// Wrap builds the transport stack for this link around inner, innermost
// first: AES-256-GCM when the link carries a secret, then compression, then
// the keep-alive. exitNode selects which side of the directional key pair to
// use and must differ between the peers.
//
// The keep-alive sits outermost on purpose, so its traffic is compressed and
// encrypted exactly like a real packet instead of being a constant plaintext
// marker emitted below both layers.
//
// The KDF context is the parsed document URL, which both peers derive
// identically from the same link, so a plain URL plus an out-of-band key file
// interoperates with a ydocs:// link pointing at the same document.
func (l Link) Wrap(inner Transport, config TransportConfig, fallbackContext string, exitNode bool) (Transport, error) {
	stack := inner

	if l.Encrypted() {
		context := l.URL
		if context == "" {
			context = fallbackContext
		}
		encrypted, err := NewEncryptedTransport(stack, l.Secret, context, exitNode)
		if err != nil {
			return nil, err
		}
		stack = encrypted
	}

	return NewKeepAliveTransport(NewCompressedTransport(stack), config.KeepAliveInterval), nil
}
