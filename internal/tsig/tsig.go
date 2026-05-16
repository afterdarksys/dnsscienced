// Package tsig provides TSIG (RFC 2845) key management, verification, and signing
// for DNS messages. It wraps miekg/dns TSIG primitives with a managed KeyRing.
package tsig

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Supported TSIG algorithms (FQDN form with trailing dot).
var supportedAlgorithms = map[string]bool{
	dns.HmacSHA256: true,
	dns.HmacSHA384: true,
	dns.HmacSHA512: true,
}

// KeyConfig holds configuration for a single TSIG key.
type KeyConfig struct {
	// Name is the key name (e.g., "transfer-key.example.com." or "transfer-key.example.com")
	Name string `yaml:"name"`
	// Algorithm is the HMAC algorithm: "hmac-sha256", "hmac-sha384", or "hmac-sha512"
	Algorithm string `yaml:"algorithm"`
	// Secret is the base64-encoded shared secret
	Secret string `yaml:"secret"`
}

// KeyRing holds a set of TSIG keys indexed by normalized FQDN name.
type KeyRing struct {
	keys map[string]keyEntry // name (FQDN) → entry
}

type keyEntry struct {
	algorithm string // normalized FQDN form
	secret    string // base64-encoded
}

// NewKeyRing validates and builds a KeyRing from configuration.
// Returns an error if any key has an invalid algorithm or malformed base64 secret.
func NewKeyRing(keys []KeyConfig) (*KeyRing, error) {
	kr := &KeyRing{keys: make(map[string]keyEntry, len(keys))}
	for _, k := range keys {
		if err := ValidateAlgorithm(k.Algorithm); err != nil {
			return nil, fmt.Errorf("key %q: %w", k.Name, err)
		}
		if _, err := base64.StdEncoding.DecodeString(k.Secret); err != nil {
			return nil, fmt.Errorf("key %q: invalid base64 secret: %w", k.Name, err)
		}
		name := dns.Fqdn(strings.ToLower(k.Name))
		alg := normalizeAlgorithm(k.Algorithm)
		kr.keys[name] = keyEntry{algorithm: alg, secret: k.Secret}
	}
	return kr, nil
}

// Secret returns the base64-encoded secret for the given key name.
// The name is normalized to FQDN before lookup.
func (kr *KeyRing) Secret(name string) (string, bool) {
	if kr == nil {
		return "", false
	}
	e, ok := kr.keys[dns.Fqdn(strings.ToLower(name))]
	if !ok {
		return "", false
	}
	return e.secret, true
}

// Algorithm returns the algorithm for the given key name.
func (kr *KeyRing) Algorithm(name string) (string, bool) {
	if kr == nil {
		return "", false
	}
	e, ok := kr.keys[dns.Fqdn(strings.ToLower(name))]
	if !ok {
		return "", false
	}
	return e.algorithm, true
}

// TsigSecretMap returns the map[string]string suitable for dns.Server.TsigSecret.
// Keys are FQDN key names, values are base64-encoded secrets.
func (kr *KeyRing) TsigSecretMap() map[string]string {
	if kr == nil || len(kr.keys) == 0 {
		return nil
	}
	m := make(map[string]string, len(kr.keys))
	for name, entry := range kr.keys {
		m[name] = entry.secret
	}
	return m
}

// Names returns all key names in the ring.
func (kr *KeyRing) Names() []string {
	if kr == nil {
		return nil
	}
	names := make([]string, 0, len(kr.keys))
	for name := range kr.keys {
		names = append(names, name)
	}
	return names
}

// Len returns the number of keys in the ring.
func (kr *KeyRing) Len() int {
	if kr == nil {
		return 0
	}
	return len(kr.keys)
}

// Verify validates the TSIG on a raw DNS wire-format message.
// requestMAC should be empty for incoming requests (first message in exchange).
// Returns nil if TSIG is valid, or an error describing the failure.
func Verify(msg []byte, keyRing *KeyRing, requestMAC string) error {
	if keyRing == nil {
		return fmt.Errorf("tsig: no key ring configured")
	}

	// Parse the message to extract the TSIG RR
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		return fmt.Errorf("tsig: unpack message: %w", err)
	}

	if m.IsTsig() == nil {
		return fmt.Errorf("tsig: message has no TSIG record")
	}

	tsigRR := m.IsTsig()
	keyName := tsigRR.Hdr.Name

	secret, ok := keyRing.Secret(keyName)
	if !ok {
		return fmt.Errorf("tsig: unknown key %q", keyName)
	}

	// dns.TsigVerify operates on the raw wire bytes
	if err := dns.TsigVerify(msg, secret, requestMAC, false); err != nil {
		return fmt.Errorf("tsig: verification failed for key %q: %w", keyName, err)
	}

	return nil
}

// Sign adds a TSIG record to a DNS message and returns the signed wire-format bytes
// and the MAC (for use as requestMAC in subsequent messages in a multi-message exchange).
// keyName must exist in keyRing.
func Sign(m *dns.Msg, keyName string, keyRing *KeyRing, requestMAC string) ([]byte, string, error) {
	if keyRing == nil {
		return nil, "", fmt.Errorf("tsig: no key ring configured")
	}

	name := dns.Fqdn(strings.ToLower(keyName))
	secret, ok := keyRing.Secret(name)
	if !ok {
		return nil, "", fmt.Errorf("tsig: unknown key %q", keyName)
	}

	alg, _ := keyRing.Algorithm(name)

	// Set the TSIG record on the message
	m.SetTsig(name, alg, 300, 0)

	// Generate the signed wire-format message
	wire, mac, err := dns.TsigGenerate(m, secret, requestMAC, false)
	if err != nil {
		return nil, "", fmt.Errorf("tsig: sign failed for key %q: %w", keyName, err)
	}

	return wire, mac, nil
}

// ValidateAlgorithm checks whether the given algorithm string is supported.
// Accepts both "hmac-sha256" and "hmac-sha256." forms.
func ValidateAlgorithm(alg string) error {
	normalized := normalizeAlgorithm(alg)
	if !supportedAlgorithms[normalized] {
		return fmt.Errorf("unsupported TSIG algorithm %q (supported: hmac-sha256, hmac-sha384, hmac-sha512)", alg)
	}
	return nil
}

// normalizeAlgorithm ensures the algorithm has the trailing dot (FQDN form).
func normalizeAlgorithm(alg string) string {
	lower := strings.ToLower(strings.TrimSpace(alg))
	if !strings.HasSuffix(lower, ".") {
		lower += "."
	}
	return lower
}
