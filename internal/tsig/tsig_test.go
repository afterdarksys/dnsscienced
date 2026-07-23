package tsig

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestKeyRingVerifyAcceptsRFC8945TruncationAndRejectsInvalidLengths(t *testing.T) {
	kr, err := NewKeyRing([]KeyConfig{{
		Name:      "truncation.example.",
		Algorithm: "hmac-sha256",
		Secret:    base64.StdEncoding.EncodeToString([]byte("truncation-test-secret")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("authenticated DNS message")
	record := &dns.TSIG{
		Hdr:       dns.RR_Header{Name: "truncation.example."},
		Algorithm: dns.HmacSHA256,
	}
	fullMAC, err := kr.Generate(message, record)
	if err != nil {
		t.Fatal(err)
	}

	record.MAC = hex.EncodeToString(fullMAC[:16])
	if err := kr.Verify(message, record); err != nil {
		t.Fatalf("RFC 8945 minimum SHA-256 truncation rejected: %v", err)
	}

	record.MAC = hex.EncodeToString(fullMAC[:15])
	if err := kr.Verify(message, record); !errors.Is(err, ErrBadTruncation) {
		t.Fatalf("short MAC error = %v, want ErrBadTruncation", err)
	}

	record.MAC = hex.EncodeToString(append(fullMAC, 0))
	if err := kr.Verify(message, record); !errors.Is(err, ErrMalformedMAC) {
		t.Fatalf("oversized MAC error = %v, want ErrMalformedMAC", err)
	}
}

// Threats: an attacker forging TSIG-signed queries/updates without knowing
// the shared secret, by exploiting distinguishable BADSIG-vs-BADTRUNC
// responses as a byte-by-byte oracle to learn a valid truncated MAC prefix.
// This proves that submitting a MAC shorter than the RFC 8945 minimum
// truncation length returns the identical error regardless of whether the
// attacker's guessed bytes happen to be correct or wrong — no signal below
// the policy floor, so the byte-by-byte forgery oracle described in
// Verify's doc comment cannot be mounted.
func TestKeyRingVerifyClosesSubMinimumTruncationOracle(t *testing.T) {
	kr, err := NewKeyRing([]KeyConfig{{
		Name:      "oracle.example.",
		Algorithm: "hmac-sha256",
		Secret:    generateTestSecret(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("authenticated DNS message")
	record := &dns.TSIG{
		Hdr:       dns.RR_Header{Name: "oracle.example."},
		Algorithm: dns.HmacSHA256,
	}
	fullMAC, err := kr.Generate(message, record)
	if err != nil {
		t.Fatal(err)
	}

	// A correct-content guess below the minimum truncation length (15 bytes,
	// one short of the 16-byte SHA-256 floor) must still be rejected as
	// ErrBadTruncation, never accepted and never distinguished from a
	// wrong-content guess by returning dns.ErrSig instead.
	record.MAC = hex.EncodeToString(fullMAC[:15])
	errCorrectPrefix := kr.Verify(message, record)
	if !errors.Is(errCorrectPrefix, ErrBadTruncation) {
		t.Fatalf("correct-prefix sub-minimum MAC error = %v, want ErrBadTruncation (oracle not closed)", errCorrectPrefix)
	}

	// A wrong-content guess of the same length must produce the exact same
	// error — proving no distinguishable signal leaks below the policy
	// floor regardless of whether the guessed bytes were right or wrong.
	wrongPrefix := append([]byte(nil), fullMAC[:15]...)
	wrongPrefix[14] ^= 0xFF
	record.MAC = hex.EncodeToString(wrongPrefix)
	errWrongPrefix := kr.Verify(message, record)
	if !errors.Is(errWrongPrefix, ErrBadTruncation) {
		t.Fatalf("wrong-prefix sub-minimum MAC error = %v, want ErrBadTruncation", errWrongPrefix)
	}
	if !errors.Is(errCorrectPrefix, errWrongPrefix) {
		t.Fatalf("correct-prefix and wrong-prefix sub-minimum guesses returned different errors (%v vs %v) — oracle present", errCorrectPrefix, errWrongPrefix)
	}

	// A single guessed byte (far below minimum) must behave identically:
	// always ErrBadTruncation, never leaking whether that byte was right.
	record.MAC = hex.EncodeToString(fullMAC[:1])
	if err := kr.Verify(message, record); !errors.Is(err, ErrBadTruncation) {
		t.Fatalf("1-byte correct-prefix MAC error = %v, want ErrBadTruncation", err)
	}
	record.MAC = hex.EncodeToString([]byte{fullMAC[0] ^ 0xFF})
	if err := kr.Verify(message, record); !errors.Is(err, ErrBadTruncation) {
		t.Fatalf("1-byte wrong-prefix MAC error = %v, want ErrBadTruncation", err)
	}
}

func generateTestSecret() string {
	// 32 bytes for HMAC-SHA256
	raw := []byte("0123456789abcdef0123456789abcdef")
	return base64.StdEncoding.EncodeToString(raw)
}

func TestTSIG_KeyRingProviderRoundTrip(t *testing.T) {
	secret := generateTestSecret()
	kr, err := NewKeyRing([]KeyConfig{{Name: "provider.example.", Algorithm: "hmac-sha256", Secret: secret}})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetTsig("provider.example.", dns.HmacSHA256, 300, time.Now().Unix())
	wire, _, err := dns.TsigGenerateWithProvider(m, kr, "", false)
	if err != nil {
		t.Fatalf("TsigGenerateWithProvider: %v", err)
	}
	if err := dns.TsigVerifyWithProvider(wire, kr, "", false); err != nil {
		t.Fatalf("TsigVerifyWithProvider: %v", err)
	}
}

func TestTSIG_ProviderConcurrentKeyRotation(t *testing.T) {
	secret := generateTestSecret()
	kr, err := NewKeyRing([]KeyConfig{{Name: "stable.example.", Algorithm: "hmac-sha256", Secret: secret}})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	tsigRR := &dns.TSIG{Hdr: dns.RR_Header{Name: "stable.example."}, Algorithm: dns.HmacSHA256}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if _, err := kr.Generate([]byte("message"), tsigRR); err != nil {
					t.Errorf("Generate: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		name := "rotating.example."
		_ = kr.Remove(name)
		if err := kr.Add(KeyConfig{Name: name, Algorithm: "hmac-sha256", Secret: secret}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	wg.Wait()
}

func TestTSIG_ProviderRejectsAlgorithmDowngrade(t *testing.T) {
	kr, err := NewKeyRing([]KeyConfig{{
		Name:      "strict.example.",
		Algorithm: "hmac-sha512",
		Secret:    base64.StdEncoding.EncodeToString([]byte("strict-secret")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	tsigRR := &dns.TSIG{
		Hdr:       dns.RR_Header{Name: "strict.example."},
		Algorithm: dns.HmacSHA256,
	}
	if _, err := kr.Generate([]byte("message"), tsigRR); !errors.Is(err, dns.ErrKeyAlg) {
		t.Fatalf("Generate error = %v, want ErrKeyAlg", err)
	}
}

func TestTSIG_NewKeyRing_Valid(t *testing.T) {
	secret := generateTestSecret()
	keys := []KeyConfig{
		{Name: "xfer-key.example.com", Algorithm: "hmac-sha256", Secret: secret},
		{Name: "update-key.example.com.", Algorithm: "hmac-sha512", Secret: secret},
	}

	kr, err := NewKeyRing(keys)
	if err != nil {
		t.Fatalf("NewKeyRing() error: %v", err)
	}
	if kr.Len() != 2 {
		t.Errorf("expected 2 keys, got %d", kr.Len())
	}

	// Check normalization (FQDN)
	s, ok := kr.Secret("xfer-key.example.com.")
	if !ok {
		t.Error("Secret lookup failed for xfer-key.example.com.")
	}
	if s != secret {
		t.Error("Secret mismatch")
	}

	// Lookup without trailing dot should also work
	s2, ok2 := kr.Secret("xfer-key.example.com")
	if !ok2 || s2 != secret {
		t.Error("Secret lookup without trailing dot failed")
	}
}

func TestTSIG_NewKeyRing_InvalidAlgorithm(t *testing.T) {
	keys := []KeyConfig{
		{Name: "bad.example.com", Algorithm: "hmac-md5", Secret: generateTestSecret()},
	}
	_, err := NewKeyRing(keys)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestTSIG_NewKeyRing_InvalidBase64(t *testing.T) {
	keys := []KeyConfig{
		{Name: "bad.example.com", Algorithm: "hmac-sha256", Secret: "not-valid-base64!!!"},
	}
	_, err := NewKeyRing(keys)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestTSIG_ValidateAlgorithm(t *testing.T) {
	valid := []string{"hmac-sha256", "hmac-sha256.", "hmac-sha384", "hmac-sha512", "HMAC-SHA256"}
	for _, a := range valid {
		if err := ValidateAlgorithm(a); err != nil {
			t.Errorf("ValidateAlgorithm(%q) unexpected error: %v", a, err)
		}
	}

	invalid := []string{"hmac-md5", "hmac-sha1", "rsa-sha256", ""}
	for _, a := range invalid {
		if err := ValidateAlgorithm(a); err == nil {
			t.Errorf("ValidateAlgorithm(%q) expected error, got nil", a)
		}
	}
}

func TestTSIG_TsigSecretMap(t *testing.T) {
	secret := generateTestSecret()
	keys := []KeyConfig{
		{Name: "k1.example.com", Algorithm: "hmac-sha256", Secret: secret},
	}
	kr, _ := NewKeyRing(keys)
	m := kr.TsigSecretMap()
	if m == nil {
		t.Fatal("TsigSecretMap returned nil")
	}
	if m["k1.example.com."] != secret {
		t.Errorf("expected secret in map for k1.example.com., got %q", m["k1.example.com."])
	}
}

func TestTSIG_SignAndVerify_RoundTrip(t *testing.T) {
	secret := generateTestSecret()
	keys := []KeyConfig{
		{Name: "test-key.example.com.", Algorithm: "hmac-sha256", Secret: secret},
	}
	kr, err := NewKeyRing(keys)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}

	// Build a simple DNS query
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Id = 1234

	// Sign the message
	wire, mac, err := Sign(m, "test-key.example.com.", kr, "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Sign returned empty wire")
	}
	if mac == "" {
		t.Fatal("Sign returned empty MAC")
	}

	// Verify the signed message
	err = Verify(wire, kr, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTSIG_Verify_NoTSIG(t *testing.T) {
	kr, _ := NewKeyRing([]KeyConfig{
		{Name: "k.example.com.", Algorithm: "hmac-sha256", Secret: generateTestSecret()},
	})

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, _ := m.Pack()

	err := Verify(wire, kr, "")
	if err == nil {
		t.Fatal("expected error for message without TSIG")
	}
}

func TestTSIG_Verify_UnknownKey(t *testing.T) {
	secret := generateTestSecret()
	// Sign with key "a" but verify with ring containing only key "b"
	krSign, _ := NewKeyRing([]KeyConfig{
		{Name: "a.example.com.", Algorithm: "hmac-sha256", Secret: secret},
	})
	krVerify, _ := NewKeyRing([]KeyConfig{
		{Name: "b.example.com.", Algorithm: "hmac-sha256", Secret: secret},
	})

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, _, _ := Sign(m, "a.example.com.", krSign, "")

	err := Verify(wire, krVerify, "")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestTSIG_NilKeyRing(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, _ := m.Pack()

	if err := Verify(wire, nil, ""); err == nil {
		t.Error("Verify with nil keyRing should error")
	}

	_, _, err := Sign(m, "k.example.com.", nil, "")
	if err == nil {
		t.Error("Sign with nil keyRing should error")
	}
}

func TestTSIG_KeyRing_Add(t *testing.T) {
	kr, _ := NewKeyRing(nil)

	err := kr.Add(KeyConfig{Name: "new.example.com.", Algorithm: "hmac-sha256", Secret: generateTestSecret()})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if kr.Len() != 1 {
		t.Errorf("expected 1 key, got %d", kr.Len())
	}

	// Duplicate should fail
	err = kr.Add(KeyConfig{Name: "new.example.com.", Algorithm: "hmac-sha256", Secret: generateTestSecret()})
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestTSIG_KeyRing_Remove(t *testing.T) {
	secret := generateTestSecret()
	kr, _ := NewKeyRing([]KeyConfig{
		{Name: "rm.example.com.", Algorithm: "hmac-sha256", Secret: secret},
	})

	if !kr.Remove("rm.example.com.") {
		t.Fatal("Remove returned false for existing key")
	}
	if kr.Len() != 0 {
		t.Errorf("expected 0 keys after remove, got %d", kr.Len())
	}
	if kr.Remove("rm.example.com.") {
		t.Fatal("Remove returned true for non-existent key")
	}

	// Verify the secrets map is also updated (dns.Server sees the change)
	m := kr.TsigSecretMap()
	if _, exists := m["rm.example.com."]; exists {
		t.Error("secrets map still contains removed key")
	}
}

func TestTSIG_KeyRing_SecretMapIsSnapshot(t *testing.T) {
	kr, _ := NewKeyRing(nil)
	snapshot := kr.TsigSecretMap()

	// Mutating the ring must not mutate a map already handed to another goroutine.
	secret := generateTestSecret()
	_ = kr.Add(KeyConfig{Name: "live.example.com.", Algorithm: "hmac-sha256", Secret: secret})
	if _, exists := snapshot["live.example.com."]; exists {
		t.Error("snapshot changed after Add")
	}
	if fresh := kr.TsigSecretMap(); fresh["live.example.com."] != secret {
		t.Error("fresh snapshot did not include Add")
	}
}
