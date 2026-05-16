package tsig

import (
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
)

func generateTestSecret() string {
	// 32 bytes for HMAC-SHA256
	raw := []byte("0123456789abcdef0123456789abcdef")
	return base64.StdEncoding.EncodeToString(raw)
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

func TestTSIG_KeyRing_SharedMap(t *testing.T) {
	kr, _ := NewKeyRing(nil)
	sharedMap := kr.TsigSecretMap()

	// Add a key — should appear in the shared map
	secret := generateTestSecret()
	_ = kr.Add(KeyConfig{Name: "live.example.com.", Algorithm: "hmac-sha256", Secret: secret})

	if sharedMap["live.example.com."] != secret {
		t.Error("shared map did not reflect Add")
	}

	// Remove — should disappear from shared map
	kr.Remove("live.example.com.")
	if _, exists := sharedMap["live.example.com."]; exists {
		t.Error("shared map did not reflect Remove")
	}
}
