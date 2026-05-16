package server

import (
	"testing"

	"github.com/dnsscience/dnsscienced/internal/config"
)

func TestNew_NoAuthMechanism(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

func TestNew_NoTLS(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

func TestAPIKey_Valid(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

func TestAPIKey_Missing(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

func TestMTLS_NoCert(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

// TestAtomicKeySet verifies the atomicKeySet type: Lookup, IDExists, Len, and Store.
func TestAtomicKeySet(t *testing.T) {
	keys := []config.APIKey{
		{ID: "key1", Secret: "secret-aaa"},
		{ID: "key2", Secret: "secret-bbb"},
	}

	aks := newAtomicKeySet(keys)

	// Lookup: valid secret returns correct id
	id, ok := aks.Lookup("secret-aaa")
	if !ok {
		t.Fatal("Lookup: expected ok=true for valid secret, got false")
	}
	if id != "key1" {
		t.Fatalf("Lookup: expected id=%q, got %q", "key1", id)
	}

	// Lookup: unknown secret returns not-ok
	_, ok = aks.Lookup("not-a-real-secret")
	if ok {
		t.Fatal("Lookup: expected ok=false for unknown secret, got true")
	}

	// IDExists: known id
	if !aks.IDExists("key2") {
		t.Fatal("IDExists: expected true for key2, got false")
	}

	// IDExists: unknown id
	if aks.IDExists("key99") {
		t.Fatal("IDExists: expected false for key99, got true")
	}

	// Len
	if l := aks.Len(); l != 2 {
		t.Fatalf("Len: expected 2, got %d", l)
	}

	// Store replaces key set atomically
	newKeys := []config.APIKey{{ID: "key3", Secret: "secret-ccc"}}
	aks.Store(newKeys)

	if _, ok := aks.Lookup("secret-aaa"); ok {
		t.Fatal("after Store: old secret should not be valid")
	}
	id, ok = aks.Lookup("secret-ccc")
	if !ok || id != "key3" {
		t.Fatalf("after Store: expected Lookup(secret-ccc)=(key3,true), got (%q,%v)", id, ok)
	}
	if aks.IDExists("key1") {
		t.Fatal("after Store: old key id should not exist")
	}
	if !aks.IDExists("key3") {
		t.Fatal("after Store: new key id should exist")
	}
	if l := aks.Len(); l != 1 {
		t.Fatalf("after Store: Len expected 1, got %d", l)
	}
}

// TestAtomicKeyReload verifies hot-swap of key sets via Store (covers D-05 reload path).
func TestAtomicKeyReload(t *testing.T) {
	initial := []config.APIKey{{ID: "id-a", Secret: "sec-a"}}
	aks := newAtomicKeySet(initial)

	// Confirm initial state
	if _, ok := aks.Lookup("sec-a"); !ok {
		t.Fatal("initial Lookup failed")
	}

	// Hot-swap to a completely different set
	aks.Store([]config.APIKey{{ID: "id-b", Secret: "sec-b"}})

	if _, ok := aks.Lookup("sec-a"); ok {
		t.Fatal("after reload: old secret must not match")
	}
	id, ok := aks.Lookup("sec-b")
	if !ok || id != "id-b" {
		t.Fatalf("after reload: expected Lookup(sec-b)=(id-b,true), got (%q,%v)", id, ok)
	}
}

func TestConfigHolder_ReloadValidation(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

func TestConnRegistry_RemoveOnEnd(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

// TestConfig_HasTLSClientCAs verifies that grpcserver.Config has TLSClientCAs field.
func TestConfig_HasTLSClientCAs(t *testing.T) {
	cfg := Config{
		ListenAddr:   ":8443",
		TLSCertFile:  "/path/cert.pem",
		TLSKeyFile:   "/path/key.pem",
		TLSClientCAs: "/path/ca-bundle.pem",
		APIKeys:      []config.APIKey{{ID: "k1", Secret: "s1"}},
	}
	if cfg.TLSClientCAs != "/path/ca-bundle.pem" {
		t.Fatalf("TLSClientCAs field not accessible: got %q", cfg.TLSClientCAs)
	}
	if len(cfg.APIKeys) != 1 || cfg.APIKeys[0].ID != "k1" {
		t.Fatalf("APIKeys field not []config.APIKey: %+v", cfg.APIKeys)
	}
}
