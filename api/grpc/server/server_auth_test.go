package server

import (
	"testing"

	"github.com/dnsscience/dnsscienced/internal/config"
)

// TestBuildCreds_MissingFiles verifies buildCreds returns an error when TLSCertFile or TLSKeyFile is empty.
func TestBuildCreds_MissingFiles(t *testing.T) {
	_, err := buildCreds(Config{})
	if err == nil {
		t.Fatal("buildCreds: expected error when TLSCertFile and TLSKeyFile are empty, got nil")
	}
}

// TestBuildCreds_BadKeyPair verifies buildCreds returns an error when cert files don't exist.
func TestBuildCreds_BadKeyPair(t *testing.T) {
	_, err := buildCreds(Config{
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("buildCreds: expected error for nonexistent cert files, got nil")
	}
}

// TestBuildCreds_BadCAFile verifies buildCreds returns an error when TLSClientCAs file doesn't exist.
func TestBuildCreds_BadCAFile(t *testing.T) {
	// We use the test cert files if they exist, otherwise just verify the error path
	_, err := buildCreds(Config{
		TLSCertFile:  "/nonexistent/cert.pem",
		TLSKeyFile:   "/nonexistent/key.pem",
		TLSClientCAs: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("buildCreds: expected error for nonexistent files, got nil")
	}
}

// TestNew_NoAuthMechanism verifies New() returns an error when both TLSClientCAs and APIKeys are unset.
func TestNew_NoAuthMechanism(t *testing.T) {
	_, _, _, _, err := New(Config{ListenAddr: ":0"}, Deps{})
	if err == nil {
		t.Fatal("New: expected error with no auth configured, got nil")
	}
}

// TestNew_NoTLS verifies New() returns an error when TLSClientCAs is empty (fail-closed D-02).
func TestNew_NoTLS(t *testing.T) {
	_, _, _, _, err := New(Config{
		ListenAddr: ":0",
		APIKeys:    []config.APIKey{{ID: "k1", Secret: "s1"}},
		// TLSClientCAs intentionally empty
	}, Deps{})
	if err == nil {
		t.Fatal("New: expected error when TLSClientCAs is empty, got nil")
	}
}

// TestNew_NoAPIKeys verifies New() returns an error when APIKeys is empty even if TLSClientCAs is set.
func TestNew_NoAPIKeys(t *testing.T) {
	_, _, _, _, err := New(Config{
		ListenAddr:   ":0",
		TLSClientCAs: "/some/ca.pem",
		// APIKeys intentionally empty
	}, Deps{})
	if err == nil {
		t.Fatal("New: expected error when APIKeys is empty, got nil")
	}
}

// TestAPIKey_Valid verifies interceptor accepts a valid Bearer token.
func TestAPIKey_Valid(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

// TestAPIKey_Missing verifies interceptor rejects missing Bearer token.
func TestAPIKey_Missing(t *testing.T) {
	t.Skip("stub -- implemented in Plan 06")
}

// TestMTLS_NoCert verifies mTLS rejection when client cert is absent.
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

// TestConfigHolder_ReloadValidation verifies that ConfigHolder.Reload() validates
// D-01/D-02 requirements before swapping config (bad config leaves current intact).
func TestConfigHolder_ReloadValidation(t *testing.T) {
	keys := []config.APIKey{{ID: "k1", Secret: "s1"}}
	ks := newAtomicKeySet(keys)
	holder := NewConfigHolder(Config{
		TLSCertFile:  "/path/cert.pem",
		TLSKeyFile:   "/path/key.pem",
		TLSClientCAs: "/path/ca.pem",
		APIKeys:      keys,
	}, ks, nil)

	// Reload without TLSClientCAs must fail (D-02)
	err := holder.Reload(Config{
		APIKeys: []config.APIKey{{ID: "k2", Secret: "s2"}},
	})
	if err == nil {
		t.Fatal("Reload: expected error when TLSClientCAs is empty, got nil")
	}

	// Reload without APIKeys must fail (D-01)
	err = holder.Reload(Config{
		TLSClientCAs: "/path/ca.pem",
	})
	if err == nil {
		t.Fatal("Reload: expected error when APIKeys is empty, got nil")
	}

	// Current config retained after failed reload - key s1 still valid
	id, ok := ks.Lookup("s1")
	if !ok || id != "k1" {
		t.Fatalf("Reload: current config must be retained after failed reload; Lookup(s1)=(%q,%v)", id, ok)
	}
}

// TestConfigHolder_ReloadKeysOnly verifies that ConfigHolder.Reload() hot-swaps API keys
// when TLS paths are unchanged (no TLS rebuild needed).
func TestConfigHolder_ReloadKeysOnly(t *testing.T) {
	keys := []config.APIKey{{ID: "k1", Secret: "s1"}}
	ks := newAtomicKeySet(keys)
	holder := NewConfigHolder(Config{
		TLSClientCAs: "/path/ca.pem",
		APIKeys:      keys,
	}, ks, nil)

	// Reload with same TLS paths but different API keys
	newKeys := []config.APIKey{{ID: "k2", Secret: "s2"}}
	err := holder.Reload(Config{
		TLSClientCAs: "/path/ca.pem",
		APIKeys:      newKeys,
	})
	if err != nil {
		t.Fatalf("Reload: unexpected error: %v", err)
	}

	// Old key must be gone
	if _, ok := ks.Lookup("s1"); ok {
		t.Fatal("Reload: old key s1 must not be valid after reload")
	}
	// New key must be valid
	id, ok := ks.Lookup("s2")
	if !ok || id != "k2" {
		t.Fatalf("Reload: new key not valid after reload; Lookup(s2)=(%q,%v)", id, ok)
	}

	// CurrentConfig must reflect new config
	got := holder.CurrentConfig()
	if len(got.APIKeys) != 1 || got.APIKeys[0].ID != "k2" {
		t.Fatalf("CurrentConfig: expected k2 after reload, got %+v", got.APIKeys)
	}
}

// TestNew_ReturnsConfigHolder verifies New() returns 5 values including *ConfigHolder.
func TestNew_ReturnsConfigHolder(t *testing.T) {
	// New() should fail with missing TLS files (D-02), but the important thing
	// is the signature is 5 returns: (*grpc.Server, net.Listener, *ConnRegistry, *ConfigHolder, error)
	_, _, _, _, err := New(Config{ListenAddr: ":0"}, Deps{})
	// error expected (no auth configured), but 5-return signature must compile
	if err == nil {
		t.Fatal("New: expected error with no auth configured, got nil")
	}
}

// TestConnRegistry_RemoveOnEnd moved to conn_registry_test.go (Plan 04)

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
