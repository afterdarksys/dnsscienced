package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/stats"

	"github.com/dnsscience/dnsscienced/api/grpc/middleware"
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
	_, err := buildCreds(Config{
		TLSCertFile:  "/nonexistent/cert.pem",
		TLSKeyFile:   "/nonexistent/key.pem",
		TLSClientCAs: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("buildCreds: expected error for nonexistent files, got nil")
	}
}

// TestNew_NoAuthMechanism verifies New() returns an error containing "tls_client_cas" when
// TLSClientCAs is empty (D-02 guard).
func TestNew_NoAuthMechanism(t *testing.T) {
	cfg := Config{ListenAddr: "localhost:0"}
	_, _, _, _, err := New(cfg, Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls_client_cas")
}

// TestNew_MTLSButNoKeys verifies New() returns an error containing "API key" when
// TLSClientCAs is set but APIKeys is empty (D-01 AND: both cert and key are required).
func TestNew_MTLSButNoKeys(t *testing.T) {
	cfg := Config{ListenAddr: "localhost:0", TLSClientCAs: "/some/ca.pem"}
	_, _, _, _, err := New(cfg, Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key")
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

// TestMTLS_NoCert verifies mTLS rejection when the client does not present a certificate.
// ADMIN-AUTH-02: dial without client cert -> TLS handshake failure.
func TestMTLS_NoCert(t *testing.T) {
	// Generate ephemeral test CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate server cert signed by test CA
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write temp files
	tmpDir := t.TempDir()
	writePEM(t, filepath.Join(tmpDir, "ca.pem"), "CERTIFICATE", caCertDER)
	writePEM(t, filepath.Join(tmpDir, "srv.pem"), "CERTIFICATE", srvCertDER)
	writeKeyPEM(t, filepath.Join(tmpDir, "srv-key.pem"), srvKey)

	// Build server TLS config with RequireAndVerifyClientCert
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvCertDER},
			PrivateKey:  srvKey,
		}},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	// Start in-process gRPC server with mTLS
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	go gs.Serve(lis) //nolint:errcheck
	defer gs.Stop()

	// Dial WITHOUT client cert (only trust server CA)
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(caCert)
	clientTLS := credentials.NewTLS(&tls.Config{
		RootCAs:    clientCertPool,
		MinVersion: tls.VersionTLS13,
		// NO Certificates field -> no client cert presented
	})
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(clientTLS)) //nolint:staticcheck
	if err != nil {
		// Connection-level rejection (some OS/versions reject at dial)
		return // test passes: connection rejected without client cert
	}
	defer conn.Close()

	// If dial succeeded, the first RPC must fail with transport/TLS error
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = conn.Invoke(ctx, "/test.Service/Ping", nil, nil)
	require.Error(t, err, "RPC must fail when no client cert is presented to mTLS server")
	assert.True(t, isTransportOrTLSError(err),
		"expected transport/TLS error, got: %v", err)
}

// isTransportOrTLSError returns true when err indicates a TLS handshake or transport failure.
func isTransportOrTLSError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "certificate required") ||
		strings.Contains(s, "tls:") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "transport closing") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "EOF") ||
		status.Code(err) == codes.Unavailable
}

// TestAPIKey_Valid verifies the apiKeyUnaryInterceptor accepts a valid Bearer token and
// stores the named key id (not a hash) in context per D-08.
func TestAPIKey_Valid(t *testing.T) {
	keySet := newAtomicKeySet([]config.APIKey{{ID: "admin-key", Secret: "mysecret"}})
	interceptor := apiKeyUnaryInterceptor(keySet)
	md := metadata.New(map[string]string{"authorization": "Bearer mysecret"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return nil, nil
	}
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, handler)
	require.NoError(t, err)
	// D-08: named key id "admin-key" stored in context (not sha256 hash)
	kid, ok := capturedCtx.Value(middleware.CtxKeyID{}).(string)
	require.True(t, ok, "CtxKeyID must be set in context after successful auth")
	assert.Equal(t, "admin-key", kid)
}

// TestAPIKey_Missing verifies the apiKeyUnaryInterceptor rejects requests with no Bearer header.
func TestAPIKey_Missing(t *testing.T) {
	keySet := newAtomicKeySet([]config.APIKey{{ID: "k1", Secret: "s1"}})
	interceptor := apiKeyUnaryInterceptor(keySet)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.New(nil))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, nil)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
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

// TestAtomicKeyReload verifies hot-swap of key sets via Store (RELOAD-02).
func TestAtomicKeyReload(t *testing.T) {
	ks := newAtomicKeySet([]config.APIKey{{ID: "k1", Secret: "s1"}})
	id, ok := ks.Lookup("s1")
	assert.True(t, ok)
	assert.Equal(t, "k1", id)

	ks.Store([]config.APIKey{{ID: "k2", Secret: "s2"}})
	_, ok = ks.Lookup("s1")
	assert.False(t, ok, "old key must not be present after reload")
	id2, ok2 := ks.Lookup("s2")
	assert.True(t, ok2)
	assert.Equal(t, "k2", id2)
}

// TestConfigHolder_ReloadValidation verifies that ConfigHolder.Reload() validates
// D-01/D-02 requirements before swapping config (bad config leaves current intact).
func TestConfigHolder_ReloadValidation(t *testing.T) {
	keySet := newAtomicKeySet([]config.APIKey{{ID: "k1", Secret: "s1"}})
	holder := NewConfigHolder(Config{
		TLSCertFile:  "a.pem",
		TLSKeyFile:   "a.key",
		TLSClientCAs: "ca.pem",
		APIKeys:      []config.APIKey{{ID: "k1", Secret: "s1"}},
	}, keySet, nil)

	// Reload with empty keys -> error (D-01)
	err := holder.Reload(Config{TLSClientCAs: "ca.pem", APIKeys: nil})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key")

	// Reload with empty TLSClientCAs -> error (D-02)
	err = holder.Reload(Config{TLSClientCAs: "", APIKeys: []config.APIKey{{ID: "k2", Secret: "s2"}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls_client_cas")
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

	newKeys := []config.APIKey{{ID: "k2", Secret: "s2"}}
	err := holder.Reload(Config{
		TLSClientCAs: "/path/ca.pem",
		APIKeys:      newKeys,
	})
	if err != nil {
		t.Fatalf("Reload: unexpected error: %v", err)
	}

	if _, ok := ks.Lookup("s1"); ok {
		t.Fatal("Reload: old key s1 must not be valid after reload")
	}
	id, ok := ks.Lookup("s2")
	if !ok || id != "k2" {
		t.Fatalf("Reload: new key not valid after reload; Lookup(s2)=(%q,%v)", id, ok)
	}

	got := holder.CurrentConfig()
	if len(got.APIKeys) != 1 || got.APIKeys[0].ID != "k2" {
		t.Fatalf("CurrentConfig: expected k2 after reload, got %+v", got.APIKeys)
	}
}

// TestNew_ReturnsConfigHolder verifies New() returns 5 values including *ConfigHolder.
func TestNew_ReturnsConfigHolder(t *testing.T) {
	_, _, _, _, err := New(Config{ListenAddr: ":0"}, Deps{})
	if err == nil {
		t.Fatal("New: expected error with no auth configured, got nil")
	}
}

// TestConnRegistry_TagAndRemoveWithAddr verifies TagConn stores entry with RemoteAddr; List() returns it;
// HandleConn removes it (CONN-01 + D-12 RemoteAddr parsing).
func TestConnRegistry_TagAndRemoveWithAddr(t *testing.T) {
	r := NewConnRegistry()
	info := &stats.ConnTagInfo{RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}}
	ctx := r.TagConn(context.Background(), info)
	conns := r.List()
	require.Len(t, conns, 1)
	assert.Equal(t, "127.0.0.1:9000", conns[0].RemoteAddr)

	r.HandleConn(ctx, &stats.ConnEnd{})
	assert.Empty(t, r.List())
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

// writePEM writes a PEM block to path.
func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}))
}

// writeKeyPEM writes an EC private key as PEM to path.
func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	writePEM(t, path, "EC PRIVATE KEY", der)
}
