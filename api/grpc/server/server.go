package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/afterdarksys/dnsscienced/api/grpc/middleware"
	"github.com/afterdarksys/dnsscienced/internal/config"
)

type Config struct {
	ListenAddr   string // e.g. ":8443"
	TLSCertFile  string
	TLSKeyFile   string
	TLSClientCAs string          // path to PEM CA bundle for mTLS; enables client cert verification
	APIKeys      []config.APIKey // named API keys per D-04; empty + no TLSClientCAs -> startup error
}

// buildCreds constructs gRPC transport credentials from cfg.
// When TLSClientCAs is set, mTLS is enabled: clients must present a cert
// signed by one of the CAs in that bundle (D-01 transport layer).
func buildCreds(cfg Config) (credentials.TransportCredentials, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("TLSCertFile and TLSKeyFile are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls key pair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.TLSClientCAs != "" {
		caPEM, err := os.ReadFile(cfg.TLSClientCAs)
		if err != nil {
			return nil, fmt.Errorf("client CA file %q: %w", cfg.TLSClientCAs, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid CA certs parsed from %q", cfg.TLSClientCAs)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsCfg), nil
}

// keyIndex holds both lookup maps for the API key set.
// secretToID maps secret -> id for O(1) auth validation + audit id retrieval (D-05).
// idSet maps id -> struct{} for O(1) id existence checks.
type keyIndex struct {
	secretToID map[string]string   // secret -> id (auth lookup + audit log per D-08)
	idSet      map[string]struct{} // id -> exists
}

// atomicKeySet holds an API key set that can be hot-swapped without a mutex.
// The interceptor calls Lookup() on every request (lock-free pointer load).
// The SIGHUP handler calls Store() to swap in a new set.
type atomicKeySet struct {
	v atomic.Value // stores keyIndex
}

func newAtomicKeySet(keys []config.APIKey) *atomicKeySet {
	s := &atomicKeySet{}
	s.Store(keys)
	return s
}

// Store atomically replaces the key set. Safe to call from any goroutine.
func (a *atomicKeySet) Store(keys []config.APIKey) {
	idx := keyIndex{
		secretToID: make(map[string]string, len(keys)),
		idSet:      make(map[string]struct{}, len(keys)),
	}
	for _, k := range keys {
		idx.secretToID[k.Secret] = k.ID
		idx.idSet[k.ID] = struct{}{}
	}
	a.v.Store(idx)
}

// Lookup returns the key ID for a given secret, and whether the secret is valid.
// Used by the auth interceptor: validates the Bearer token AND retrieves the id for audit (D-08).
func (a *atomicKeySet) Lookup(secret string) (id string, ok bool) {
	idx := a.v.Load().(keyIndex)
	id, ok = idx.secretToID[secret]
	return
}

// Len returns the number of keys currently configured.
func (a *atomicKeySet) Len() int {
	idx := a.v.Load().(keyIndex)
	return len(idx.secretToID)
}

// IDExists checks if a key ID is in the current set.
func (a *atomicKeySet) IDExists(id string) bool {
	idx := a.v.Load().(keyIndex)
	_, ok := idx.idSet[id]
	return ok
}

// ConfigHolder provides atomic full config reload per D-11.
// On SIGHUP, the handler calls Reload() which atomically swaps the key set
// and rebuilds TLS credentials if paths changed. No half-reloaded state.
type ConfigHolder struct {
	mu     sync.RWMutex
	keySet *atomicKeySet
	cfg    Config
	creds  credentials.TransportCredentials
}

// NewConfigHolder creates a holder with the initial config state.
func NewConfigHolder(cfg Config, keySet *atomicKeySet, creds credentials.TransportCredentials) *ConfigHolder {
	return &ConfigHolder{
		keySet: keySet,
		cfg:    cfg,
		creds:  creds,
	}
}

// Reload atomically swaps to a new config per D-09/D-11.
// Rebuilds TLS credentials if TLS paths changed; reloads API keys.
// Returns error if new TLS creds cannot be built (current config retained).
func (h *ConfigHolder) Reload(newCfg Config) error {
	// Validate new config has required auth (D-01/D-02)
	if newCfg.TLSClientCAs == "" {
		return fmt.Errorf("reload: tls_client_cas is required (D-02)")
	}
	if len(newCfg.APIKeys) == 0 {
		return fmt.Errorf("reload: at least one API key is required (D-01)")
	}

	// Rebuild TLS creds if any TLS path changed
	var newCreds credentials.TransportCredentials
	h.mu.RLock()
	tlsChanged := newCfg.TLSCertFile != h.cfg.TLSCertFile ||
		newCfg.TLSKeyFile != h.cfg.TLSKeyFile ||
		newCfg.TLSClientCAs != h.cfg.TLSClientCAs
	h.mu.RUnlock()

	if tlsChanged && (newCfg.TLSCertFile != "" && newCfg.TLSKeyFile != "") {
		var err error
		newCreds, err = buildCreds(newCfg)
		if err != nil {
			return fmt.Errorf("reload: failed to build new TLS credentials: %w", err)
		}
	}

	// Atomic swap (D-11): update everything under write lock
	h.mu.Lock()
	h.keySet.Store(newCfg.APIKeys)
	h.cfg = newCfg
	if newCreds != nil {
		h.creds = newCreds
	}
	h.mu.Unlock()

	return nil
}

// CurrentConfig returns a copy of the current config (for diagnostics).
func (h *ConfigHolder) CurrentConfig() Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// GetCreds returns the current TLS credentials (for future dynamic TLS reload).
func (h *ConfigHolder) GetCreds() credentials.TransportCredentials {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.creds
}

type Deps struct {
	Register func(s *grpc.Server) // function to register all service servers
	Unary    []grpc.UnaryServerInterceptor
	Stream   []grpc.StreamServerInterceptor
}

// New creates a TLS gRPC server with fail-closed auth guards per D-01 and D-02.
// Returns (*grpc.Server, net.Listener, *ConnRegistry, *ConfigHolder, error).
// ConfigHolder enables SIGHUP full config reload per D-09/D-11.
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, *ConnRegistry, *ConfigHolder, error) {
	// D-02: Fail closed - refuse to start without BOTH auth mechanisms.
	// D-01: Both mTLS and API key auth are required simultaneously.
	if cfg.TLSClientCAs == "" {
		return nil, nil, nil, nil, fmt.Errorf("admin server requires tls_client_cas to be configured (D-02: fail closed)")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("admin server requires at least one named API key in api_keys (D-01: both mTLS and key required)")
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, nil, nil, nil, fmt.Errorf("admin server requires both tls_cert_file and tls_key_file when mTLS is enabled")
	}

	// Create connection registry and wire as stats handler (Plan 04).
	registry := NewConnRegistry()

	var opts []grpc.ServerOption
	var builtCreds credentials.TransportCredentials

	// TLS config via buildCreds (mTLS-capable; supports RequireAndVerifyClientCert when TLSClientCAs is set)
	creds, err := buildCreds(cfg)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tls: %w", err)
	}
	builtCreds = creds
	opts = append(opts, grpc.Creds(creds))

	// Wire ConnRegistry as gRPC stats handler to track all admin connections.
	opts = append(opts, grpc.StatsHandler(registry))

	// Interceptors (chain) using atomicKeySet for AND auth per D-01
	keySet := newAtomicKeySet(cfg.APIKeys)
	unaries := append([]grpc.UnaryServerInterceptor{apiKeyUnaryInterceptor(keySet)}, deps.Unary...)
	streams := append([]grpc.StreamServerInterceptor{apiKeyStreamInterceptor(keySet)}, deps.Stream...)
	opts = append(opts,
		grpc.ChainUnaryInterceptor(unaries...),
		grpc.ChainStreamInterceptor(streams...),
	)

	gs := grpc.NewServer(opts...)
	if deps.Register != nil {
		deps.Register(gs)
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create ConfigHolder for SIGHUP full config reload per D-09/D-11.
	configHolder := NewConfigHolder(cfg, keySet, builtCreds)

	return gs, ln, registry, configHolder, nil
}

// apiKeyUnaryInterceptor enforces Bearer token auth on every request.
// Per D-01: API key auth is ALWAYS required (AND with mTLS, not OR).
// On success, stores the key's named ID in context for audit logging (D-08).
func apiKeyUnaryInterceptor(keySet *atomicKeySet) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		token := extractBearer(md)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		id, ok := keySet.Lookup(token)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
		}
		// Store the named key ID in context for audit interceptor (D-08: log id, not secret)
		ctx = context.WithValue(ctx, middleware.CtxKeyID{}, id)
		return handler(ctx, req)
	}
}

// apiKeyStreamInterceptor enforces Bearer token auth on every stream.
// Per D-01: API key auth is ALWAYS required (AND with mTLS, not OR).
// Stores key ID in context via CtxKeyID{} for audit logging (matches unary interceptor).
func apiKeyStreamInterceptor(keySet *atomicKeySet) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		md, _ := metadata.FromIncomingContext(ss.Context())
		token := extractBearer(md)
		if token == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		id, ok := keySet.Lookup(token)
		if !ok {
			return status.Error(codes.Unauthenticated, "invalid bearer token")
		}
		// Enrich stream context with key ID for audit logging.
		wrapped := &keyIDStream{
			ServerStream: ss,
			ctx:          context.WithValue(ss.Context(), middleware.CtxKeyID{}, id),
		}
		return handler(srv, wrapped)
	}
}

// keyIDStream wraps a grpc.ServerStream to override Context() with an enriched context
// containing the authenticated API key ID.
type keyIDStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *keyIDStream) Context() context.Context {
	return s.ctx
}

// extractBearer returns the Bearer token from gRPC metadata authorization header.
func extractBearer(md metadata.MD) string {
	vals := md.Get("authorization")
	for _, v := range vals {
		const prefix = "Bearer "
		if len(v) > len(prefix) && v[:len(prefix)] == prefix {
			return v[len(prefix):]
		}
	}
	return ""
}
