package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dnsscience/dnsscienced/api/grpc/middleware"
	"github.com/dnsscience/dnsscienced/internal/config"
)

type Config struct {
	ListenAddr   string           // e.g. ":8443"
	TLSCertFile  string
	TLSKeyFile   string
	TLSClientCAs string           // path to PEM CA bundle for mTLS; enables client cert verification
	APIKeys      []config.APIKey  // named API keys per D-04; empty + no TLSClientCAs -> startup error
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

type Deps struct {
	Register func(s *grpc.Server) // function to register all service servers
	Unary    []grpc.UnaryServerInterceptor
	Stream   []grpc.StreamServerInterceptor
}

// New creates a TLS gRPC server with fail-closed auth guards per D-01 and D-02.
// Returns (*grpc.Server, net.Listener, *ConnRegistry, error).
// Plan 05 will change this to 5-return (adding ConfigHolder).
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, *ConnRegistry, error) {
	// D-02: Fail closed - refuse to start without BOTH auth mechanisms.
	// D-01: Both mTLS and API key auth are required simultaneously.
	if cfg.TLSClientCAs == "" {
		return nil, nil, nil, fmt.Errorf("admin server requires tls_client_cas to be configured (D-02: fail closed)")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("admin server requires at least one named API key in api_keys (D-01: both mTLS and key required)")
	}

	// Create connection registry and wire as stats handler (Plan 04).
	registry := NewConnRegistry()

	var opts []grpc.ServerOption

	// TLS config via buildCreds (mTLS-capable; supports RequireAndVerifyClientCert when TLSClientCAs is set)
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		creds, err := buildCreds(cfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

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
		return nil, nil, nil, err
	}
	return gs, ln, registry, nil
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
func apiKeyStreamInterceptor(keySet *atomicKeySet) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		md, _ := metadata.FromIncomingContext(ss.Context())
		token := extractBearer(md)
		if token == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		_, ok := keySet.Lookup(token)
		if !ok {
			return status.Error(codes.Unauthenticated, "invalid bearer token")
		}
		return handler(srv, ss)
	}
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
