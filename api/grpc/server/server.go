package server

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"

	"github.com/dnsscience/dnsscienced/internal/config"
)

type Config struct {
	ListenAddr   string           // e.g. ":8443"
	TLSCertFile  string
	TLSKeyFile   string
	TLSClientCAs string           // path to PEM CA bundle for mTLS; enables client cert verification
	APIKeys      []config.APIKey  // named API keys per D-04; empty + no TLSClientCAs -> startup error
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

// New creates a TLS gRPC server with basic auth interceptors.
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, error) {
	var opts []grpc.ServerOption

	// TLS config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Interceptors (chain)
	unaries := append([]grpc.UnaryServerInterceptor{apiKeyUnaryInterceptor(cfg.APIKeys)}, deps.Unary...)
	streams := append([]grpc.StreamServerInterceptor{apiKeyStreamInterceptor(cfg.APIKeys)}, deps.Stream...)
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
		return nil, nil, err
	}
	return gs, ln, nil
}

func apiKeyUnaryInterceptor(validKeys []config.APIKey) grpc.UnaryServerInterceptor {
	set := make(map[string]struct{}, len(validKeys))
	for _, k := range validKeys {
		set[k.Secret] = struct{}{}
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if len(set) > 0 {
			md, _ := metadata.FromIncomingContext(ctx)
			if !authorize(md, set) {
				return nil, status.Error(codes.Unauthenticated, "unauthenticated")
			}
		}
		return handler(ctx, req)
	}
}

func apiKeyStreamInterceptor(validKeys []config.APIKey) grpc.StreamServerInterceptor {
	set := make(map[string]struct{}, len(validKeys))
	for _, k := range validKeys {
		set[k.Secret] = struct{}{}
	}
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if len(set) > 0 {
			md, _ := metadata.FromIncomingContext(ss.Context())
			if !authorize(md, set) {
				return status.Error(codes.Unauthenticated, "unauthenticated")
			}
		}
		return handler(srv, ss)
	}
}

func authorize(md metadata.MD, set map[string]struct{}) bool {
	if md == nil {
		return false
	}
	vals := md.Get("authorization")
	for _, v := range vals {
		var token string
		fmt.Sscanf(v, "Bearer %s", &token)
		if _, ok := set[token]; ok {
			return true
		}
	}
	return false
}
