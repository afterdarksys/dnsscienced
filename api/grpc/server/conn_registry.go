package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/stats"
)

// ConnInfo holds metadata about a single active admin gRPC connection.
// KeyID and CertCN are populated by the auth interceptor via EnrichConn (D-12).
type ConnInfo struct {
	ID            string
	RemoteAddr    string
	ConnectedAt   time.Time
	QueriesServed int64
	KeyID         string // populated by auth interceptor after successful key validation (D-12)
	CertCN        string // populated by auth interceptor from peer cert CN (D-12)
}

// connIDKey is the context key used to propagate the connection UUID through the stats handler.
type connIDKey struct{}

// ConnRegistry implements grpc/stats.Handler to track active admin connections.
// Wire it via grpc.StatsHandler(registry) in server options.
type ConnRegistry struct {
	mu    sync.RWMutex
	conns map[string]*ConnInfo
}

// NewConnRegistry creates an empty registry.
func NewConnRegistry() *ConnRegistry {
	return &ConnRegistry{conns: make(map[string]*ConnInfo)}
}

// TagConn assigns a UUID to the new connection and stores it in the context and registry.
func (r *ConnRegistry) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	id := newUUID()
	addr := ""
	if info != nil && info.RemoteAddr != nil {
		addr = info.RemoteAddr.String()
	}
	r.mu.Lock()
	r.conns[id] = &ConnInfo{
		ID:          id,
		RemoteAddr:  addr,
		ConnectedAt: time.Now(),
	}
	r.mu.Unlock()
	return context.WithValue(ctx, connIDKey{}, id)
}

// HandleConn removes the connection from the registry on disconnect.
func (r *ConnRegistry) HandleConn(ctx context.Context, cs stats.ConnStats) {
	if _, ok := cs.(*stats.ConnEnd); ok {
		if id, ok := ctx.Value(connIDKey{}).(string); ok && id != "" {
			r.mu.Lock()
			delete(r.conns, id)
			r.mu.Unlock()
		}
	}
}

// TagRPC is required by the stats.Handler interface; this registry does not use it.
func (r *ConnRegistry) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC is required by the stats.Handler interface; this registry does not use it.
func (r *ConnRegistry) HandleRPC(_ context.Context, _ stats.RPCStats) {}

// EnrichConn updates the KeyID and CertCN fields on an existing connection entry.
// Called by the auth interceptor after successful authentication (D-12).
// The auth interceptor (Plan 02) must call registry.EnrichConn(connID, id, certCN)
// after successful auth -- this is wired in Plan 05 Task 1.
func (r *ConnRegistry) EnrichConn(connID string, keyID string, certCN string) {
	r.mu.Lock()
	if c, ok := r.conns[connID]; ok {
		c.KeyID = keyID
		c.CertCN = certCN
	}
	r.mu.Unlock()
}

// ConnIDFromContext extracts the connection UUID from context (set by TagConn).
// Exported so the auth interceptor can retrieve connID to call EnrichConn.
func ConnIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(connIDKey{}).(string)
	return id, ok
}

// List returns a point-in-time snapshot of all active connections.
func (r *ConnRegistry) List() []*ConnInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ConnInfo, 0, len(r.conns))
	for _, c := range r.conns {
		cp := *c // copy to avoid race on caller reading stale pointer
		out = append(out, &cp)
	}
	return out
}

// newUUID generates a 16-byte random hex string for use as a connection ID.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SplitHostPort splits a RemoteAddr string into host and port.
// Returns empty strings on parse failure. Exported for use by admin service.
func SplitHostPort(addr string) (host string, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		// Addr may not have a port (e.g., unix socket path)
		return strings.TrimSpace(addr), ""
	}
	return h, p
}
