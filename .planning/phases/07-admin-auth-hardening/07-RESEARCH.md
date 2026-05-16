# Phase 7: Admin Auth Hardening - Research

**Researched:** 2026-05-16
**Domain:** Go gRPC security — mTLS, interceptor-based auth/audit, connection tracking, key rotation
**Confidence:** HIGH

---

## Summary

The admin gRPC server (`api/grpc/server/server.go`) has a single dangerous bypass: when
`APIKeys` is empty the auth interceptors skip validation entirely (line 67: `if len(set) > 0`).
This phase removes that bypass and adds defense-in-depth through mutual TLS, per-request audit
logging, live connection tracking, and hot-reload of API keys.

The codebase is already structured for this work. The gRPC `Config` struct lives in
`api/grpc/server/server.go`, the middleware pattern is in
`api/grpc/middleware/middleware.go`, and the admin service stubs for
`ListConnections`/`KillConnection` are in `internal/admin/service.go`. No new packages are
needed — all capabilities come from the standard library (`crypto/tls`, `crypto/x509`) plus
the existing gRPC modules already in `go.mod` (`google.golang.org/grpc v1.78.0`).

The key architectural decision is that mTLS and API keys serve different auth roles. When
mTLS is configured, the cert CN identifies the caller; the API key (if still configured) acts
as a secondary application-layer credential. The plan must handle the case where the operator
configures mTLS-only (no API keys): in that scenario the mandatory-key enforcement should
require at least one of the two mechanisms to be configured, not both.

**Primary recommendation:** Fix the bypass first (one-line change), then add mTLS and audit
logging as layered interceptors, then wire the connection registry as a `grpc.StatsHandler`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| API key enforcement | gRPC server (interceptor) | — | Auth must happen before any handler runs |
| mTLS credential config | gRPC server (TLS config) | — | Transport-layer auth is owned by the transport |
| Cert CN extraction | gRPC interceptor | — | CN is available from peer context in interceptor |
| Per-request audit log | gRPC interceptor (middleware) | — | Cross-cutting concern; fits existing middleware pattern |
| Connection registry | gRPC StatsHandler | admin.Service | StatsHandler owns lifecycle; Service queries it |
| ListConnections / KillConnection | admin.Service (RPC handler) | Connection registry | Service queries registry; kill closes the conn |
| Key hot-reload | grpc/server.Config (atomic) | SIGHUP handler in main | Config owner holds the live key set |

---

## Standard Stack

### Core (all already in go.mod — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `crypto/tls` | stdlib | `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert`, `ClientCAs` pool | Official Go TLS |
| `crypto/x509` | stdlib | Load CA cert pool, extract `Subject.CommonName` from peer cert | Official Go PKI |
| `google.golang.org/grpc/credentials` | v1.78.0 | `credentials.NewTLS(&tls.Config{...})`, `TLSInfo` for auth-info extraction | gRPC official |
| `google.golang.org/grpc/peer` | v1.78.0 | `peer.FromContext(ctx)` to get `*peer.Peer` carrying `AuthInfo` | gRPC official |
| `google.golang.org/grpc/stats` | v1.78.0 | `stats.Handler` interface for connection lifecycle hooks | gRPC official |
| `sync/atomic` | stdlib | `atomic.Value` for lock-free hot-swap of API key set | Preferred for read-heavy, write-rare config |

[VERIFIED: go.mod — all grpc packages are at v1.78.0]
[VERIFIED: stdlib packages — part of Go 1.26.2 on this machine]

### No New Dependencies Required

The phase requires zero new `go get` calls. Everything needed is already imported or in stdlib.

---

## Architecture Patterns

### System Architecture Diagram

```
Admin gRPC client
        |
        | (TLS handshake)
        v
[grpc.Creds(credentials.NewTLS(tlsCfg))]    ← mTLS enforced at transport layer
        |
        | (accepted connection)
        v
[StatsHandler.TagConn / HandleConn]          ← registers/deregisters in ConnectionRegistry
        |
        v
[ChainUnaryInterceptor]
   1. apiKeyInterceptor(atomicKeySet)         ← mandatory: reject if no keys AND no cert
   2. auditInterceptor(logger)               ← logs: caller ID, method, timestamp, result
   3. UnaryLoggingMetrics() (existing)       ← Prometheus metrics (already wired)
        |
        v
[AdminService handler]
   - ListConnections → ConnectionRegistry.List()
   - KillConnection  → ConnectionRegistry.Kill(id)
   - ReloadAPIKeys   → atomicKeySet.Store(newSet)
```

### Recommended File Structure (changes only)

```
api/grpc/server/
├── server.go            # Add mTLS config fields; swap atomic key set; fix bypass
├── conn_registry.go     # NEW: ConnectionRegistry + StatsHandler implementation
api/grpc/middleware/
├── middleware.go        # Add AuditUnaryInterceptor, AuditStreamInterceptor
internal/config/
├── config.go            # Add TLSClientCertFile, TLSClientCAs to AdminConfig
internal/admin/
├── service.go           # Wire ConnectionRegistry; implement ListConnections/KillConnection
cmd/dnsscienced/
├── main.go              # Pass TLS fields to grpcserver.Config; wire SIGHUP for key reload
```

### Pattern 1: mTLS Server Credentials

**What:** Build a `tls.Config` that requires client certificates verified against a CA pool.
**When to use:** When `TLSClientCAs` is set in config.

```go
// Source: credentials package (pkg.go.dev/google.golang.org/grpc/credentials) [VERIFIED: pkg.go.dev]
import (
    "crypto/tls"
    "crypto/x509"
    "os"
    "google.golang.org/grpc/credentials"
)

func buildServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
    tlsCfg := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }
    if clientCAFile != "" {
        caPEM, err := os.ReadFile(clientCAFile)
        if err != nil {
            return nil, err
        }
        pool := x509.NewCertPool()
        if !pool.AppendCertsFromPEM(caPEM) {
            return nil, fmt.Errorf("failed to parse client CA cert")
        }
        tlsCfg.ClientCAs = pool
        tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
    }
    return tlsCfg, nil
}

// Usage in New():
creds := credentials.NewTLS(tlsCfg)
opts = append(opts, grpc.Creds(creds))
```

[VERIFIED: credentials package docs at pkg.go.dev/google.golang.org/grpc/credentials]

### Pattern 2: Extract Cert CN in Interceptor

**What:** After mTLS handshake, client cert is available via `peer.FromContext` → `TLSInfo`.
**When to use:** In `auditInterceptor` to determine caller identity.

```go
// Source: peer package + credentials package [VERIFIED: pkg.go.dev]
import (
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/peer"
)

func callerIdentity(ctx context.Context) string {
    // Check API key identity first (set by key interceptor via context value)
    if kid, ok := ctx.Value(ctxKeyID{}).(string); ok && kid != "" {
        return "key:" + kid
    }
    // Fall back to cert CN
    p, ok := peer.FromContext(ctx)
    if !ok {
        return "unknown"
    }
    tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
    if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
        return "unknown"
    }
    return "cert:" + tlsInfo.State.PeerCertificates[0].Subject.CommonName
}
```

[VERIFIED: credentials.TLSInfo.State.PeerCertificates pattern — confirmed via pkg.go.dev/google.golang.org/grpc/credentials]

### Pattern 3: Audit Interceptor

**What:** Log caller identity, method name, timestamp, and gRPC status code after handler returns.
**When to use:** Chain immediately after auth interceptor, before business logic.

```go
// Source: middleware pattern (middleware.go in codebase) + grpc interceptor docs [VERIFIED: codebase grep]
func AuditUnaryInterceptor(logger *logging.Logger) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler) (interface{}, error) {
        start := time.Now()
        resp, err := handler(ctx, req)
        st := status.Convert(err)
        logger.Info().
            Str("caller", callerIdentity(ctx)).
            Str("method", info.FullMethod).
            Str("code", st.Code().String()).
            Dur("latency", time.Since(start)).
            Msg("admin rpc")
        return resp, err
    }
}
```

### Pattern 4: Atomic Key Set Hot-Reload

**What:** Hold the key set in an `atomic.Value`; swap it without restarting the server.
**When to use:** For `ReloadAPIKeys` RPC or SIGHUP handler.

```go
// Source: sync/atomic stdlib [ASSUMED — standard Go pattern for read-heavy configs]
type atomicKeySet struct {
    v atomic.Value // stores map[string]struct{}
}

func newAtomicKeySet(keys []string) *atomicKeySet {
    s := &atomicKeySet{}
    s.Store(keys)
    return s
}

func (a *atomicKeySet) Store(keys []string) {
    m := make(map[string]struct{}, len(keys))
    for _, k := range keys {
        m[k] = struct{}{}
    }
    a.v.Store(m)
}

func (a *atomicKeySet) Load() map[string]struct{} {
    return a.v.Load().(map[string]struct{})
}
```

The interceptor calls `keySet.Load()` on every request — a pointer load, essentially free.
`keySet.Store()` is called only on reload, replacing the pointer atomically.

### Pattern 5: Connection Registry via StatsHandler

**What:** Implement `stats.Handler` to register every incoming connection with a UUID.
**When to use:** Wire as `grpc.StatsHandler(registry)` in server options.

```go
// Source: stats package docs [VERIFIED: pkg.go.dev/google.golang.org/grpc/stats]
type ConnRegistry struct {
    mu    sync.RWMutex
    conns map[string]*ConnInfo  // id -> info
}

type connIDKey struct{}

func (r *ConnRegistry) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
    id := newUUID()
    r.mu.Lock()
    r.conns[id] = &ConnInfo{
        ID:          id,
        RemoteAddr:  info.RemoteAddr.String(),
        ConnectedAt: time.Now(),
    }
    r.mu.Unlock()
    return context.WithValue(ctx, connIDKey{}, id)
}

func (r *ConnRegistry) HandleConn(ctx context.Context, cs stats.ConnStats) {
    if _, ok := cs.(*stats.ConnEnd); ok {
        if id, ok := ctx.Value(connIDKey{}).(string); ok {
            r.mu.Lock()
            delete(r.conns, id)
            r.mu.Unlock()
        }
    }
}

// Required by interface but not used for this feature:
func (r *ConnRegistry) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }
func (r *ConnRegistry) HandleRPC(context.Context, stats.RPCStats) {}

// KillConnection — close the underlying net.Conn
// Note: gRPC does not expose a direct "close this connection" API from StatsHandler context.
// The practical approach is to store the context cancel or use grpc.Server.Stop per-connection.
// Simplest viable: store net.Conn in TagConn via ConnTagInfo.RemoteAddr, match and close.
// See "KillConnection Limitation" in pitfalls below.
```

### Pattern 6: Mandatory Auth Policy

The bypass is at `server.go:67`: `if len(set) > 0` — skip auth when key list is empty.

The fix depends on what mechanisms are configured:

| APIKeys configured | mTLS configured | Policy |
|-------------------|-----------------|--------|
| yes | yes | Require valid key AND valid cert |
| yes | no | **[SUPERSEDED by D-01 — AND policy applies; TLSClientCAs is mandatory per D-02]** |
| no | yes | **[SUPERSEDED by D-01 — AND policy applies; both mTLS AND API key always required]** |
| no | no | **REJECT at startup** — refuse to start with no auth |

The interceptor should be restructured to: check if auth is configured at all (fail fast if
not), then enforce whichever mechanisms are configured. Do not bypass silently.

```go
// Mandatory auth: fail at startup if no auth mechanism is configured
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, error) {
    if len(cfg.APIKeys) == 0 && cfg.TLSClientCAs == "" {
        return nil, nil, fmt.Errorf("admin server requires at least one auth mechanism: api_keys or tls_client_cas")
    }
    // ... rest of New()
}
```

### Anti-Patterns to Avoid

- **`credentials.NewServerTLSFromFile`** for mTLS: this helper only loads server cert/key; it
  cannot set `ClientCAs` or `ClientAuth`. Use `credentials.NewTLS(&tls.Config{...})` instead.
- **Checking cert after returning Unauthenticated**: always extract identity before calling handler.
- **Storing `net.Conn` by remote addr string**: remote addr is not guaranteed unique (NAT,
  port reuse). Use a UUID assigned in `TagConn`.
- **`sync.RWMutex` for key sets**: use `atomic.Value` — it avoids starvation when audit
  interceptors hold read locks concurrently.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TLS handshake + cert verification | custom TLS listener | `credentials.NewTLS` + stdlib `crypto/tls` | Dozens of edge cases: renegotiation, session tickets, CRL |
| Client cert chain validation | manual cert parsing | `tls.RequireAndVerifyClientCert` + `ClientCAs` pool | Handles intermediate CAs, expiry, revocation hooks |
| Connection tracking hooks | polling goroutine | `grpc.StatsHandler` | Only official supported hook into gRPC connection lifecycle |
| Key set swap | mutex-wrapped slice | `atomic.Value` | Lock-free; no reader starvation; idiomatic for read-heavy configs |
| Structured audit logging | `fmt.Printf` | `zerolog` (already used in codebase) | JSON output, fields, levels — `zerolog` is already imported |

---

## Common Pitfalls

### Pitfall 1: mTLS and `credentials.NewServerTLSFromFile`

**What goes wrong:** Developer uses `credentials.NewServerTLSFromFile` (which is what the
current code uses) and tries to add `ClientCAs` to it. This is not possible — the function
returns an opaque `credentials.TransportCredentials` with no way to set client auth fields.

**Why it happens:** The convenience helper is documented for server-only TLS, not mTLS.

**How to avoid:** When `TLSClientCAs` is configured, always build the `tls.Config` manually
and pass it to `credentials.NewTLS(&tlsCfg)`.

**Warning signs:** Clients connect without presenting certs and the server accepts them.

### Pitfall 2: Empty APIKeys Bypass (The Exact Bug to Fix)

**What goes wrong:** `server.go:67` — `if len(set) > 0` — means that when `api_keys: []`
in config, ALL requests are accepted without authentication. This is the primary security
defect this phase must close.

**Why it happens:** The original implementation treated "no keys configured" as "auth
disabled" rather than "auth misconfigured."

**How to avoid:** Change the guard to require at least one auth mechanism to be active. If
neither keys nor mTLS client CAs are configured, the server must refuse to start.

### Pitfall 3: Peer Info Not Available Without TLS

**What goes wrong:** `peer.FromContext(ctx)` returns `ok=true` but `p.AuthInfo` is nil when
the connection is not TLS-authenticated. Code that assumes `AuthInfo.(credentials.TLSInfo)`
will panic.

**Why it happens:** Developers assume mTLS = always present. In dev/test environments the
server may run without TLS creds.

**How to avoid:** Always nil-check `AuthInfo` and the `PeerCertificates` slice before
indexing. Degrade gracefully (log "no cert" rather than panic).

### Pitfall 4: KillConnection Limitation in gRPC

**What goes wrong:** gRPC does not expose a first-class "close this connection" API from
the server side. There is no `grpc.Server.CloseConn(id)`.

**Why it happens:** gRPC transports own connection lifetime; they don't expose handle-level
teardown in the public API.

**Practical mitigation:** The `ConnTagInfo` struct passed to `TagConn` includes `RemoteAddr`
(`net.Addr`). To kill a connection you must either:
  (a) wrap the `net.Listener` to intercept `Accept()` and track `net.Conn` by ID, then
      call `conn.Close()` directly, OR
  (b) accept that `KillConnection` returns success=false with message "connection teardown
      not yet supported" and mark this as a follow-on task.

Option (b) is the lowest-risk choice for this phase. The stub already returns false; the
registry integration + ListConnections is the meaningful deliverable.

[VERIFIED: gRPC Go docs — no public CloseConn API exists as of v1.78.0]

### Pitfall 5: SIGHUP Handler Race

**What goes wrong:** The SIGHUP handler in `main.go` reads the config file and calls
`atomicKeySet.Store(...)`. If it fires while the server is starting up (before the key set
pointer is stored), or if two SIGHUPs fire in rapid succession, the reload can be lost or
result in a partial load.

**Why it happens:** Signal handlers run in a goroutine; no ordering guarantee with startup.

**How to avoid:** Initialize the `atomicKeySet` before `grpcserver.New()` is called. Use a
debounce channel or mutex around the reload function. Only reload keys after a successful
config parse (don't apply partial configs).

---

## Code Examples

### Full mTLS Server Config in `server.go`

```go
// Source: credentials package docs + stdlib tls.Config [VERIFIED: pkg.go.dev]
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
            return nil, fmt.Errorf("client CA: %w", err)
        }
        pool := x509.NewCertPool()
        if !pool.AppendCertsFromPEM(caPEM) {
            return nil, fmt.Errorf("no valid CA certs in %s", cfg.TLSClientCAs)
        }
        tlsCfg.ClientCAs = pool
        tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
    }
    return credentials.NewTLS(tlsCfg), nil
}
```

### Updated Config Struct

```go
// In api/grpc/server/server.go
type Config struct {
    ListenAddr      string   // e.g. ":8443"
    TLSCertFile     string
    TLSKeyFile      string
    TLSClientCAs    string   // path to PEM CA bundle for mTLS client verification
    APIKeys         []string // static API keys; empty list + no mTLS → startup error
}

// In internal/config/config.go AdminConfig
type AdminConfig struct {
    Enabled         bool     `yaml:"enabled"`
    Listen          string   `yaml:"listen"`
    APIKeys         []string `yaml:"api_keys"`
    TLSCertFile     string   `yaml:"tls_cert_file"`
    TLSKeyFile      string   `yaml:"tls_key_file"`
    TLSClientCAs    string   `yaml:"tls_client_cas"`
}
```

### Wiring in main.go

```go
// Source: existing main.go pattern [VERIFIED: codebase read]
grpcCfg := grpcserver.Config{
    ListenAddr:   loadedCfg.Admin.Listen,
    APIKeys:      loadedCfg.Admin.APIKeys,
    TLSCertFile:  loadedCfg.Admin.TLSCertFile,
    TLSKeyFile:   loadedCfg.Admin.TLSKeyFile,
    TLSClientCAs: loadedCfg.Admin.TLSClientCAs,
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `credentials.NewServerTLSFromFile` (server-only TLS) | `credentials.NewTLS(&tls.Config{ClientAuth: RequireAndVerifyClientCert})` | This phase | Enables mTLS |
| Empty key list = bypass | Empty key list = startup error unless mTLS configured | This phase | Removes auth bypass |
| No audit log | Structured zerolog entry per RPC | This phase | Operator visibility |
| `ListConnections` always returns empty | `StatsHandler` registry feeds real data | This phase | Meaningful connection management |

**Deprecated in this codebase after this phase:**
- The `if len(set) > 0` bypass pattern — must be removed, never reverted

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `atomic.Value` is preferred over `sync.RWMutex` for the key set hot-swap | Pattern 4 | Low — either works; atomic.Value has no practical downside here |
| A2 | KillConnection via direct `net.Conn.Close()` requires a wrapped listener | Pitfall 4 | Medium — if gRPC exposes a new API in v1.78 this is unnecessary complexity |
| A3 | `zerolog` is the project's structured logger (imported in `internal/admin/service.go`) | Code Examples | Low — confirmed by import of `internal/logging` package which wraps zerolog |

---

## Open Questions (RESOLVED)

1. **Is API key auth still required when mTLS is configured?** (RESOLVED — D-01)
   - Resolution: YES. D-01 mandates "Both mTLS and API key auth are required simultaneously.
     Client must present a valid cert AND a valid named API key. Cert proves machine identity;
     key proves operator intent." This is AND logic, not OR.

2. **ReloadAPIKeys: dedicated RPC or SIGHUP only?** (RESOLVED — D-10)
   - Resolution: SIGHUP only. D-10 states "No ReloadAPIKeys RPC — SIGHUP is the sole reload
     mechanism. Simpler surface, auditable via OS process logs."

3. **Key identity for audit log: hash or prefix?** (RESOLVED — D-04/D-08)
   - Resolution: Named key ID. D-04 introduces named key structs {id, secret}. D-08 mandates
     "Secret is never logged — only the id from the named key config." No hash needed;
     the configured human-readable id is logged directly.
---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Compile + test | yes | 1.26.2 | — |
| grpcurl | Manual testing of auth enforcement | yes | found at /usr/local/bin/grpcurl | — |
| openssl | Generating mTLS test certificates | [ASSUMED: typical macOS dev machine] | — | `go run` cert gen script |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go testing (stdlib) + testify |
| Config file | none — standard `go test ./...` |
| Quick run command | `go test ./api/grpc/server/... ./api/grpc/middleware/... -v -run TestAuth` |
| Full suite command | `go test ./... -timeout 60s` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AUTH-01 | Empty api_keys + no mTLS → New() returns error | unit | `go test ./api/grpc/server/... -run TestNew_NoAuthMechanism` | No — Wave 0 |
| AUTH-02 | Empty api_keys + mTLS configured → requests accepted via cert | unit | `go test ./api/grpc/server/... -run TestMTLS_NoBearerRequired` | No — Wave 0 |
| AUTH-03 | Valid Bearer token → authorized | unit | `go test ./api/grpc/server/... -run TestAPIKey_Valid` | No — Wave 0 |
| AUTH-04 | No Bearer token, keys configured → Unauthenticated | unit | `go test ./api/grpc/server/... -run TestAPIKey_Missing` | No — Wave 0 |
| AUDIT-01 | Each RPC produces a structured log entry with caller/method/code | unit | `go test ./api/grpc/middleware/... -run TestAuditInterceptor` | No — Wave 0 |
| CONN-01 | ListConnections returns active connection count > 0 | integration | `go test ./internal/admin/... -run TestListConnections` | No — Wave 0 |
| RELOAD-01 | SIGHUP causes new key set to be loaded atomically | unit | `go test ./api/grpc/server/... -run TestAtomicKeyReload` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./api/grpc/server/... ./api/grpc/middleware/... -timeout 30s`
- **Per wave merge:** `go test ./... -timeout 60s`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `api/grpc/server/server_auth_test.go` — covers AUTH-01 through AUTH-04, RELOAD-01
- [ ] `api/grpc/middleware/audit_test.go` — covers AUDIT-01
- [ ] `internal/admin/service_conn_test.go` — covers CONN-01

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | API key (Bearer) + mTLS client cert |
| V3 Session Management | no | gRPC is stateless per-RPC; no session tokens |
| V4 Access Control | yes | All admin RPCs require auth; no bypass |
| V5 Input Validation | yes | CA cert path validation in config load |
| V6 Cryptography | yes | `crypto/tls` stdlib — TLS 1.3 minimum; never hand-roll |

### Known Threat Patterns for gRPC Admin Server

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unauthenticated access via empty key list | Spoofing | Remove `if len(set) > 0` bypass; startup error if no auth |
| Credential stuffing against API key endpoint | Spoofing | mTLS as second factor; audit log monitors failed attempts |
| Man-in-the-middle (server cert not verified by client) | Tampering | Client must verify server cert; enforce TLS 1.3+ |
| Audit log forging via crafted metadata | Tampering | Extract identity from TLS AuthInfo (not from metadata) |
| Connection exhaustion / resource starvation | Denial of Service | Connection registry provides visibility; KillConnection for cleanup |
| Key leakage via audit log | Information Disclosure | Log key hash (sha256[:8]), never the raw key |

---

## Sources

### Primary (HIGH confidence)

- `pkg.go.dev/google.golang.org/grpc/credentials` — `TLSInfo`, `NewTLS`, `NewServerTLSFromFile`
- `pkg.go.dev/google.golang.org/grpc/peer` — `FromContext`, `Peer.AuthInfo`
- `pkg.go.dev/google.golang.org/grpc/stats` — `Handler` interface, `ConnTagInfo`, `ConnBegin`, `ConnEnd`
- Codebase read: `api/grpc/server/server.go`, `api/grpc/middleware/middleware.go`,
  `internal/admin/service.go`, `internal/config/config.go`, `cmd/dnsscienced/main.go`
- `go.mod` — confirmed grpc v1.78.0, no new dependencies needed

### Secondary (MEDIUM confidence)

- Context7 `/grpc/grpc-go` — mTLS configuration examples, interceptor patterns
- grpc-go GitHub `examples/features/encryption/README.md` — mTLS usage examples
- grpc-go GitHub `examples/features/stats_monitoring/` — StatsHandler patterns

### Tertiary (LOW confidence, marked)

- A1, A2, A3 in Assumptions Log — verified by reasoning from codebase + docs, but not from
  an authoritative spec

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages already in go.mod; docs verified via pkg.go.dev
- Architecture: HIGH — codebase fully read; change surface is small and well-bounded
- Pitfalls: HIGH — bypass bug directly observed at server.go:67; KillConnection limit
  verified against gRPC docs
- Test map: MEDIUM — requirement IDs are inferred from phase description (no REQUIREMENTS.md)

**Research date:** 2026-05-16
**Valid until:** 2026-06-16 (gRPC Go API is stable; crypto/tls is stdlib)
