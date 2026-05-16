# Phase 7: Admin Auth Hardening - Context

**Gathered:** 2026-05-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Lock down the gRPC admin API: fix the auth bypass when `api_keys` is empty, add mutual TLS (both client cert and API key required), add per-request structured audit logging, wire connection tracking for ListConnections/KillConnection, and enable SIGHUP-triggered full config reload for zero-downtime key rotation.

</domain>

<decisions>
## Implementation Decisions

### mTLS + API Key Auth
- **D-01:** Both mTLS and API key auth are **required simultaneously**. Client must present a valid cert AND a valid named API key. Cert proves machine identity; key proves operator intent.
- **D-02:** **Fail closed** — if `TLSClientCAs` is not configured, the server refuses to start. No accidental plain-TLS admin API in production.
- **D-03:** Remove the `len(set) > 0` bypass in `apiKeyUnaryInterceptor` and `apiKeyStreamInterceptor`. Empty key list = reject all, not allow all.

### Named API Keys (config schema change)
- **D-04:** API keys change from `api_keys: ["secret"]` (plain list) to `api_keys: [{id: "admin-key", secret: "..."}]` (named structs). The `id` field is used in audit logs instead of the secret. Human-readable, rotation-friendly.
- **D-05:** The `atomicKeySet` type should index by both secret (for fast auth lookup) and id (for audit log lookup by secret).

### Audit Logging
- **D-06:** Audit events go to the **existing `logging.Logger`** as structured JSON lines. No separate audit file. One log stream, ops knows where to look.
- **D-07:** Required audit fields per request: `key_id` (named key ID or cert CN if key-less future), `method` (full gRPC method name), `timestamp` (RFC3339), `result` (OK/UNAUTHENTICATED/etc.), `remote_addr`.
- **D-08:** Secret is **never** logged — only the `id` from the named key config.

### Key Reload / SIGHUP
- **D-09:** **SIGHUP triggers a full config reload** — not just API keys. Reloads keys, TLS cert paths, and any other config that changed.
- **D-10:** No `ReloadAPIKeys` RPC — SIGHUP is the sole reload mechanism. Simpler surface, auditable via OS process logs.
- **D-11:** Full config reload must be atomic — swap the new config under a lock/atomic, don't leave the server in a half-reloaded state. Connection draining is out of scope (existing connections continue on old TLS session; new connections get new config).

### Connection Tracking
- **D-12:** Connection identity = **remote IP + key ID + TLS cert CN**. All three fields required for rich `ListConnections` output and targeted `KillConnection`.
- **D-13:** **Live connections only** — registry holds only active connections. No retention of closed connections. No memory leak risk.
- **D-14:** `ConnRegistry` is a gRPC `StatsHandler` (implements `stats.Handler`) — this is the standard gRPC hook for connection lifecycle events.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing Auth Infrastructure
- `api/grpc/server/server.go` — Current server setup: `Config` struct, `apiKeyUnaryInterceptor`, `apiKeyStreamInterceptor`, `authorize()`. The bypass is `len(set) > 0` guard. TLS via `credentials.NewServerTLSFromFile`.
- `api/grpc/middleware/middleware.go` — Existing interceptor chain: `UnaryLoggingMetrics`, `StreamLoggingMetrics`. Audit interceptors slot in here.

### Config
- `internal/config/config.go` — Where `TLSClientCAs`, `TLSClientCertFile`, and the new named key struct need to be added.
- `cmd/dnsscienced/main.go` — SIGHUP signal handler wiring point; where `ConnRegistry` gets passed to the gRPC server.

### Logging
- `internal/logging/logger.go` — The logger that audit events write to (`SetQueryLogEnabled`, structured output patterns).

### gRPC Stats API
- `google.golang.org/grpc/stats` — `stats.Handler` interface for `ConnRegistry` (ConnBegin/ConnEnd hooks). No external doc needed — standard gRPC library.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `middleware.UnaryLoggingMetrics()` / `StreamLoggingMetrics()` — Pattern for new `AuditUnaryInterceptor` / `AuditStreamInterceptor`. Same structure, different payload.
- `middleware.genID()` — Already generates request IDs; audit interceptor can reuse for correlation.
- `server.authorize()` — Extend to return the matched key ID (not just bool) so audit interceptor can log it.

### Established Patterns
- gRPC interceptor chain via `grpc.ChainUnaryInterceptor` / `grpc.ChainStreamInterceptor` — audit interceptors join this chain.
- `credentials.NewServerTLSFromFile` → replace with `credentials.NewTLS(tlsCfg)` where `tlsCfg` sets `ClientCAs` and `ClientAuth: tls.RequireAndVerifyClientCert`.
- Auth bypass pattern: `len(set) > 0` check in both unary and stream interceptors — both must be fixed.

### Integration Points
- `server.Config` → add `TLSClientCAs string` field and change `APIKeys []string` → `APIKeys []APIKey` (named struct)
- SIGHUP handler in `main.go` → call config reload function that swaps atomic config reference
- `grpc.NewServer(opts...)` → add `grpc.StatsHandler(connRegistry)` option
- `admin.Service.ListConnections` / `KillConnection` → now have a real `ConnRegistry` to query (no longer `codes.Unimplemented`)

</code_context>

<specifics>
## Specific Ideas

- Named key config format: `{id: "admin-key", secret: "..."}` — planner should use this exact shape in the config struct
- SIGHUP reload: full config (not keys-only) — planner should scope reload to include TLS cert restat
- Connection tracking: IP + key ID + cert CN — all three in the `ConnEntry` struct

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 7-admin-auth-hardening*
*Context gathered: 2026-05-16*
