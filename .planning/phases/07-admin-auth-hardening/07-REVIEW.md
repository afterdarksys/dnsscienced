---
phase: 07-admin-auth-hardening
reviewed: 2026-05-16T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - api/grpc/middleware/audit_test.go
  - api/grpc/middleware/middleware.go
  - api/grpc/registry/register.go
  - api/grpc/server/conn_registry_test.go
  - api/grpc/server/conn_registry.go
  - api/grpc/server/server_auth_test.go
  - api/grpc/server/server.go
  - cmd/dnsscience-grpc/main.go
  - cmd/dnsscienced/main_wiring_test.go
  - cmd/dnsscienced/main.go
  - internal/admin/service_conn_test.go
  - internal/admin/service.go
  - internal/config/config.go
  - internal/logging/logger.go
findings:
  critical: 5
  warning: 6
  info: 3
  total: 14
status: issues_found
---

# Phase 07: Code Review Report

**Reviewed:** 2026-05-16T00:00:00Z
**Depth:** standard
**Files Reviewed:** 14
**Status:** issues_found

## Summary

This phase implements admin gRPC auth hardening: mTLS + API key dual-auth, connection registry tracking, audit logging, and SIGHUP-based config reload. The core design (fail-closed guard, atomicKeySet, ConfigHolder) is sound. However, five critical defects were found — three security issues and two correctness issues — plus six warnings. The most severe issues are: the server starts without TLS credentials when only one of cert/key is set (D-01 bypass); nil-pointer panics in multiple service.go paths when `cache` is nil; and a file descriptor leak in the logger's SetQueryLogEnabled.

---

## Critical Issues

### CR-01: Server starts with no TLS when only one of TLSCertFile/TLSKeyFile is set

**File:** `api/grpc/server/server.go:215`
**Issue:** The guard condition uses `||` (OR) instead of `&&` (AND). If only one of `TLSCertFile` or `TLSKeyFile` is set, the condition is true, `buildCreds` is called (which rejects the partial config), and an error is returned. But if both are empty, the condition is false and the server starts without any transport-level TLS — only the API key interceptor runs. An attacker on the network can observe bearer tokens in plaintext. This directly violates D-01 and D-02: the comment above says "D-02: fail closed" but the code falls through to a plaintext listener when no cert files are provided. The test `TestNew_NoTLS` only checks `TLSClientCAs == ""` and does not exercise the zero-cert path.

```go
// CURRENT (line 215) — allows plain TCP when both fields empty:
if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {

// FIX — also reject startup when TLS cert is absent:
if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
    return nil, nil, nil, nil, fmt.Errorf(
        "admin server requires tls_cert_file and tls_key_file (D-02: fail closed)")
}
creds, err := buildCreds(cfg)
// ... always wire creds
```

### CR-02: Nil-pointer panic in FlushCache, GetCacheStats, PurgeCache, and helper flush functions when cache is nil

**File:** `internal/admin/service.go:296, 363, 382, 1065, 1082, 1099`
**Issue:** `NewService` accepts `cache *cache.ShardedCache` and it is explicitly passed as `nil` in `api/grpc/registry/register.go` (line 70: `srv.GetShardedCache()` — which may return nil when no cache is initialized). `FlushCache`, `GetCacheStats`, `PurgeCache`, and the three private `flush*` helpers all call `s.cache.Flush()`, `s.cache.GetStats()`, `s.cache.ForEach()`, `s.cache.Delete()` without a nil guard. Any of these RPCs issued against an admin server whose DNS server has no sharded cache will panic and crash the process.

```go
// FIX — add nil guard at the top of each affected method, e.g.:
func (s *Service) FlushCache(ctx context.Context, req *pb.AdminFlushCacheRequest) (*pb.AdminFlushCacheResponse, error) {
    if s.cache == nil {
        return nil, status.Error(codes.Unavailable, "cache not configured")
    }
    // ...
}
// Same pattern for GetCacheStats, PurgeCache, and the three private helpers.
```

### CR-03: Bearer token comparison leaks timing information — constant-time comparison not used

**File:** `api/grpc/server/server.go:97-100`
**Issue:** `atomicKeySet.Lookup` performs a plain map lookup (`idx.secretToID[secret]`). While map lookups are not guaranteed to be constant-time in Go and the Go runtime makes no constant-time promises here, the real issue is subtler: an attacker who controls the secret can distinguish "no such key at all" (fast rejection via map miss) from "key exists but wrong" (impossible in this design, which is good). The larger concern is that the secret itself is stored and compared as a plain string key in a map. **The secrets should be stored as their SHA-256 hash** and the incoming bearer token should also be hashed before lookup, so that if the key map were ever dumped (via a memory bug, core file, or debug endpoint) the raw secrets would not be exposed.

```go
// FIX — store hashed secrets:
import "crypto/sha256"
import "encoding/hex"

func hashSecret(s string) string {
    h := sha256.Sum256([]byte(s))
    return hex.EncodeToString(h[:])
}

// In Store():
idx.secretToID[hashSecret(k.Secret)] = k.ID

// In Lookup():
func (a *atomicKeySet) Lookup(secret string) (id string, ok bool) {
    idx := a.v.Load().(keyIndex)
    id, ok = idx.secretToID[hashSecret(secret)]
    return
}
```

### CR-04: File descriptor leak in SetQueryLogEnabled when re-enabling query logging

**File:** `internal/logging/logger.go:272-287`
**Issue:** `SetQueryLogEnabled(true)` calls `setupQueryLog()` (line 277) while `l.queryFile` may still be open from a prior enable/disable cycle (if `SetQueryLogEnabled(false)` was called between invocations the file handle is closed, but if the logger was initially created with `EnableQueryLog: true` then `l.queryFile` is already set when re-enable is called). More concretely: `setupQueryLog` opens a new file handle (line 163) and assigns it to `l.queryFile` without closing the previous one. Any call sequence of `Enable→Disable→Enable` leaks one fd per cycle.

```go
// FIX — close existing handle before re-opening in SetQueryLogEnabled:
if enabled && !l.config.EnableQueryLog {
    l.config.EnableQueryLog = true
    if l.queryFile != nil {          // close stale handle
        _ = l.queryFile.Close()
        l.queryFile = nil
    }
    return l.setupQueryLog()
}
```

### CR-05: ConnRegistry wiring is broken — nil is always passed, D-12 data never populated

**File:** `cmd/dnsscienced/main.go:255, 267`  
**File:** `api/grpc/registry/register.go:81`
**Issue:** `RegisterAll` is always called with `connRegistry: nil` (main.go line 255, register.go line 81). The returned `connReg` from `grpcserver.New()` is captured but immediately discarded with `_ = connReg` (main.go line 267). As a result, `admin.Service.connRegistry` is always nil in production. `ListConnections` silently returns an empty response. No connection metadata (RemoteAddr, KeyID, CertCN) is ever tracked. This is documented as "Plan 05 completes the live-registry wiring", but the code as submitted is structurally broken for the stated D-12 requirement and there is no mechanism at all to complete the wiring without a re-architecture: `RegisterAll` is called inside a closure captured before `connReg` exists, so even post-construction wiring is not possible without refactoring. The `ListConnections` test in `service_conn_test.go` passes because it directly constructs `Service` with a real registry — it does not test the production wiring path.

**Fix:** Pass the registry into `RegisterAll` after it is returned from `New()`, or restructure the closure to capture a pointer-to-pointer that is filled post-construction:

```go
// Option A: two-step wiring (simplest)
var connReg *grpcserver.ConnRegistry
grpcDeps := grpcserver.Deps{
    Register: func(s *grpc.Server) {
        registry.RegisterAll(s, &serverSrvAdapter{srv}, loadedCfg.ZonesDir, compileBin, connReg)
    },
    // ...
}
grpcSrv, grpcListener, connReg, configHolder, err = grpcserver.New(grpcCfg, grpcDeps)
// connReg is now set but Register was already called with nil.

// Option B (correct): deferred registration — call Register after New() returns:
var connReg *grpcserver.ConnRegistry
grpcDeps := grpcserver.Deps{
    Register: nil,  // skip inline registration
    // ...
}
grpcSrv, grpcListener, connReg, configHolder, err = grpcserver.New(grpcCfg, grpcDeps)
// Now register with live connReg:
registry.RegisterAll(grpcSrv, &serverSrvAdapter{srv}, loadedCfg.ZonesDir, compileBin, connReg)
```

---

## Warnings

### WR-01: extractBearer is case-sensitive — "bearer" or "BEARER" tokens rejected

**File:** `api/grpc/server/server.go:293-295`
**Issue:** `v[:len(prefix)] == prefix` performs a case-sensitive match against `"Bearer "`. RFC 6750 specifies that the auth-scheme token is case-insensitive. gRPC clients that send `"bearer <token>"` or `"BEARER <token>"` will be rejected with Unauthenticated even though their token is valid. This is a correctness issue for any non-Go client library.

```go
// FIX:
if strings.HasPrefix(strings.ToLower(v), "bearer ") {
    return v[len("bearer "):]
}
```

### WR-02: apiKeyStreamInterceptor does not store KeyID in context — audit log always shows "unknown"

**File:** `api/grpc/server/server.go:272-287`
**Issue:** `apiKeyUnaryInterceptor` stores the key ID in context via `context.WithValue(ctx, middleware.CtxKeyID{}, id)` (line 267). `apiKeyStreamInterceptor` does not (lines 272-287): it validates the token but discards `id` (line 282: `_, ok := keySet.Lookup(token)`). The streaming stream's context is never enriched with the key ID. `AuditStreamInterceptor` therefore always logs `caller: "unknown"` for streaming RPCs, defeating D-08 for the streaming path.

```go
// FIX in apiKeyStreamInterceptor — capture id and propagate:
id, ok := keySet.Lookup(token)
if !ok {
    return status.Error(codes.Unauthenticated, "invalid bearer token")
}
// Wrap the stream to inject context with key ID
wrappedStream := grpc_middleware.WrapServerStream(ss)
wrappedStream.WrappedContext = context.WithValue(ss.Context(), middleware.CtxKeyID{}, id)
return handler(srv, wrappedStream)
```

### WR-03: Reload in ConfigHolder can silently keep stale TLS creds when TLS paths change but cert/key are absent

**File:** `api/grpc/server/server.go:155`
**Issue:** `Reload()` only rebuilds TLS credentials when `tlsChanged && (newCfg.TLSCertFile != "" && newCfg.TLSKeyFile != "")`. If the operator sets `TLSClientCAs` to a new path but clears `TLSCertFile`/`TLSKeyFile` in the config, TLS changes are silently ignored and the server keeps the old credentials without returning an error. A SIGHUP that should have updated the CA bundle is dropped silently.

```go
// FIX — validate TLS fields are always present during reload:
if tlsChanged {
    if newCfg.TLSCertFile == "" || newCfg.TLSKeyFile == "" {
        return fmt.Errorf("reload: tls_cert_file and tls_key_file are required when tls paths change")
    }
    var err error
    newCreds, err = buildCreds(newCfg)
    if err != nil {
        return fmt.Errorf("reload: failed to build new TLS credentials: %w", err)
    }
}
```

### WR-04: zerolog.SetGlobalLevel called in setupSystemLog mutates global state — breaks concurrent tests

**File:** `internal/logging/logger.go:112`
**Issue:** `zerolog.SetGlobalLevel(level)` is a package-global mutation (zerolog uses a global atomic). When multiple `Logger` instances are created in tests (or in the same process with different configs), each `setupSystemLog` call overwrites the global log level used by all zerolog loggers, including test loggers. This is a latent race in test suites that create multiple loggers concurrently and will produce non-deterministic log suppression.

```go
// FIX — scope the level to the logger instance only:
l.systemLog = zerolog.New(writer).Level(level).With().Timestamp().Logger()
// Remove: zerolog.SetGlobalLevel(level)
```

### WR-05: FlushCache ALL case reports the cache size AFTER flush as EntriesFlushed

**File:** `internal/admin/service.go:296-302`
**Issue:** `s.cache.Flush()` is called first (line 296), then `s.cache.GetStats()` is called (line 297) to report how many entries were flushed. After a flush the size is 0 (or near-zero), so `EntriesFlushed` is always reported as 0. The correct approach is to get stats before flushing.

```go
// FIX:
stats := s.cache.GetStats()      // read BEFORE flush
flushed := uint64(stats.Size)
s.cache.Flush()
return &pb.AdminFlushCacheResponse{
    EntriesFlushed: flushed,
    Message:        "Entire cache flushed",
}, nil
```

### WR-06: dnsscience-grpc main.go missing TLSClientCAs in Config — mTLS is never enabled

**File:** `cmd/dnsscience-grpc/main.go:77`
**Issue:** The standalone gRPC binary builds its `server.Config` without setting `TLSClientCAs`:

```go
cfg := server.Config{ListenAddr: eListen, TLSCertFile: eCert, TLSKeyFile: eKey, APIKeys: eAPIKeys}
```

`TLSClientCAs` is always the zero value (`""`). The server startup call will fail with `"admin server requires tls_client_cas"` (CR-01 guard), meaning this binary is **completely non-functional** for any config that requires D-02 compliance. Additionally, there is no flag or config field to supply a CA bundle, so there is no way to make this binary work without a code change.

**Fix:** Add a `--tls-client-cas` flag and wire it into the `Config`:

```go
clientCAs := flag.String("tls-client-cas", "", "CA bundle for mTLS client verification")
// ...
cfg := server.Config{
    ListenAddr:   eListen,
    TLSCertFile:  eCert,
    TLSKeyFile:   eKey,
    APIKeys:      eAPIKeys,
    TLSClientCAs: *clientCAs,
}
```

---

## Info

### IN-01: main_wiring_test.go tests are compilation sentinels only — no behavioral assertions

**File:** `cmd/dnsscienced/main_wiring_test.go:13-28`
**Issue:** Both tests contain no assertions. `TestMainWiring_SIGHUPInSource` calls `strings.Contains("", "SIGHUP")` and discards the result, providing zero coverage. `TestMainWiring_ConfigHolderDeclared` only logs a message. These tests will never go red on a behavioral regression; they only fail if the package fails to compile.

**Fix:** Replace with integration tests that at minimum verify the SIGHUP signal handler fires and calls `configHolder.Reload`, or remove the dead test file and rely on compile-time checking alone.

### IN-02: audit_test.go TestAuditInterceptor_NoKeyLeak tests for a hardcoded secret that is never in the test

**File:** `api/grpc/middleware/audit_test.go:142`
**Issue:** The test checks `!strings.Contains(logOutput, "super-secret-token")` but `"super-secret-token"` never appears anywhere in the test — not in the context, not in the handler, not in any middleware. The assertion is trivially true and provides no real protection against secret leakage.

**Fix:** Set the context with a known secret value, pass the actual secret through a simulated auth step, then assert it does not appear in the log output.

### IN-03: Commented-out `// TODO` entries left in production code

**File:** `internal/admin/service.go:904-905`
**Issue:** Two TODO comments reference unimplemented features (EMA and histogram tracking for latency metrics):

```go
AvgLatencyMs: 0.0, // TODO: add EMA tracking in a future phase
P99LatencyMs: 0.0, // TODO: add histogram tracking in a future phase
```

These are shipped as zeros. Callers cannot distinguish "no data" from "truly 0 ms latency". Track with a GitHub issue and return a sentinel or omit the fields until implemented.

---

_Reviewed: 2026-05-16T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
