---
phase: 07
plan: "06"
subsystem: admin-auth-test-suite
tags: [grpc, tdd, mtls, api-keys, audit, conn-registry, security, d-01, d-04, d-07, d-08, d-09, d-11]
dependency_graph:
  requires: [07-01, 07-02, 07-03, 07-04, 07-05]
  provides: [Phase7-test-suite, AUTH-01-04-tests, AUDIT-01-test, CONN-01-test, RELOAD-01-02-tests]
  affects:
    - api/grpc/server/server_auth_test.go
    - api/grpc/middleware/audit_test.go
    - internal/logging/logger.go
tech_stack:
  added: [logging.NewWithWriter(io.Writer), crypto/ecdsa, crypto/x509 ephemeral test certs]
  patterns: [bytes-buffer-backed-zerolog, ephemeral-tls-cert-gen, tdd-stub-to-real-assertions]
key_files:
  created: []
  modified:
    - api/grpc/server/server_auth_test.go
    - api/grpc/middleware/audit_test.go
    - internal/logging/logger.go
decisions:
  - "logging.NewWithWriter added to logging package for test capture without file I/O"
  - "TestConnRegistry_RemoveOnEnd already existed in conn_registry_test.go (Plan 04); renamed to TestConnRegistry_TagAndRemoveWithAddr in server_auth_test.go to add RemoteAddr assertion without redeclaration"
  - "TDD cycle: production code already complete from Plans 01-05; test stubs (t.Skip) were the RED state; replacing with real assertions is the GREEN gate"
  - "TestMTLS_NoCert uses in-process gRPC server with ephemeral ecdsa certs + RequireAndVerifyClientCert; dialects without client cert return codes.Unavailable"
metrics:
  duration: "6m"
  completed: "2026-05-16"
  tasks_completed: 1
  files_changed: 3
requirements_satisfied:
  - ADMIN-AUTH-01
  - ADMIN-AUTH-02
  - ADMIN-AUTH-03
  - ADMIN-AUTH-04
  - ADMIN-AUDIT-01
  - ADMIN-CONN-01
  - ADMIN-RELOAD-01
---

# Phase 07 Plan 06: Phase 7 Auth + Audit + Connection Test Suite Summary

**One-liner:** Replaced 3 skip-stubs in server_auth_test.go with real assertions covering D-01 AND auth, D-04 named APIKey structs, D-07 audit fields (remote_addr+timestamp), D-08 named key id logging, ADMIN-AUTH-02 mTLS cert rejection, and CONN-01 registry; added logging.NewWithWriter for buffer-captured audit tests.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 (GREEN) | Replace stubs + add real test implementations; add NewWithWriter | bff3a80 | server_auth_test.go, audit_test.go, logger.go |

## What Was Built

### api/grpc/server/server_auth_test.go

**New tests replacing stubs:**
- `TestNew_MTLSButNoKeys`: verifies D-01 AND auth — TLSClientCAs set but no APIKeys returns error containing "API key"
- `TestMTLS_NoCert` (ADMIN-AUTH-02): generates ephemeral in-memory CA + server cert via `crypto/ecdsa`; starts real gRPC server with `RequireAndVerifyClientCert`; dials without client cert; asserts `isTransportOrTLSError` on the result
- `TestAPIKey_Valid` (D-08): calls `apiKeyUnaryInterceptor` with `config.APIKey{ID:"admin-key", Secret:"mysecret"}`; verifies `capturedCtx.Value(middleware.CtxKeyID{})` equals `"admin-key"` (named id, not hash, not secret)
- `TestAPIKey_Missing`: verifies Unauthenticated code returned when no Bearer header present

**Updated tests:**
- `TestAtomicKeyReload`: upgraded to use `require`/`assert` style; covers RELOAD-02
- `TestConfigHolder_ReloadValidation`: upgraded to use `require`/`assert` style; covers D-09/D-11 guard
- `TestConnRegistry_TagAndRemoveWithAddr`: new name (avoiding redeclaration vs conn_registry_test.go); verifies `RemoteAddr` field set to `"127.0.0.1:9000"` from `ConnTagInfo`

**Helper functions added:**
- `writePEM(t, path, blockType, der)` — writes PEM block to temp file
- `writeKeyPEM(t, path, key)` — marshals EC private key as PEM
- `isTransportOrTLSError(err)` — checks for TLS/transport failure strings

### api/grpc/middleware/audit_test.go

**Replaced weak TestAuditInterceptor** (which only checked function signature) with real implementation:
- Creates `logging.NewWithWriter(&buf)` — `bytes.Buffer`-backed logger
- Calls `AuditUnaryInterceptor(logger)` with real handler
- Asserts `buf.String()` contains `"remote_addr"`, `"timestamp"`, `"method"`, `"code"`, `"admin rpc"` as JSON keys (D-07, no conditional language)

**Replaced TestAuditInterceptor_NoKeyLeak** (which only tested `callerIdentity` directly) with buffer-capturing version:
- Sets `CtxKeyID{}` = `"admin-key"` in context
- Invokes interceptor and captures log output
- Asserts `"admin-key"` appears (D-08); asserts `"super-secret-token"` does NOT appear

### internal/logging/logger.go

**Added `NewWithWriter(w io.Writer) *Logger`:**
```go
func NewWithWriter(w io.Writer) *Logger {
    l := &Logger{}
    l.systemLog = zerolog.New(w).With().Timestamp().Logger()
    return l
}
```
Enables test-time log capture without file I/O overhead; avoids the `NewLogger(Config{})` path which requires valid log file paths.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TestConnRegistry_RemoveOnEnd redeclaration**
- **Found during:** Build of server package
- **Issue:** Plan's `server_auth_test.go` listed `TestConnRegistry_RemoveOnEnd` but Plan 04 already created it in `conn_registry_test.go` (both in `package server`)
- **Fix:** Renamed to `TestConnRegistry_TagAndRemoveWithAddr` in `server_auth_test.go`; this version adds `RemoteAddr` assertion (`"127.0.0.1:9000"`) which is more specific than the Plan 04 version
- **Files modified:** `api/grpc/server/server_auth_test.go`
- **Commit:** bff3a80

**2. [Rule 2 - Missing] `logging.NewWithWriter` did not exist**
- **Found during:** Writing `audit_test.go` — the plan notes "If `logging.NewWithWriter` does not exist, create the logger directly"
- **Issue:** `logging.Logger` has unexported `systemLog zerolog.Logger` — tests cannot construct it directly without a constructor; plan explicitly anticipated this
- **Fix:** Added `NewWithWriter(w io.Writer) *Logger` to `internal/logging/logger.go` — wraps `zerolog.New(w).With().Timestamp().Logger()` as the system log
- **Files modified:** `internal/logging/logger.go`
- **Commit:** bff3a80

## TDD Gate Compliance

This plan (`type: tdd`) operates in a special mode: the production code from Plans 01-05 was already complete. The Wave 0 stubs (`t.Skip()`) represented the RED state (tests existed but skipped/passed without asserting). Replacing them with real assertions that verify production behavior is the GREEN gate.

- RED gate: Wave 0 stubs (commit from Plan 00 phase, not this plan) — tests were SKIPped
- GREEN gate: commit `bff3a80` — all 7 requirements have concrete passing assertions

Per plan: "These tests are the machine-readable proof that the auth bypass is gone."

## Known Stubs

None — all requirement IDs now have concrete passing test assertions.

## Threat Surface Scan

No new network endpoints. Test files only.
- T-07-06-01 (MITIGATED): `TestAPIKey_Valid` calls `apiKeyUnaryInterceptor` with real `metadata.NewIncomingContext` (not mocked auth state)
- T-07-06-02 (ACCEPTED): `TestMTLS_NoCert` uses ephemeral ecdsa certs — P-256 keys, valid for 1 hour, only used for transport path testing

## Self-Check: PASSED

- `api/grpc/server/server_auth_test.go` contains `TestAPIKey_Valid`: confirmed
- `api/grpc/server/server_auth_test.go` contains `TestMTLS_NoCert`: confirmed
- `api/grpc/server/server_auth_test.go` contains `TestNew_MTLSButNoKeys`: confirmed
- `api/grpc/middleware/audit_test.go` contains `bytes.Buffer`: confirmed
- `api/grpc/middleware/audit_test.go` contains `remote_addr`: confirmed
- `internal/logging/logger.go` contains `NewWithWriter`: confirmed
- Commit bff3a80: confirmed in git log
- `go test ./api/grpc/server/... ./api/grpc/middleware/... ./internal/admin/...`: all PASS
- `go build ./...`: PASS
