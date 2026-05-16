---
phase: 07
plan: "02"
subsystem: admin-auth
tags: [grpc, mtls, tls13, api-keys, auth, security, interceptor]
dependency_graph:
  requires: [07-01]
  provides: [buildCreds, fail-closed-New, AND-auth-interceptors, middleware.CtxKeyID]
  affects: [api/grpc/server/server.go, api/grpc/middleware/middleware.go]
tech_stack:
  added: [crypto/tls, crypto/x509, os]
  patterns: [fail-closed-startup, AND-auth-policy, atomicKeySet-lookup, TLS13-minimum, mTLS-client-cert]
key_files:
  created: []
  modified:
    - api/grpc/server/server.go
    - api/grpc/middleware/middleware.go
    - api/grpc/server/server_auth_test.go
decisions:
  - "buildCreds() builds TLS creds with optional mTLS; RequireAndVerifyClientCert wired when TLSClientCAs is set"
  - "New() fails if TLSClientCAs empty (D-02 fail-closed) OR APIKeys empty (D-01 AND policy)"
  - "Interceptors ALWAYS require Bearer token — no OR skip when mTLS is active (D-01)"
  - "authorize() helper removed; replaced by atomicKeySet.Lookup(secret)->(id,ok)"
  - "extractBearer() parses authorization header correctly (no fmt.Sscanf token truncation)"
  - "middleware.CtxKeyID{} added to middleware package; injects key id into ctx for audit (D-08)"
metrics:
  duration: "3m"
  completed: "2026-05-16"
  tasks_completed: 2
  files_changed: 3
requirements_satisfied: [ADMIN-AUTH-01, ADMIN-AUTH-02, ADMIN-AUTH-03, ADMIN-AUTH-04]
---

# Phase 07 Plan 02: mTLS Credentials + AND Auth Interceptors Summary

**One-liner:** buildCreds() replaces NewServerTLSFromFile with mTLS-capable TLS13 credentials; New() fails closed if TLSClientCAs or APIKeys absent; interceptors enforce AND policy (cert + Bearer always required) per D-01.

## Tasks Completed

| # | Task | Commit | Result |
|---|------|--------|--------|
| RED | Failing tests for buildCreds and fail-closed New() guards | 463eb39 | FAIL (expected) |
| GREEN | buildCreds, fail-closed New(), AND interceptors, extractBearer | 6e75c0c | PASS |

## What Was Built

### api/grpc/server/server.go

**buildCreds(cfg Config) (credentials.TransportCredentials, error)**
- Requires TLSCertFile and TLSKeyFile; returns error if either is empty
- Loads cert via `tls.LoadX509KeyPair`; sets `MinVersion: tls.VersionTLS13`
- When `TLSClientCAs != ""`: reads CA PEM, builds `x509.CertPool`, sets `ClientCAs` + `ClientAuth=RequireAndVerifyClientCert`
- Returns `credentials.NewTLS(&tlsCfg)`

**New() fail-closed guards**
- Returns error when `cfg.TLSClientCAs == ""` (D-02: admin server requires CA bundle)
- Returns error when `len(cfg.APIKeys) == 0` (D-01: AND policy requires named keys)

**apiKeyUnaryInterceptor(keySet *atomicKeySet)**
- ALWAYS extracts Bearer token via `extractBearer(md)`
- Calls `keySet.Lookup(token)` returning `(id, ok)` — returns Unauthenticated if `!ok`
- Stores `id` in context via `middleware.CtxKeyID{}` for audit logging (D-08)
- No `if len(set) > 0` bypass — auth is unconditional

**apiKeyStreamInterceptor(keySet *atomicKeySet)**
- Same pattern as unary interceptor; `id` not stored (stream context injection deferred)

**extractBearer(md metadata.MD) string**
- Parses `Authorization: Bearer <token>` from gRPC metadata
- Replaces `fmt.Sscanf` in old `authorize()` (which would truncate tokens at spaces)

**authorize() function removed**
- Old `map[string]struct{}` set replaced by `atomicKeySet.Lookup()`

### api/grpc/middleware/middleware.go

**CtxKeyID type added**
```go
type CtxKeyID struct{}
```
- Exported context key for the authenticated API key ID per D-08
- Set by `apiKeyUnaryInterceptor` after successful auth
- Retrieved by audit interceptors via `ctx.Value(middleware.CtxKeyID{})`

### api/grpc/server/server_auth_test.go

New tests replacing stubs:
- `TestBuildCreds_MissingFiles`: error when cert files empty
- `TestBuildCreds_BadKeyPair`: error when cert files not found
- `TestBuildCreds_BadCAFile`: error when CA file not found
- `TestNew_NoAuthMechanism`: error with no auth at all
- `TestNew_NoTLS`: error when TLSClientCAs is empty (D-02)
- `TestNew_NoAPIKeys`: error when APIKeys is empty (D-01)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added CtxKeyID to middleware package**
- **Found during:** Task 2 implementation
- **Issue:** Plan required `middleware.CtxKeyID{}` in `apiKeyUnaryInterceptor`, but the type did not exist in `api/grpc/middleware/middleware.go`
- **Fix:** Added `type CtxKeyID struct{}` with documentation comment to middleware.go
- **Files modified:** `api/grpc/middleware/middleware.go`
- **Commit:** 6e75c0c

## Known Stubs

None — all stub tests in this plan's scope were either implemented or intentionally kept as stubs for later plans (TestAPIKey_Valid, TestAPIKey_Missing, TestMTLS_NoCert marked for Plan 06).

## Threat Surface Scan

No new network endpoints introduced. Changes address threats from plan's threat model:
- T-07-02-01 (MITIGATED): `if len(set) > 0` bypass removed; startup fails if APIKeys empty
- T-07-02-02 (MITIGATED): `tls.RequireAndVerifyClientCert` + CA pool active when TLSClientCAs set
- T-07-02-03 (MITIGATED): `MinVersion: tls.VersionTLS13` — TLS 1.2 and below rejected
- T-07-02-04 (MITIGATED): `New()` returns error if TLSClientCAs empty OR APIKeys empty

## Self-Check: PASSED

- `api/grpc/server/server.go` exists and contains `func buildCreds`: confirmed
- `api/grpc/server/server.go` does NOT contain `NewServerTLSFromFile`: confirmed
- `api/grpc/server/server.go` contains `RequireAndVerifyClientCert`: confirmed (1 match)
- `api/grpc/server/server.go` contains `VersionTLS13`: confirmed (1 match)
- `api/grpc/server/server.go` does NOT contain `func authorize`: confirmed
- `api/grpc/server/server.go` contains `keySet.Lookup`: confirmed (2 matches — unary + stream)
- `api/grpc/server/server.go` contains `tls_client_cas to be configured`: confirmed (1 match)
- `api/grpc/server/server.go` contains `at least one named API key`: confirmed (1 match)
- `api/grpc/middleware/middleware.go` contains `type CtxKeyID struct{}`: confirmed
- RED commit 463eb39: confirmed in git log
- GREEN commit 6e75c0c: confirmed in git log
- `go build ./...` passes: confirmed
- All 6 new tests PASS; 3 pre-existing tests (TestAtomicKeySet, TestAtomicKeyReload, TestConfig_HasTLSClientCAs) still PASS
