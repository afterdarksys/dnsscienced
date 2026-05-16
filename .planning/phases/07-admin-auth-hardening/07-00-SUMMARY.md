---
phase: 07-admin-auth-hardening
plan: "00"
subsystem: testing
tags: [go, grpc, test-stubs, tdd, admin-auth]

requires:
  - phase: 06-admin-api
    provides: admin service, gRPC middleware, server packages for stub test anchoring

provides:
  - 12 stub test functions across 3 packages (server, middleware, admin_test) that compile and skip
  - Test registration hooks enabling `go test -run TestFunctionName` in Plans 01-05

affects:
  - 07-01 through 07-06 (all plans verify against these stubs before and after implementation)

tech-stack:
  added: []
  patterns:
    - "Stub test pattern: t.Skip() stubs compiled in target package so go test -run finds them before implementation exists"
    - "White-box test placement: server_auth_test.go in package server (not server_test) for unexported access in Plan 06"
    - "External test package: service_conn_test.go in package admin_test to avoid import cycle with grpcserver"

key-files:
  created:
    - api/grpc/server/server_auth_test.go
    - api/grpc/middleware/audit_test.go
    - internal/admin/service_conn_test.go
  modified: []

key-decisions:
  - "server_auth_test.go placed in package server (white-box) to allow Plan 06 access to unexported types"
  - "service_conn_test.go placed in package admin_test (external) to avoid import cycle with grpcserver package"
  - "All stubs call t.Skip() immediately — Nyquist compliance requires stubs discoverable before assertions exist"

patterns-established:
  - "Stub-first TDD: create t.Skip() stubs in correct package; later plans replace bodies with real assertions"

requirements-completed:
  - ADMIN-AUTH-01
  - ADMIN-AUTH-02
  - ADMIN-AUTH-03
  - ADMIN-AUTH-04
  - ADMIN-AUDIT-01
  - ADMIN-CONN-01
  - ADMIN-RELOAD-01

duration: 8min
completed: 2026-05-16
---

# Phase 07 Plan 00: Test Skeleton Summary

**12 stub test functions across 3 packages (server, middleware, admin_test) compile and skip, enabling `go test -run` verification in Plans 01-06**

## Performance

- **Duration:** 8 min
- **Started:** 2026-05-16T18:00:00Z
- **Completed:** 2026-05-16T18:08:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `api/grpc/server/server_auth_test.go` with 9 stub functions (auth, key reload, conn registry) in package `server` for white-box access
- Created `api/grpc/middleware/audit_test.go` with 2 stub functions for audit interceptor tests in package `middleware`
- Created `internal/admin/service_conn_test.go` with 1 stub function in package `admin_test` (external package to avoid import cycle)
- All 12 stubs compile and skip cleanly; `go test ./api/grpc/...` and `go test ./internal/admin/...` exit 0

## Task Commits

Each task was committed atomically:

1. **Task 1: Create server_auth_test.go with all auth/reload/conn stubs** - `90ec234` (test)
2. **Task 2: Create audit_test.go and service_conn_test.go stubs** - `67cd2fe` (test)

**Plan metadata:** (docs commit below)

## Files Created/Modified

- `api/grpc/server/server_auth_test.go` - 9 stub test functions: TestNew_NoAuthMechanism, TestNew_NoTLS, TestAPIKey_Valid, TestAPIKey_Missing, TestMTLS_NoCert, TestAtomicKeySet, TestAtomicKeyReload, TestConfigHolder_ReloadValidation, TestConnRegistry_RemoveOnEnd
- `api/grpc/middleware/audit_test.go` - 2 stub test functions: TestAuditInterceptor, TestAuditInterceptor_NoKeyLeak
- `internal/admin/service_conn_test.go` - 1 stub test function: TestListConnections

## Decisions Made

- `server_auth_test.go` uses `package server` (white-box) so Plan 06 can access unexported fields without additional test helpers
- `service_conn_test.go` uses `package admin_test` (external) to avoid circular import since the admin service eventually imports grpcserver types

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. The `TestFindGlue` failure in `internal/resolver` appeared in `go test ./...` output but is a pre-existing failure documented in STATE.md — not introduced by this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 12 stub functions discoverable via `go test -run`; Plans 01-05 can reference them in their verify blocks
- Plan 01 can begin immediately: implement gRPC server auth (API key + mTLS TLS config) and replace TestNew_NoAuthMechanism / TestAPIKey_* / TestMTLS_NoCert with real assertions

---
*Phase: 07-admin-auth-hardening*
*Completed: 2026-05-16*
