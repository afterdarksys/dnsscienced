---
phase: 08-rfc9859-dsync
plan: "06"
subsystem: dsync
tags: [prometheus, grpc, dsync, rfc9859, metrics, observability]

requires:
  - phase: 08-rfc9859-dsync/01
    provides: DSYNCRecord codec, NotifyLimiter
  - phase: 08-rfc9859-dsync/02
    provides: Handler, DSYNCNotifier, sendNotify, AllowAllACL
  - phase: 08-rfc9859-dsync/03
    provides: server.go DSYNC integration, DSYNCConfig
  - phase: 08-rfc9859-dsync/05
    provides: SourceACL, WebhookClient, SetWebhook pattern

provides:
  - DSYNCMetrics struct with three prometheus.CounterVec counters (inbound/outbound/webhook)
  - Handler.SetMetrics() for post-construction metrics wiring
  - DSYNCNotifier.SetMetrics() for post-construction metrics wiring
  - server.go creates DSYNCMetrics and wires both handler and notifier
  - DSYNCAdminService gRPC service with SendDSYNCNotify RPC
  - Strict qtype validation (CDS/CSYNC only) and zone_name validation
  - Registry conditional registration of DSYNCAdminService when notifier present

affects: [grpc-admin, prometheus-scrape, dsync-observability]

tech-stack:
  added: [github.com/prometheus/client_golang/prometheus/testutil]
  patterns:
    - SetMetrics setter pattern for post-construction injection (mirrors SetWebhook)
    - Nil-safe counter guard pattern (if h.metrics != nil)
    - Fire-and-forget RPC pattern with counter increment deferred to worker
    - TDD RED/GREEN cycle for gRPC services

key-files:
  created:
    - internal/dsync/metrics.go
    - internal/dsync/metrics_test.go
    - api/grpc/services/dsync.go
    - api/grpc/services/dsync_test.go
  modified:
    - internal/dsync/handler.go
    - internal/dsync/sender.go
    - internal/server/server.go
    - api/grpc/proto/admin.proto
    - api/grpc/proto/pb/admin.pb.go
    - api/grpc/proto/pb/admin_grpc.pb.go
    - api/grpc/registry/register.go

key-decisions:
  - "OutboundSent counter incremented INSIDE worker after successful sendNotify, NOT at RPC enqueue site (D-10)"
  - "DSYNCMetrics nil-guarded everywhere — counters are optional, handlers remain functional without them"
  - "RegisterAll uses variadic dsyncNotifier parameter for backward-compatible registry extension"
  - "qtype validation is strict case-sensitive: only 'CDS' and 'CSYNC' accepted (T-08-20)"
  - "Both handler and notifier share the same *DSYNCMetrics instance for unified counter set"

patterns-established:
  - "Post-construction setter pattern: SetMetrics() mirrors SetWebhook() — NewHandler/NewDSYNCNotifier signatures remain stable"
  - "Nil-safe metric guard: if h.metrics != nil before every counter increment"
  - "TDD for gRPC services: test file first (RED), then service implementation (GREEN)"

requirements-completed: [DSYNC-07, DSYNC-08]

duration: 25min
completed: 2026-05-16
---

# Phase 08 Plan 06: DSYNC Prometheus Metrics + Admin RPC Summary

**Prometheus CounterVec metrics wired into DSYNC handler and notifier, plus SendDSYNCNotify Admin RPC with strict qtype validation registered on the gRPC admin server**

## Performance

- **Duration:** 25 min
- **Started:** 2026-05-16T20:40:00Z
- **Completed:** 2026-05-16T21:10:00Z
- **Tasks:** 3
- **Files modified:** 11

## Accomplishments

- Created `internal/dsync/metrics.go` with three prometheus.CounterVec counters (inbound/outbound/webhook) following project pattern exactly
- Wired metrics into Handler (accepted/refused_acl/refused_ratelimit) and DSYNCNotifier worker (sent/failed after sendNotify)
- Added SendDSYNCNotify Admin RPC via TDD: proto extension + code generation + strict CDS/CSYNC qtype validation + registry wiring

## Task Commits

Each task was committed atomically:

1. **Task 1: Create internal/dsync/metrics.go** - `b6bcc3b` (feat)
2. **Task 2: Wire DSYNCMetrics into Handler, Notifier, server.go + metrics_test.go** - `1d086bd` (feat)
3. **Task 3: SendDSYNCNotify RPC — RED gate** - `3a12f80` (test)
4. **Task 3: SendDSYNCNotify RPC — GREEN gate** - `cf7db7f` (feat)

**Plan metadata:** (pending docs commit)

_Note: Task 3 has two commits per TDD protocol (test RED then impl GREEN)_

## TDD Gate Compliance

- `test(08-06)` commit `3a12f80` — RED gate: tests fail to compile (NewDSYNCService undefined)
- `feat(08-06)` commit `cf7db7f` — GREEN gate: all 5 TestSendDSYNCNotify_* tests pass
- No REFACTOR commit needed (clean implementation on first pass)

## Files Created/Modified

- `internal/dsync/metrics.go` — DSYNCMetrics struct with 3 prometheus.CounterVec; NewDSYNCMetrics constructor with MustRegister
- `internal/dsync/metrics_test.go` — TestMetricsIncrement*, TestMetricsIncrement_ACLRefused, TestMetricsIncrement_RateLimitRefused
- `internal/dsync/handler.go` — Added metrics field, SetMetrics(), counter increments in HandleInbound and webhook goroutine
- `internal/dsync/sender.go` — Added metrics field, SetMetrics(), OutboundSent/OutboundFailed increments inside worker after sendNotify
- `internal/server/server.go` — Creates DSYNCMetrics and calls SetMetrics on dsyncHandler in DSYNC init block
- `api/grpc/proto/admin.proto` — DSYNCAdminService + SendDSYNCNotify/Request/Response messages appended
- `api/grpc/proto/pb/admin.pb.go` — Regenerated with new DSYNC message types
- `api/grpc/proto/pb/admin_grpc.pb.go` — Regenerated with RegisterDSYNCAdminServiceServer
- `api/grpc/services/dsync.go` — DSYNCService implementing DSYNCAdminServiceServer; fire-and-forget Notify delegation
- `api/grpc/services/dsync_test.go` — 5 test cases covering valid CDS, valid CSYNC, empty zone, invalid qtype, case sensitivity
- `api/grpc/registry/register.go` — RegisterAll extended with variadic dsyncNotifier; conditional RegisterDSYNCAdminServiceServer

## Decisions Made

- **OutboundSent placement:** Counter incremented INSIDE worker after sendNotify, NOT at RPC enqueue site. The RPC is fire-and-forget (D-10); incrementing at enqueue would be misleading since the notify may not be sent (queue full, no matching records, network error).
- **Nil-safe guards everywhere:** All counter calls wrapped in `if h.metrics != nil` so Handler and DSYNCNotifier remain functional when metrics are not wired (e.g., in tests that don't need counter verification).
- **Variadic registry extension:** `RegisterAll(..., dsyncNotifier ...*dsync.DSYNCNotifier)` keeps existing call sites backward-compatible; callers that don't pass a notifier skip registration.
- **Strict qtype case sensitivity:** "cds" and "csync" (lowercase) rejected with InvalidArgument per T-08-20.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed rate-limit test using wrong IP**
- **Found during:** Task 2 (metrics_test.go TestMetricsIncrement_RateLimitRefused)
- **Issue:** `blockedLimiter` drains the token bucket for IP `1.2.3.4`, but the test sent the NOTIFY from `192.0.2.1` — a different IP with a fresh token bucket, so rate limiting never fired
- **Fix:** Updated test to send from `1.2.3.4` (matching the IP blockedLimiter drained)
- **Files modified:** internal/dsync/metrics_test.go
- **Verification:** TestMetricsIncrement_RateLimitRefused passes; correct Rcode=REFUSED returned
- **Committed in:** `1d086bd` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug in test IP mismatch)
**Impact on plan:** Minor test fix, no production code change. All counters still verified correctly.

## Issues Encountered

- `go mod tidy` required after adding `prometheus/testutil` import in metrics_test.go — applied before running tests

## Known Stubs

None — all counter call sites are fully wired and operational.

## Threat Flags

No new threat surface introduced beyond the plan's threat model. DSYNCAdminService is gated by admin gRPC auth middleware (T-08-17 mitigated by Phase 7). Zone names exposed in counter labels are not secrets (T-08-21 accepted).

## Next Phase Readiness

- Phase 08 is complete: all 6 plans delivered (DSYNC-01 through DSYNC-08, DSYNC-09 zone test)
- Prometheus metrics observable at /metrics endpoint for DSYNC inbound/outbound/webhook events
- SendDSYNCNotify admin RPC available for triggering outbound DSYNC NOTIFY after CDS/CSYNC updates

---
*Phase: 08-rfc9859-dsync*
*Completed: 2026-05-16*

## Self-Check: PASSED

All created files exist. All task commits verified in git log.
- Files: metrics.go, metrics_test.go, dsync.go, dsync_test.go, SUMMARY.md — FOUND
- Commits: b6bcc3b, 1d086bd, 3a12f80, cf7db7f — FOUND
