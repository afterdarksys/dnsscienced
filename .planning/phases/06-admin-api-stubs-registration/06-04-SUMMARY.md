---
phase: 06-admin-api-stubs-registration
plan: "04"
subsystem: api
tags: [grpc, admin, metrics, dns, go]

requires:
  - phase: 06-02
    provides: AdminSrvAdapter with GetAdminStats() wired into admin.Service; udpQueries/tcpQueries atomics in server.Server

provides:
  - GetMetrics RPC returns live QueriesTotal/QueriesUdp/QueriesTcp/UpstreamFailures from srv.GetAdminStats() plus CacheHits/CacheMisses from cache.GetStats()
  - ListConnections returns codes.Unimplemented (not silent empty list)
  - KillConnection returns codes.Unimplemented (not success=false)
  - Full Phase 6 build and test suite green

affects:
  - 07-admin-auth-hardening
  - phase-06-verification

tech-stack:
  added: []
  patterns:
    - "Nil-guard before dereferencing s.srv and s.cache in GetMetrics — satisfies T-06-14 DoS mitigation"
    - "codes.Unimplemented with descriptive message is the honest contract for unbuilt features (not silent success=false)"

key-files:
  created: []
  modified:
    - internal/admin/service.go

key-decisions:
  - "GetMetrics reads query counters from s.srv.GetAdminStats() and cache counters from s.cache.GetStats() with separate nil guards — srv and cache may be nil independently"
  - "ListConnections/KillConnection return codes.Unimplemented so callers can distinguish not-built from tried-and-failed"
  - "AvgLatencyMs and P99LatencyMs left at 0.0 — EMA/histogram tracking deferred to a future phase as documented in plan"

patterns-established:
  - "GetMetrics pattern: nil-guard srv, then nil-guard cache, assemble response struct — enables test stubs with either field nil"

requirements-completed:
  - ADMIN-METRICS-02
  - ADMIN-CONN-01

duration: 2min
completed: 2026-05-16
---

# Phase 6 Plan 04: Wire GetMetrics and Fix Connection Stubs Summary

**GetMetrics now returns live QueriesTotal/UDP/TCP/Errors from AdminSrvAdapter.GetAdminStats() plus cache hits/misses; ListConnections and KillConnection return codes.Unimplemented**

## Performance

- **Duration:** 2 min
- **Started:** 2026-05-16T14:12:25Z
- **Completed:** 2026-05-16T14:14:01Z
- **Tasks:** 2 (1 code change + 1 verification)
- **Files modified:** 1

## Accomplishments

- GetMetrics wired to live server stats via s.srv.GetAdminStats() returning Queries/UDPQueries/TCPQueries/Errors with nil guard
- Cache stats (CacheHits/CacheMisses) read from s.cache.GetStats() with separate nil guard (T-06-14 mitigated)
- ListConnections changed from silent empty list to codes.Unimplemented (honest contract)
- KillConnection changed from success=false stub to codes.Unimplemented (honest contract)
- Full build (go build ./...) passes; 44 firewalld regression tests pass; Phase 6 package tests pass under race detector

## Task Commits

1. **Task 1: Wire GetMetrics to live stats; ListConnections/KillConnection return Unimplemented** - `6d8d3c3` (feat)
2. **Task 2: Full build and test suite verification** - (no file changes — verification only)

## Files Created/Modified

- `/Users/ryan/development/dnsscienced/internal/admin/service.go` - GetMetrics rewritten to use s.srv.GetAdminStats(); ListConnections and KillConnection return codes.Unimplemented

## Decisions Made

- GetMetrics uses two separate nil guards (s.srv and s.cache) because either may be nil independently in test or standalone contexts
- AvgLatencyMs and P99LatencyMs remain 0.0 — EMA/histogram tracking is a future-phase concern explicitly noted in TODO comments
- codes.Unimplemented with a descriptive message ("connection tracking not yet implemented") is the correct gRPC convention for unbuilt features

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None — the pre-existing vet warning in internal/protective/engine.go (return copies lock value) is pre-Phase 6 and was not introduced or modified in this plan.

## Known Stubs

- GetMetrics: AvgLatencyMs = 0.0 and P99LatencyMs = 0.0 — intentional, documented with TODO comments, future phase will add EMA/histogram tracking
- ListConnections and KillConnection: codes.Unimplemented — intentional, connection tracking not yet built

## Threat Flags

None — no new security-relevant surfaces introduced. T-06-14 (nil-guard on GetMetrics) is satisfied by the implementation.

## Next Phase Readiness

- Phase 6 (admin-api-stubs-registration) is now complete: all 4 plans delivered
- internal/admin/service.go is fully implemented for Phase 6 scope
- Phase 7 (Admin Auth Hardening) can proceed: all admin RPCs are in their correct state
- pb.RegisterAdminServiceServer is wired in api/grpc/registry/register.go (confirmed: count=1)

---
*Phase: 06-admin-api-stubs-registration*
*Completed: 2026-05-16*
