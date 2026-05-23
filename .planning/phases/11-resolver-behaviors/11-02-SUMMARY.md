---
phase: 11-resolver-behaviors
plan: 02
subsystem: resolver
tags: [dns, resolver, qname-minimization, nsec, nsec3, serve-stale, rfc9156, rfc8767, rfc8198]

# Dependency graph
requires:
  - phase: 11-resolver-behaviors
    plan: 01
    provides: "resolver.Config with QNAMEMinimization/AggressiveNSEC/ServeStale; serve-stale bug fixes; NSECCache with nsec3Record storage"
provides:
  - "QNAME minimization in resolveIterative(): currentZone tracking from root through delegation hops"
  - "engine.ApplyQNAMEMinimization() called per-hop; qtype=A at intermediate hops (RFC 9156)"
  - "NODATA fallback at intermediate minimized hop: re-query with full QNAME to same nameserver"
  - "currentZone updated from resp.Ns[0].Header().Name (zone owner, not NS target)"
  - "RFC 8767 stale TTL=0 rewrite in first cache.Get() path (bug fix: was only in stale fallback path)"
  - "internal/resolver/resolver_behaviors_test.go: 6 tests for serve-stale + QNAME minimization"
  - "internal/cache/nsec_test.go: 8 tests for NSEC synthesis, NSEC3 store/synthesize/guards/flush"
affects:
  - "Phase 12 AXFR: resolver package stable"
  - "Phase 13 DDNS: resolver package stable"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "QNAME minimization: currentZone state in resolveIterative() loop; engine.ApplyQNAMEMinimization per hop"
    - "Intermediate-hop NODATA recovery: re-query with full QNAME when minimized hop gets empty NOERROR + no NS"
    - "Delegation zone tracking: resp.Ns[0].Header().Name (owner = zone), not resp.Ns[0].(*dns.NS).Ns (nameserver)"
    - "Stale TTL=0 rewrite: applied in BOTH cache.Get() paths (initial lookup + stale fallback after upstream failure)"

key-files:
  created:
    - internal/resolver/resolver_behaviors_test.go
    - internal/cache/nsec_test.go
  modified:
    - internal/resolver/recursive.go

key-decisions:
  - "currentZone initialized to '.' (root); updated on each referral via resp.Ns[0].Header().Name"
  - "Intermediate qtype: dns.TypeA used at non-final hops per RFC 9156; original qtype used when sendName == qname"
  - "NODATA fallback pattern: single re-query to same nameserver; no re-try on failure (falls through to next NS)"
  - "RFC 8767 TTL=0 rewrite must apply in both cache paths — initial Get() for stale entries AND stale fallback after upstream failure"
  - "TestFindGlue pre-existing failure (IPv6 bracket formatting) is not a regression; documented in STATE.md since Plan 01"

patterns-established:
  - "QNAME minimization state machine: currentZone + sendName + sendType computed before each hop"
  - "Zone owner extraction: resp.Ns[0].Header().Name (not .(*dns.NS).Ns) for currentZone update"

requirements-completed: [RESOLVE-01, RESOLVE-02, RESOLVE-03]

# Metrics
duration: 15min
completed: 2026-05-23
---

# Phase 11 Plan 02: QNAME Minimization + Comprehensive Test Coverage Summary

**RFC 9156 QNAME minimization in resolveIterative() with currentZone tracking, qtype=A at intermediate hops, NODATA fallback, and 14 new tests covering serve-stale and NSEC/NSEC3 synthesis**

## Performance

- **Duration:** 15 min
- **Started:** 2026-05-23T03:51:00Z
- **Completed:** 2026-05-23T03:57:59Z
- **Tasks:** 2
- **Files modified:** 3 (recursive.go modified; resolver_behaviors_test.go + nsec_test.go created)

## Accomplishments

- Implemented RFC 9156 QNAME minimization in `resolveIterative()`: `currentZone := "."` tracking across delegation hops, minimized QNAME via `engine.ApplyQNAMEMinimization()`, `qtype=A` at intermediate hops, NODATA fallback with full-QNAME re-query, `currentZone` update from NS owner name on referral
- Fixed Rule 1 bug: first `cache.Get()` path in `Resolve()` did not rewrite TTL=0 for stale entries — RFC 8767 requires TTL=0 on ALL stale responses, not only the upstream-failure fallback path
- Wrote 6 resolver behavior tests (serve-stale: ExpiredEntry, TTLRewrittenToZero, BeyondMaxStaleTTL, Disabled; QNAME: ConfigFlag, DisabledByDefault) and 8 NSEC/NSEC3 tests (NSEC synthesis, no-match, NSEC3 store, NSEC3 synthesis, SkipNonSHA1, SkipOptOut, Flush NSEC3, Flush NSEC)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add QNAME minimization to resolveIterative()** - `33a9f11` (feat)
2. **Task 2: Add comprehensive tests + stale TTL=0 rewrite for first cache path** - `2bf44d4` (feat)

## Files Created/Modified

- `internal/resolver/recursive.go` - Added `"strings"` + `"engine"` imports; added `currentZone` tracking + QNAME minimization + NODATA fallback + zone update in `resolveIterative()`; added TTL=0 rewrite for stale entries in first `cache.Get()` path
- `internal/resolver/resolver_behaviors_test.go` (new) - 6 tests: TestServeStale_ExpiredEntry, TestServeStale_TTLRewrittenToZero, TestServeStale_BeyondMaxStaleTTL, TestServeStale_Disabled, TestQNAMEMinimization_ConfigFlag, TestQNAMEMinimization_DisabledByDefault
- `internal/cache/nsec_test.go` (new) - 8 tests: TestNSECCache_SynthesizeNXDOMAIN_NSEC, TestNSECCache_SynthesizeNXDOMAIN_NoMatch, TestNSECCache_Store_NSEC3, TestNSECCache_SynthesizeNXDOMAIN_NSEC3, TestNSECCache_Store_NSEC3_SkipNonSHA1, TestNSECCache_Store_NSEC3_SkipOptOut, TestNSECCache_Flush_NSEC3, TestNSECCache_Flush_NSEC

## Decisions Made

- `currentZone` initialized to `"."` (root zone) — matches RFC 9156 starting state
- `sendType = dns.TypeA` only when `sendName != qname` (intermediate hop); original qtype preserved for final hop
- NODATA fallback: single re-query to same nameserver with full QNAME; if that also fails, fall through to next nameserver rotation normally
- Use `resp.Ns[0].Header().Name` (zone owner name) for `currentZone` update — NOT `resp.Ns[0].(*dns.NS).Ns` (nameserver hostname) — this is the critical correctness distinction per RESEARCH.md anti-patterns

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Stale TTL=0 rewrite missing from initial cache.Get() path**
- **Found during:** Task 2 (TestServeStale_TTLRewrittenToZero failed: TTL=300, want 0)
- **Issue:** RFC 8767 requires TTL=0 for ALL stale responses. The serve-stale TTL rewrite was only applied in the second code path (stale fallback after upstream failure). The initial `cache.Get()` in `Resolve()` returns stale entries (when ServeStale=true and entry is within window) but did not zero out the TTL.
- **Fix:** Added `if entry.IsExpired()` block with TTL=0 rewrite for Answer/Ns/Extra (matching the pattern in the stale fallback path)
- **Files modified:** internal/resolver/recursive.go
- **Verification:** TestServeStale_TTLRewrittenToZero now passes (was FAIL, now PASS)
- **Committed in:** `2bf44d4` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug)
**Impact on plan:** Fix required for RFC 8767 correctness. All stale responses must carry TTL=0. No scope creep.

## Issues Encountered

- `TestFindGlue` pre-existing failure (IPv6 bracket formatting) — not introduced by this plan; documented in STATE.md since Plan 01. Only new tests are affected by this execution.

## Known Stubs

None.

## Threat Flags

None. Files created/modified match the threat model in the plan: QNAME minimization mitigations (T-11-05 qtype=A, T-11-06 MaxIterations bound) are both implemented as specified.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 11 complete: RESOLVE-01 (QNAME minimization), RESOLVE-02 (NSEC/NSEC3 synthesis), RESOLVE-03 (serve-stale) all delivered
- `go build ./...` passes; all new tests pass; only pre-existing TestFindGlue failure remains (documented, not a regression)
- Phase 12 (AXFR server) can begin; resolver package is stable

## Self-Check: PASSED

Files created:
- FOUND: /Users/ryan/development/dnsscienced/internal/resolver/resolver_behaviors_test.go
- FOUND: /Users/ryan/development/dnsscienced/internal/cache/nsec_test.go

Commits verified:
- FOUND: 33a9f11 (Task 1)
- FOUND: 2bf44d4 (Task 2)

---
*Phase: 11-resolver-behaviors*
*Completed: 2026-05-23*
