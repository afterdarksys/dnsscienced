---
phase: 11-resolver-behaviors
plan: 01
subsystem: resolver
tags: [dns, resolver, cache, nsec, nsec3, serve-stale, rfc8767, rfc8198]

# Dependency graph
requires:
  - phase: 10-record-type-expansion
    provides: "completed prior phases; stable internal/cache and internal/resolver packages"
provides:
  - "resolver.Config with QNAMEMinimization, AggressiveNSEC, ServeStale, StaleTTL fields"
  - "D-10 all-off defaults: all three features enabled when none are explicitly set"
  - "D-11 wiring: resolver feature flags propagated into CacheConfig before cache construction"
  - "D-07 bug 1 fix: removed !entry.IsExpired() guard from Resolve() cache lookup"
  - "D-07/D-08 bug 2 fix: stale fallback with TTL=0 rewrite on upstream failure"
  - "NSECCache.nsec3records field + nsec3Record struct for NSEC3 storage"
  - "Store() NSEC3 loop with SHA1-only and opt-out guards"
  - "Flush() NSEC3 expiry eviction"
  - "SynthesizeNXDOMAIN() NSEC3 fallback via synthesizeFromNSEC3()"
  - "buildSyntheticNXDOMAIN_NSEC3() using dns.NSEC3.Cover()"
affects:
  - "11-02 QNAME minimization (reads QNAMEMinimization field)"
  - "11-03 NSEC3 synthesis integration tests (tests NSECCache NSEC3 path)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-10 all-false guard: detect zero-value Config and enable all features by default"
    - "D-11 wiring: resolver-level feature flags propagate into sub-package Config before construction"
    - "Stale cache fallback pattern: cache.Get() after resolveIterative() failure; TTL=0 rewrite before return"
    - "NSEC3 storage: split owner at second label boundary; uppercase hash comparisons; Cover() for synthesis"

key-files:
  created: []
  modified:
    - internal/resolver/recursive.go
    - internal/cache/nsec.go

key-decisions:
  - "D-07 bug 1: cache.Get() already handles stale logic — removing !entry.IsExpired() guard is correct"
  - "D-07/D-08 bug 2: stale fallback uses pool.GetMessage()+defer PutMessage(); staleResp.Copy() essential before defer reclaims"
  - "D-10: all-false guard detects unconfigured Config{}; all three features enabled to match Unbound/Knot defaults"
  - "D-11: StaleTTL defaults to 24h when ServeStale=true and StaleTTL=0; AggressiveNSEC wired into CacheConfig.AggressiveNSEC"
  - "NSEC3: Skip opt-out (Flags&0x01) and non-SHA1 algorithms; use dns.NSEC3.Cover() not hand-rolled range check"
  - "synthesizeFromNSEC3 called under mu.RLock already held by SynthesizeNXDOMAIN — no double-lock"

patterns-established:
  - "Feature flag wiring: resolver-level bool -> CacheConfig field before cache.NewShardedCache()"
  - "NSEC3 storage: nsec3records []*nsec3Record alongside records []*nsecRecord in NSECCache"

requirements-completed: [RESOLVE-03, RESOLVE-01]

# Metrics
duration: 15min
completed: 2026-05-22
---

# Phase 11 Plan 01: Config Extension + Serve-Stale Fixes + NSEC3 Storage Summary

**RFC 8767 serve-stale with TTL=0 rewrite, RFC 8198 NSEC3 synthesis foundation, and three-feature defaults wired into resolver.Config and CacheConfig**

## Performance

- **Duration:** 15 min
- **Started:** 2026-05-22T00:00:00Z
- **Completed:** 2026-05-22T00:15:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Extended resolver.Config with QNAMEMinimization, AggressiveNSEC, ServeStale, StaleTTL fields; all three default ON when none are explicitly configured (D-10)
- Fixed two serve-stale bugs: removed incorrect !entry.IsExpired() guard (D-07 bug 1); added stale fallback path with TTL=0 rewrite after upstream failure (D-07/D-08 bug 2)
- Extended NSECCache with nsec3Record struct, NSEC3 storage in Store(), NSEC3 expiry in Flush(), and NSEC3 synthesis via SynthesizeNXDOMAIN() -> synthesizeFromNSEC3() -> dns.NSEC3.Cover()

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend resolver.Config + fix serve-stale bugs in Resolve()** - `34a3502` (feat)
2. **Task 2: Extend NSECCache with NSEC3 storage, Store(), and Flush()** - `c046874` (feat)

## Files Created/Modified

- `internal/resolver/recursive.go` - Config extended with 4 fields; D-10 defaults + D-11 wiring in NewRecursive(); serve-stale bug fixes in Resolve()
- `internal/cache/nsec.go` - nsec3Record struct; nsec3records field on NSECCache; NSEC3 loop in Store(); NSEC3 flush; synthesizeFromNSEC3(); buildSyntheticNXDOMAIN_NSEC3()

## Decisions Made

- D-10 all-false guard: detect zero-value Config{} and enable all three features by default, matching Unbound/Knot Resolver defaults
- D-11 wiring: StaleTTL defaults to 24h when unset; AggressiveNSEC propagates to CacheConfig before cache construction
- staleResp.Copy() essential — pool.PutMessage() resets message on defer; pattern mirrors existing line 187
- NSEC3: skip opt-out (Flags&0x01) and non-SHA1; use dns.NSEC3.Cover() rather than hand-rolled hash range comparison
- synthesizeFromNSEC3() called with mu.RLock already held by caller (SynthesizeNXDOMAIN); no re-locking needed

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-existing test failure: TestFindGlue in internal/resolver (IPv6 bracket formatting) — documented in STATE.md, not introduced by this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 02 (QNAME minimization) can now read cfg.QNAMEMinimization from the Config
- Plan 03 (NSEC3 synthesis + integration tests) can test the synthesizeFromNSEC3() path
- All structural changes (config fields + serve-stale fixes + NSEC3 storage) are complete
- go build ./... passes; go test ./internal/cache/... passes; go test ./internal/resolver/... has only pre-existing TestFindGlue failure

---
*Phase: 11-resolver-behaviors*
*Completed: 2026-05-22*
