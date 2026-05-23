---
phase: 13-dynamic-dns-updates
plan: "01"
subsystem: dns
tags: [rfc2136, dynamic-dns, zone-mutation, go, sync]

# Dependency graph
requires:
  - phase: 12-axfr-server
    provides: Zone struct, ZoneConfig, TSIG auth patterns, SourceACL pattern
provides:
  - "Zone.DeleteRecord: exact-match RR removal with case-normalized owner"
  - "Zone.DeleteRRSet: bulk removal of all records of a type at an owner"
  - "Zone.DeleteName: removal of all rrsets at an owner"
  - "Zone.updateMu sync.Mutex for concurrent UPDATE serialization (D-06)"
  - "ZoneConfig.AllowUpdate []string for per-zone UPDATE ACL (D-15)"
  - "ZoneConfig.PersistUpdates *bool for write-back control (D-11)"
  - "11 passing tests in zone_mutation_test.go covering all three methods"
affects: [13-02-update-handler, 13-03-update-persistence]

# Tech tracking
tech-stack:
  added: ["sync (stdlib) added to zone.go imports"]
  patterns:
    - "Delete method no-op on miss: return nil when record/rrset/owner not found (RFC 2136 §3.4.2.5)"
    - "TDD RED/GREEN: test file committed before implementation, then implementation brings tests to green"
    - "Normalized copy for string comparison: dns.Copy(rr) with lowercased owner prevents false mismatches"

key-files:
  created:
    - internal/zone/zone_mutation_test.go
  modified:
    - internal/zone/zone.go
    - internal/config/config.go

key-decisions:
  - "DeleteRecord uses dns.Copy(rr) with normalized owner before String() comparison — avoids mutating caller's RR while ensuring case-insensitive match against stored lowercase owners"
  - "DeleteRecord/DeleteRRSet clean up empty maps (type map then owner map) to keep Records map compact — prevents unbounded growth from insert/delete cycles"
  - "updateMu is unexported (lowercase) — only the UPDATE handler (Plan 02) should serialize on it; zone methods do not lock themselves (called on clones)"
  - "AllowUpdate mirrors AllowTransfer exactly ([]string, omitempty) — consistent ACL pattern throughout config"
  - "PersistUpdates mirrors AllowAXFRFallback (*bool, omitempty) — pointer enables nil-detection for absent config"

patterns-established:
  - "Zone mutation methods: nil guard -> normalize owner -> lookup -> operate -> clean empty maps -> return nil on miss"
  - "Config fields for RFC 2136: AllowUpdate (CIDR list, empty=deny) + PersistUpdates (pointer-bool)"

requirements-completed:
  - DYNUP-01
  - DYNUP-03

# Metrics
duration: 3min
completed: 2026-05-23
---

# Phase 13 Plan 01: Zone Mutation Foundation Summary

**RFC 2136 zone mutation layer: three delete methods (DeleteRecord/DeleteRRSet/DeleteName), updateMu concurrency field, and AllowUpdate/PersistUpdates config fields — 11 tests all passing**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-05-23T15:34:29Z
- **Completed:** 2026-05-23T15:37:28Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added `updateMu sync.Mutex` to Zone struct for RFC 2136 concurrent UPDATE serialization (D-06)
- Implemented `DeleteRecord`, `DeleteRRSet`, `DeleteName` with RFC 2136 §3.4.2.5 no-op semantics
- 11 unit tests covering exact match, no-op, nil guard, case normalization, and cross-owner isolation
- Extended `ZoneConfig` with `AllowUpdate []string` and `PersistUpdates *bool` (D-15, D-11)

## Task Commits

Each task was committed atomically:

1. **TDD RED — zone_mutation_test.go** - `b19dfc3` (test)
2. **TDD GREEN — zone.go delete methods + updateMu** - `09a9192` (feat)
3. **Task 2: ZoneConfig AllowUpdate + PersistUpdates** - `b8a4968` (feat)

## Files Created/Modified
- `/Users/ryan/development/dnsscienced/internal/zone/zone_mutation_test.go` - 11 tests for all three delete methods; `mutationTestZone()` helper with SOA/NS/MX/A/AAAA/MX records
- `/Users/ryan/development/dnsscienced/internal/zone/zone.go` - `updateMu sync.Mutex` field added; `DeleteRecord`, `DeleteRRSet`, `DeleteName` methods; `"sync"` added to imports
- `/Users/ryan/development/dnsscienced/internal/config/config.go` - `AllowUpdate []string` and `PersistUpdates *bool` added to `ZoneConfig`

## Decisions Made
- `DeleteRecord` builds a normalized copy via `dns.Copy(rr)` with the lowercased owner before calling `.String()` for comparison. This is necessary because stored records have lowercase owners, but the caller may pass an RR with mixed-case owner (e.g., from an incoming UPDATE message). Without normalization, string comparison would fail silently and the method would incorrectly return no-op.
- Empty maps (type map, owner map) are deleted after the last RR is removed. This keeps `z.Records` compact for zones that receive many insert/delete cycles over time.
- `updateMu` is unexported — zone methods don't lock themselves since they operate on clones during UPDATE processing. The handler (Plan 02) acquires the mutex before applying mutations to the live zone.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] DeleteRecord case-normalization: dns.Copy before String() comparison**
- **Found during:** Task 1 (TDD GREEN) — `TestDeleteRecord_NormalizesOwner` failed on first run
- **Issue:** `rr.String()` includes owner name verbatim. Stored records have lowercase owners. When caller passes uppercase owner, the string comparison produced no match even though the record logically exists.
- **Fix:** Build normalized copy via `dns.Copy(rr)` with `normalized.Header().Name = owner` (already lowercased) before calling `.String()`. Does not mutate caller's RR.
- **Files modified:** `internal/zone/zone.go` (DeleteRecord implementation)
- **Verification:** `TestDeleteRecord_NormalizesOwner` passes; all 11 delete tests pass
- **Committed in:** `09a9192` (feat Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug — case normalization in string comparison)
**Impact on plan:** Required fix for correctness. No scope creep.

## Issues Encountered
None beyond the case-normalization bug above (caught and fixed during TDD GREEN iteration).

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Plan 02 (UPDATE handler) can call `zone.Clone()` then `clone.DeleteRecord/DeleteRRSet/DeleteName`, then acquire `z.updateMu` before swapping the live zone
- `ZoneConfig.AllowUpdate` is ready for SourceACL construction in Plan 02 (mirrors AllowTransfer/AXFR pattern)
- `ZoneConfig.PersistUpdates` is ready for Plan 03 persistence logic
- All existing tests continue to pass; `go build ./...` clean

## Self-Check: PASSED

All created files exist on disk. All task commits verified in git history. `updateMu sync.Mutex` present in zone.go (grep count: 1).

---
*Phase: 13-dynamic-dns-updates*
*Completed: 2026-05-23*
