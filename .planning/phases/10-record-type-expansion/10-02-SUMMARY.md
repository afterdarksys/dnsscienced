---
phase: 10-record-type-expansion
plan: "02"
subsystem: zone
tags: [dns, bind, parser, sshfp, naptr, smimea, loc, round-trip, wire-equality, dzc]

# Dependency graph
requires:
  - internal/zone/parser_dnszone.go (Plan 01 SSHFP/NAPTR/SMIMEA/LOC parse functions)
  - internal/zone/testdata/roundtrip_rrtype.dnszone (Plan 01 YAML fixture)
  - internal/zone/compiler.go (CompileZone, WriteCompiledZone)
  - internal/zone/loader.go (LoadCompiledZone)
provides:
  - BIND fixture with SSHFP, NAPTR, SMIMEA, LOC records (example.org.bind)
  - TestParseBIND_SSHFP, TestParseBIND_NAPTR, TestParseBIND_SMIMEA, TestParseBIND_LOC
  - TestRoundTrip_SSHFP, TestRoundTrip_NAPTR, TestRoundTrip_SMIMEA, TestRoundTrip_LOC
  - assertRoundTrip helper (wire byte equality via dns.PackRR + bytes.Equal)
  - doRoundTrip helper (parse -> compile -> write -> load cycle)
affects: [RRTYPE-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "doRoundTrip helper: single parse/compile/write/load cycle shared across four round-trip tests"
    - "assertRoundTrip helper: dns.PackRR both sides + bytes.Equal for wire byte comparison (D-10)"
    - "BIND parse tests follow TestParseBIND_ARecords pattern: parse fixture, GetRecords, check len >= 1"

key-files:
  created: []
  modified:
    - internal/zone/testdata/example.org.bind
    - internal/zone/parser_bind_test.go
    - internal/zone/parser_dnszone_test.go

key-decisions:
  - "doRoundTrip helper shared across four round-trip tests to avoid four separate parse/compile/load cycles"
  - "Round-trip tests pass immediately (GREEN without RED) because infrastructure was correctly built in Plan 01 — TDD note recorded"

patterns-established:
  - "Round-trip test pattern: ParseDNSZone -> CompileZone -> WriteCompiledZone(t.TempDir()) -> LoadCompiledZone -> assertRoundTrip"
  - "Wire equality via dns.PackRR + bytes.Equal is the canonical comparison method (D-10)"

requirements-completed: [RRTYPE-03, RRTYPE-04, RRTYPE-05, RRTYPE-06, RRTYPE-07]

# Metrics
duration: 8min
completed: 2026-05-21
---

# Phase 10 Plan 02: BIND Tests + DZC Round-Trip Wire Equality Summary

**BIND fixture extended with SSHFP/NAPTR/SMIMEA/LOC records, four BIND parse tests confirm miekg/dns native handling, four DZC round-trip wire equality tests confirm all new types survive compile-decompile (RRTYPE-07)**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-05-21T22:10:00Z
- **Completed:** 2026-05-21T22:18:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Extended `example.org.bind` BIND fixture with SSHFP (ECDSA SHA-256), NAPTR (SIP E2U), SMIMEA (DANE-EE SPKI SHA-256), and LOC (MIT campus area) records
- Added four BIND parse tests (`TestParseBIND_SSHFP`, `TestParseBIND_NAPTR`, `TestParseBIND_SMIMEA`, `TestParseBIND_LOC`) confirming miekg/dns handles all four types natively
- Added `assertRoundTrip` helper using `dns.PackRR` + `bytes.Equal` for wire byte equality (D-10)
- Added `doRoundTrip` helper performing the full parse -> compile -> write -> load cycle
- Added four round-trip tests (`TestRoundTrip_SSHFP`, `TestRoundTrip_NAPTR`, `TestRoundTrip_SMIMEA`, `TestRoundTrip_LOC`) — all pass with wire byte equality confirmed
- Full `internal/zone` test suite passes with zero regressions

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Failing BIND parse tests** - `95244a6` (test)
2. **Task 1 (GREEN): BIND fixture extension** - `6350607` (feat)
3. **Task 2: Round-trip wire equality tests** - `57e75f8` (test)

_TDD Task 1: RED commit confirmed all four tests fail before fixture extension._
_TDD Task 2: Tests pass immediately — Plan 01 infrastructure was fully correct (see TDD note below)._

## TDD Gate Compliance

### Task 1
- RED phase: `95244a6` — confirmed all four TestParseBIND_* tests fail before fixture extension
- GREEN phase: `6350607` — fixture extended, all four tests pass

### Task 2
Round-trip tests passed immediately on first run without a RED phase. The infrastructure (`CompileZone`, `WriteCompiledZone`, `LoadCompiledZone`, `roundtrip_rrtype.dnszone`) was built correctly in Plan 01. Per plan TDD rules, this is the "feature already exists" scenario — the tests are testing real, working functionality built in the prior wave. No RED phase is possible without artificially breaking working code. Tests pass because implementation is correct.

## Files Created/Modified

- `internal/zone/testdata/example.org.bind` — appended SSHFP, NAPTR, SMIMEA, LOC records at end
- `internal/zone/parser_bind_test.go` — added TestParseBIND_SSHFP, TestParseBIND_NAPTR, TestParseBIND_SMIMEA, TestParseBIND_LOC
- `internal/zone/parser_dnszone_test.go` — added assertRoundTrip helper, doRoundTrip helper, TestRoundTrip_SSHFP, TestRoundTrip_NAPTR, TestRoundTrip_SMIMEA, TestRoundTrip_LOC; added "bytes" and "path/filepath" imports

## Decisions Made

- `doRoundTrip` helper performs parse/compile/write/load once and all four round-trip tests call it — avoids redundant I/O and follows planner's preferred "single-load approach"
- Wire equality uses `dns.PackRR` + `bytes.Equal` per D-10 (not string comparison)

## Deviations from Plan

None - plan executed exactly as written. BIND fixture contains all four new record types, all four BIND parse tests pass, all four round-trip wire equality tests pass.

Pre-existing failures in `internal/dnssec`, `internal/engine`, and `internal/resolver` packages are out of scope — they are not caused by changes in this plan and existed before this execution.

## Deferred Issues (Out of Scope)

Pre-existing failures observed during full-project test run (`go test ./...`):
- `internal/dnssec/cache.go:102`: uint16-to-string conversion compile error
- `internal/engine` TestResolver_Resolve: test hits live DNS (gets real IPs vs mock expected values)
- `internal/resolver` TestFindGlue: returns slice format instead of scalar string

These were present before plan 02 execution and are not caused by zone package changes.

## User Setup Required

None.

## Next Phase Readiness

- RRTYPE-07 (round-trip wire equality) is now satisfied
- All four new record types have full coverage: YAML parse tests (Plan 01), BIND parse tests (Plan 02), DZC round-trip tests (Plan 02)
- No blockers for subsequent phases

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| internal/zone/testdata/example.org.bind contains SSHFP | FOUND |
| internal/zone/testdata/example.org.bind contains NAPTR | FOUND |
| internal/zone/testdata/example.org.bind contains SMIMEA | FOUND |
| internal/zone/testdata/example.org.bind contains LOC | FOUND |
| parser_bind_test.go contains TestParseBIND_SSHFP | FOUND |
| parser_bind_test.go contains TestParseBIND_NAPTR | FOUND |
| parser_bind_test.go contains TestParseBIND_SMIMEA | FOUND |
| parser_bind_test.go contains TestParseBIND_LOC | FOUND |
| parser_dnszone_test.go contains TestRoundTrip_SSHFP | FOUND |
| parser_dnszone_test.go contains TestRoundTrip_NAPTR | FOUND |
| parser_dnszone_test.go contains TestRoundTrip_SMIMEA | FOUND |
| parser_dnszone_test.go contains TestRoundTrip_LOC | FOUND |
| RED commit 95244a6 | FOUND |
| GREEN commit 6350607 | FOUND |
| Round-trip commit 57e75f8 | FOUND |
| go test ./internal/zone/... passes | PASS |

---
*Phase: 10-record-type-expansion*
*Completed: 2026-05-21*
