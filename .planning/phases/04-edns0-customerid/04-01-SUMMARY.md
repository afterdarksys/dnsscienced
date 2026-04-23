---
phase: 04-edns0-customerid
plan: 01
subsystem: firewall
tags: [dns, edns0, go, zerolog, miekg-dns, threat-intel]

# Dependency graph
requires:
  - phase: 03-live-threat-feed
    provides: ThreatIntel with customer trust bonus already wired in Score() — CustomerID field consumed but never populated until this phase
provides:
  - EDNS0 option code 65000 extraction into QueryContext.CustomerID before any policy evaluation
  - extractCustomerID() package-private helper with 64-byte cap and RFC 6891 private-use constant
  - 7 new unit/integration tests covering all CUST-0x requirements
affects: [05-verdict-redirect, starlark-policy, threat-intel-scoring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "EDNS0 private-use option extraction: r.IsEdns0() → iterate opt.Option → type-assert *dns.EDNS0_LOCAL → compare local.Code != constant"
    - "Oversized payload guard: silent drop with single debug-level zerolog entry carrying len field"
    - "Extraction encapsulated in helper file (edns0.go) separate from Check() for independent testability"

key-files:
  created:
    - internal/firewalld/edns0.go
  modified:
    - internal/firewalld/firewalld.go
    - internal/firewalld/firewalld_test.go

key-decisions:
  - "D-01: EDNS0 option code 65000 (0xFDE8) — private-use range per RFC 6891 §6.1.3.1"
  - "D-02: Named constant edns0CustomerIDCode with RFC doc comment; edns0MaxCustomerIDLen=64"
  - "D-03: Extraction inside Firewall.Check() — server.go not modified; fully encapsulated in firewall package"
  - "D-04: qctx.CustomerID set immediately after struct literal, before any policy/junk/intel evaluation"
  - "D-05: Raw UTF-8 conversion — string(local.Data) with no escaping; malformed bytes cause no match, no crash"
  - "D-06: 64-byte hard cap — accommodates bare UUID (36 bytes) plus prefixed variants"
  - "D-07/D-08: Absent OPT or missing code 65000 → CustomerID stays empty string, silent"
  - "D-09: Oversized payload → CustomerID empty, one debug log with len field"
  - "Claude discretion: new edns0.go file (not inlined in firewalld.go) for testability"
  - "Integration tests adapted: SetCustomerTrust() absent — used CustomerMeta config map directly"

patterns-established:
  - "EDNS0 option iteration: same pattern as cookie extraction in server.go — r.IsEdns0() then range opt.Option"
  - "Test helper makeQueryWithCustomerID mirrors makeQuery — builds OPT record with EDNS0_LOCAL at code 65000"
  - "TDD RED commit: test(phase-plan): message; GREEN commit: feat(phase-plan): message"

requirements-completed: [CUST-01, CUST-02, CUST-03]

# Metrics
duration: 8min
completed: 2026-04-23
---

# Phase 4 Plan 01: EDNS0 CustomerID Extraction Summary

**EDNS0 option code 65000 extracted into QueryContext.CustomerID before firewall evaluation, with 64-byte cap, debug log on oversized, and 7 new tests (4 unit + 3 integration) all green**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-04-23T22:05:00Z
- **Completed:** 2026-04-23T22:13:28Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Created `internal/firewalld/edns0.go` with `edns0CustomerIDCode=65000` constant, `edns0MaxCustomerIDLen=64` constant, and `extractCustomerID()` helper implementing all D-01 through D-09 decisions
- Wired `qctx.CustomerID = extractCustomerID(r, fw.logger)` in `Firewall.Check()` immediately after qctx struct literal, before any static policy/junk/intel evaluation (CUST-02 compliance)
- Added 7 new tests: `TestExtractCustomerID` (4 subtests: present/no_opt/wrong_code/oversized), `TestFirewall_CustomerIDExtracted`, `TestFirewall_CustomerIDTrustBonus`, `TestFirewall_NoCustomerID_Allowed` — all pass
- Total firewalld test count: 31 (was 27 before this phase); `go build ./...` exits 0

## Task Commits

Each task was committed atomically:

1. **Task 1: Create edns0.go + all tests (RED phase)** - `9b1e660` (test)
2. **Task 2: Wire firewalld.go CustomerID extraction (GREEN phase)** - `d43eb8b` (feat)

**Plan metadata:** (docs commit follows)

_Note: TDD plan — test commit (RED) then feat commit (GREEN)_

## Files Created/Modified
- `internal/firewalld/edns0.go` — new file: `edns0CustomerIDCode` constant, `edns0MaxCustomerIDLen` constant, `extractCustomerID(r *dns.Msg, logger zerolog.Logger) string` helper
- `internal/firewalld/firewalld.go` — one-line insertion: `qctx.CustomerID = extractCustomerID(r, fw.logger)` after qctx struct literal, before `// 1. Static policy rules.`
- `internal/firewalld/firewalld_test.go` — added zerolog import, `makeQueryWithCustomerID` helper, and 7 test functions

## Decisions Made
- Used `edns0CustomerIDCode` as the constant name (Claude discretion, D-02 open question) — descriptive and grep-verifiable
- Created separate `edns0.go` file rather than inlining in `firewalld.go` (Claude discretion) — keeps Check() readable and helper independently testable
- Integration tests adapted from plan template: `defaultTestConfig()` and `SetCustomerTrust()` do not exist in the package; used inline `Config{}` struct literal with `CustomerMeta` map — same behavioral coverage, matches existing test style

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Adaptation] Integration test helpers adapted for actual API surface**
- **Found during:** Task 1 (test writing)
- **Issue:** Plan template used `defaultTestConfig()` and `fw.intel.SetCustomerTrust()` which do not exist in the package
- **Fix:** Used `Config{}` struct literal with `ThreatIntelConfig.CustomerMeta` map directly — equivalent behavioral coverage: `TestFirewall_CustomerIDExtracted` now verifies that trust bonus reduces score to VerdictAllow; `TestFirewall_CustomerIDTrustBonus` verifies blocked-without-ID vs allowed-with-ID via CustomerMeta config
- **Files modified:** internal/firewalld/firewalld_test.go
- **Verification:** All 7 new tests pass
- **Committed in:** 9b1e660 (Task 1 commit)

---

**Total deviations:** 1 auto-adapted (adaptation to actual API surface)
**Impact on plan:** No scope change. All 7 required tests implemented with equivalent coverage. CUST-01, CUST-02, CUST-03 fully satisfied.

## Issues Encountered
None — build and tests green on first attempt after API adaptation.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- CUST-01, CUST-02, CUST-03 delivered; `QueryContext.CustomerID` now populated at intake
- Starlark scripts can access `q["customer_id"]` (already wired in starlark.go `buildQueryValue()`)
- ThreatIntel customer trust bonus fully exercised (already wired in threat_intel.go Score())
- No blockers for Phase 5 (VerdictRedirect load balancing)
- Pre-existing test failures unchanged: internal/dnssec build error, internal/engine/TestResolver_Resolve (live DNS), internal/resolver/TestFindGlue (formatting)

## Self-Check: PASSED

- FOUND: internal/firewalld/edns0.go
- FOUND: internal/firewalld/firewalld.go (with qctx.CustomerID insertion at line 181)
- FOUND: internal/firewalld/firewalld_test.go (with 7 new tests)
- FOUND: .planning/phases/04-edns0-customerid/04-01-SUMMARY.md
- FOUND commit: 9b1e660 (test RED phase)
- FOUND commit: d43eb8b (feat GREEN phase)
- All 31 firewalld tests pass; go build ./... exits 0

---
*Phase: 04-edns0-customerid*
*Completed: 2026-04-23*
