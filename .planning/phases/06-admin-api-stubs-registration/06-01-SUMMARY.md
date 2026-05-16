---
phase: 06-admin-api-stubs-registration
plan: 01
subsystem: api
tags: [go, logging, rrl, server, atomic, sync, mutex]

# Dependency graph
requires: []
provides:
  - "Logger.SetQueryLogEnabled/IsQueryLogEnabled/QueryLogConfig/QueriesLogged methods"
  - "Logger.LogQuery race-fixed (holds mu for full body)"
  - "rrl.Limiter.GetConfig/UpdateConfig with cfgMu sync.RWMutex"
  - "server.Server udpQueries/tcpQueries atomics + Stats.UDPQueries/TCPQueries"
affects:
  - "06-02 (admin logging RPC)"
  - "06-03 (admin RRL RPC)"
  - "06-04 (admin metrics RPC)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "cfg snapshot pattern: take RLock, copy value, RUnlock, use local copy — avoids lock contention in hot path"
    - "TDD: test(RED) commit → feat(GREEN) commit per task"

key-files:
  created:
    - internal/logging/logger_test.go
    - internal/rrl/limiter_admin_test.go
    - internal/server/server_transport_test.go
  modified:
    - internal/logging/logger.go
    - internal/rrl/limiter.go
    - internal/server/server.go

key-decisions:
  - "cfg snapshot in rrl.Check(): take RLock, copy l.cfg to local var, RUnlock — single-lock overhead vs. per-field locking; simpler, race-free, matches plan spec"
  - "Refactored isExempt/getLimitForCategory/bucketHash/getPrefix from Limiter methods to package-level functions accepting Config snapshot — avoids re-acquiring lock in sub-calls"
  - "LogQuery holds l.mu for entire body (not just the EnableQueryLog check) — fixes data race with SetQueryLogEnabled (T-06-01 mitigation)"
  - "udpQueries/tcpQueries discrimination in handleDNS uses separate type-assert block before clientIP extraction — does not alter existing clientIP logic"

patterns-established:
  - "cfg snapshot pattern: take RLock, copy value, RUnlock, use local copy in hot query path"
  - "atomic.Int64/Uint64 zero-value-safe fields — no init required"

requirements-completed:
  - ADMIN-LOG-01
  - ADMIN-RRL-01
  - ADMIN-METRICS-01

# Metrics
duration: 6min
completed: 2026-05-16
---

# Phase 6 Plan 01: Admin API Package Extension Summary

**Three internal packages extended with admin-ready methods: Logger gains dynamic query-log control + queriesLogged counter; rrl.Limiter gains GetConfig/UpdateConfig with cfgMu RWMutex cfg snapshot; server.Server gains udpQueries/tcpQueries atomics and Stats.UDPQueries/TCPQueries fields.**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-05-16T13:50:54Z
- **Completed:** 2026-05-16T13:56:39Z
- **Tasks:** 3 (each with TDD RED + GREEN commits)
- **Files modified:** 6 (3 source, 3 test)

## Accomplishments
- Logger: SetQueryLogEnabled/IsQueryLogEnabled/QueryLogConfig/QueriesLogged added; LogQuery race fixed by holding mu for full body; queriesLogged atomic counter incremented on each logged query
- rrl.Limiter: cfgMu sync.RWMutex added; Check() uses cfg snapshot under RLock (T-06-02); GetConfig/UpdateConfig exposed; race detector clean
- server.Server: udpQueries/tcpQueries atomic.Uint64 fields; handleDNS increments correct counter per transport; Stats.UDPQueries/TCPQueries populated by GetStats()

## Task Commits

Each task was committed atomically (TDD: test commit then feat commit):

1. **Task 1 RED: Logger tests** - `8dba6cf` (test)
2. **Task 1 GREEN: Logger implementation** - `080a43e` (feat)
3. **Task 2 RED: rrl.Limiter tests** - `3c41dc0` (test)
4. **Task 2 GREEN: rrl.Limiter implementation** - `8ec1b0f` (feat)
5. **Task 3 RED: server transport counter tests** - `e774647` (test)
6. **Task 3 GREEN: server transport counter implementation** - `4cf87af` (feat)

## Files Created/Modified
- `internal/logging/logger.go` - Added queriesLogged field, 4 exported methods, LogQuery mu fix
- `internal/logging/logger_test.go` - 6 TDD tests for new Logger methods
- `internal/rrl/limiter.go` - Added cfgMu, cfg snapshot in Check(), GetConfig/UpdateConfig, refactored helpers to pkg-level fns
- `internal/rrl/limiter_admin_test.go` - 4 TDD tests for GetConfig/UpdateConfig/cfgMu
- `internal/server/server.go` - Added udpQueries/tcpQueries atomics, Stats fields, handleDNS increment, GetStats population
- `internal/server/server_transport_test.go` - 3 TDD tests for Stats fields and GetStats

## Decisions Made
- cfg snapshot pattern for rrl.Limiter: single RLock copy at top of Check() → local var used throughout; avoids holding lock during bucket operations
- Helper functions (isExempt, getLimitForCategory, bucketHash, getPrefix) refactored from receiver methods to package-level functions accepting Config snapshot — eliminates secondary lock acquisition
- LogQuery holds mu for entire body to fix pre-existing data race with SetQueryLogEnabled
- UDP/TCP discrimination in handleDNS added as separate block before existing clientIP extraction — non-invasive, parallel type-assert

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Refactored Limiter helper methods to package-level functions**
- **Found during:** Task 2 (rrl.Limiter implementation)
- **Issue:** Plan specified cfg snapshot in Check() with `l.cfg` replaced by `cfg.` in sub-methods, but the sub-methods are receiver methods that would still reference `l.cfg` if called elsewhere. Refactoring to package-level functions accepting a Config snapshot is the correct pattern.
- **Fix:** Converted isExempt, getLimitForCategory, bucketHash, getPrefix from Limiter methods to package-level functions taking a Config parameter; Check() passes the snapshot
- **Files modified:** internal/rrl/limiter.go
- **Verification:** go test -race ./internal/rrl/... exits 0, no race output
- **Committed in:** 8ec1b0f (Task 2 feat commit)

---

**Total deviations:** 1 auto-fixed (1 Rule 1 bug — refactor for correctness)
**Impact on plan:** Essential for correct cfg snapshot semantics. No scope creep.

## Issues Encountered
- Pre-existing vet error in internal/protective/engine.go (line 410: return copies lock value) — pre-dates Phase 6, out of scope. Logged to deferred-items.md.

## Threat Flags

None — no new network endpoints, auth paths, or trust boundary surfaces introduced. All three changes are internal package extensions. T-06-01 (LogQuery race) and T-06-02 (cfg update race) both mitigated as specified in threat model.

## Next Phase Readiness
- Wave 2 plans (06-02 through 06-04) can now delegate to these methods without package design work
- Logger: admin RPC can call SetQueryLogEnabled, IsQueryLogEnabled, QueryLogConfig, QueriesLogged
- Limiter: admin RPC can call GetConfig, UpdateConfig
- Server: admin RPC can call GetStats() and receive UDPQueries + TCPQueries in response

---
*Phase: 06-admin-api-stubs-registration*
*Completed: 2026-05-16*

## Self-Check: PASSED

- internal/logging/logger.go: FOUND
- internal/rrl/limiter.go: FOUND
- internal/server/server.go: FOUND
- 06-01-SUMMARY.md: FOUND
- Commit 8dba6cf: FOUND
- Commit 080a43e: FOUND
- Commit 3c41dc0: FOUND
- Commit 8ec1b0f: FOUND
- Commit e774647: FOUND
- Commit 4cf87af: FOUND
