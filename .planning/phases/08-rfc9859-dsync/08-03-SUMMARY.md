---
phase: 08-rfc9859-dsync
plan: 03
subsystem: dns
tags: [dsync, rfc9859, notify, config, server, opcode, rate-limit]

requires:
  - phase: 08-01
    provides: internal/dsync package with NotifyLimiter, AllowAllACL, TypeDSYNC
  - phase: 08-02
    provides: dsync.Handler with HandleInbound, AllowAllACL Allower interface

provides:
  - ZoneDSYNCConfig struct in internal/config/config.go (NotifyParent, PropagationDelay)
  - DSYNCConfig struct in internal/server/server.go (Enabled, RateLimitPerMin, Burst)
  - DSYNC field on server.Config and ZoneConfig
  - dsyncHandler *dsync.Handler field on Server struct
  - New() initializes dsyncHandler when DSYNC.Enabled=true with rpm/burst defaults
  - handleDNS opcode dispatch: OpcodeNotify routes to dsync before any query processing
  - NOTIFY path returns NOTIMPL when DSYNC disabled (T-08-09 mitigated)

affects:
  - 08-04
  - 08-05
  - 08-06

tech-stack:
  added: []
  patterns:
    - "opcode-dispatch-first: NOTIFY opcode branch is checked before pool.GetMessage and before defensive managers in handleDNS"
    - "pool-reset-aware-tests: testResponseWriter copies Rcode immediately in WriteMsg to avoid pool.PutMessage reset after defer"
    - "rate-limit-default-guard: New() enforces rpm>=1 and burst>=1 when configured values are <=0 (T-08-10 mitigated)"

key-files:
  created:
    - internal/server/notify_test.go
  modified:
    - internal/config/config.go
    - internal/server/server.go

key-decisions:
  - "Use zerolog.Nop() as the logger for dsyncHandler in server.go — Server has no logger field; a nop logger avoids adding an unrelated dependency without disrupting Phase 8 scope"
  - "testResponseWriter copies Rcode (not Msg pointer) in WriteMsg because pool.PutMessage resets the msg struct after handleDNS returns via defer — capturing only the Rcode int is sufficient for these tests"
  - "rpm converted to rps as float64(rpm)/60.0 before passing to dsync.NewNotifyLimiter — no rate.Limit import needed in server.go"

patterns-established:
  - "Opcode dispatch before pool allocation: NOTIFY messages handled without pool.GetMessage to avoid pool lifecycle complexity in the early-return path"

requirements-completed:
  - DSYNC-08

duration: 13min
completed: 2026-05-16
---

# Phase 08 Plan 03: DSYNC Server Wiring Summary

**RFC 9859 NOTIFY opcode dispatch wired into handleDNS with ZoneDSYNCConfig/DSYNCConfig structs and dsync.Handler integration**

## Performance

- **Duration:** 13 min
- **Started:** 2026-05-16T22:15:11Z
- **Completed:** 2026-05-16T22:28:36Z
- **Tasks:** 2 (Task 2 TDD: 3 commits)
- **Files modified:** 3

## Accomplishments
- Added ZoneDSYNCConfig (YAML-parseable with notify_parent, propagation_delay) to config.go
- Added DSYNCConfig (enabled, rate_limit_per_min, burst) to server.Config
- Wired dsync.Handler into Server struct with full New() initialization including rpm/burst defaults
- Inserted RFC 9859 opcode dispatch at the correct position in handleDNS (before pool/defensive)
- 3 new tests passing: NOTIFY-enabled NOERROR, NOTIFY-disabled NOTIMPL, normal query unaffected

## Task Commits

Each task was committed atomically:

1. **Task 1: Add DSYNC config structs** - `bd40bd9` (feat)
2. **Task 2 RED: Failing notify tests** - `1b8b226` (test)
3. **Task 2 GREEN: Wire dsync.Handler + opcode dispatch** - `640e67d` (feat)

_TDD task had RED (test) + GREEN (feat) commits._

## Files Created/Modified
- `internal/config/config.go` - Added ZoneDSYNCConfig struct and DSYNC field on ZoneConfig
- `internal/server/server.go` - Added DSYNCConfig struct, DSYNC field on Config, dsyncHandler field on Server, New() init, handleDNS opcode branch
- `internal/server/notify_test.go` - 3 integration tests for NOTIFY opcode dispatch

## Decisions Made
- Used `zerolog.Nop()` as logger for dsyncHandler — Server has no logger field; avoids scope creep
- `testResponseWriter` captures `Rcode int` (not `*dns.Msg`) because `pool.PutMessage` resets the struct after `handleDNS` returns via `defer`; the int is a value copy immune to reset
- No `rate.Limit` import in server.go — `float64(rpm)/60.0` passed directly to `dsync.NewNotifyLimiter(rps float64, burst int)`

## Deviations from Plan

None - plan executed exactly as written. One implementation detail discovered during TDD RED phase (pool.PutMessage resetting captured msg) was handled by adjusting the test writer design, not the production code.

## Issues Encountered
- During TDD RED phase, `TestHandleDNSNotifyOpcode_Enabled` appeared to pass before implementation because `pool.PutMessage` (via `defer`) was resetting the shared `*dns.Msg` pointer's Rcode back to 0 after `handleDNS` returned. The test captured a pointer to the pooled msg; by the time the assertion ran, the defer had zeroed it. Fixed by capturing only the `Rcode int` in `WriteMsg` — a value copy immune to post-return mutation.

## Known Stubs
- `dsync.NewHandler` logger is `zerolog.Nop()` — structured log output from NOTIFY handling is suppressed until a logger field is added to Server in a future plan.
- `dsync.AllowAllACL()` is the stub ACL — Plan 05 replaces this with a real SourceACL.

## Threat Flags

No new security surface beyond the plan's threat model.

## Self-Check: PASSED

- FOUND: internal/config/config.go
- FOUND: internal/server/server.go
- FOUND: internal/server/notify_test.go
- FOUND: .planning/phases/08-rfc9859-dsync/08-03-SUMMARY.md
- FOUND commit: bd40bd9 (feat: config structs)
- FOUND commit: 1b8b226 (test: RED phase)
- FOUND commit: 640e67d (feat: GREEN phase)

## Next Phase Readiness
- handleDNS NOTIFY dispatch is complete and tested; Plans 04-06 can build on this foundation
- dsyncHandler field accessible throughout server package for future ACL wiring (Plan 05)
- DSYNCConfig YAML-parseable; operators can enable/disable via config.yaml

---
*Phase: 08-rfc9859-dsync*
*Completed: 2026-05-16*
