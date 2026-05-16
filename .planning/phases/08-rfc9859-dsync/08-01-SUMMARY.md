---
phase: 08-rfc9859-dsync
plan: 01
subsystem: dns
tags: [dsync, rfc9859, ratelimit, codec, tdd, miekg-dns, golang-x-time]

# Dependency graph
requires: []
provides:
  - "internal/dsync package: TypeDSYNC=66, DSYNCRecord struct, EncodeDSYNC, DecodeDSYNC, ParseRFC3597"
  - "Per-source-IP NOTIFY rate limiter: NotifyLimiter with background eviction"
affects:
  - 08-02  # inbound NOTIFY handler depends on DSYNCRecord and NotifyLimiter
  - 08-03  # outbound sender depends on EncodeDSYNC/DecodeDSYNC
  - 08-04  # discovery uses ParseRFC3597 for _dsync lookup responses
  - 08-05  # server wiring uses NotifyLimiter

# Tech tracking
tech-stack:
  added: []  # No new dependencies — uses github.com/miekg/dns and golang.org/x/time/rate already in go.mod
  patterns:
    - "RFC3597 hex codec pattern: EncodeDSYNC produces hex string for dns.RFC3597.Rdata; DecodeDSYNC consumes it"
    - "Per-IP visitor map with background goroutine eviction (sweepStale, 10-min TTL, 5-min sweep interval)"
    - "sync.Once for idempotent Close() on background-goroutine types"
    - "TDD: test(RED) commit then feat(GREEN) commit, gate verified by git log"

key-files:
  created:
    - internal/dsync/dsync.go
    - internal/dsync/dsync_test.go
    - internal/dsync/ratelimit.go
    - internal/dsync/ratelimit_test.go
  modified: []

key-decisions:
  - "TypeDSYNC = 66: miekg/dns v1.1.72 does not define it; defined in internal/dsync package"
  - "DSYNCRecord is a plain struct (not dns.RR interface); codec is EncodeDSYNC/DecodeDSYNC pair operating on hex strings"
  - "Close() uses sync.Once for safe multiple-call semantics — prevents panic when defer + explicit call coexist"
  - "Test helpers (ForceLastSeen, SweepStaleForTest, VisitorCount) exported on NotifyLimiter for white-box eviction testing"
  - "Minimum RDATA length 6 bytes enforced before any field access (T-08-01 mitigated)"

patterns-established:
  - "Pattern 1: DNS RFC3597 hex codec — EncodeDSYNC uses dns.PackDomainName into 255-byte scratch buf; DecodeDSYNC uses dns.UnpackDomainName at offset 5"
  - "Pattern 2: Per-IP limiter map with background eviction — visitor struct holds *rate.Limiter + lastSeen; sweepStale called every 5min; entries evicted after 10min idle"
  - "Pattern 3: sync.Once for Close() — prevents double-close panic when defer + direct call both fire"

requirements-completed: [DSYNC-01, DSYNC-02, DSYNC-04, DSYNC-05]

# Metrics
duration: 83min
completed: 2026-05-16
---

# Phase 08 Plan 01: DSYNC Codec and Rate Limiter Summary

**RFC 9859 DSYNC type-66 codec with EncodeDSYNC/DecodeDSYNC/ParseRFC3597 and per-source-IP token-bucket NotifyLimiter with background eviction via golang.org/x/time/rate**

## Performance

- **Duration:** 83 min
- **Started:** 2026-05-16T20:28:37Z
- **Completed:** 2026-05-16T21:51:00Z
- **Tasks:** 2 (TDD: 1 RED + 1 GREEN)
- **Files modified:** 4 created

## Accomplishments

- DSYNC RR type-66 codec: wire-format encode/decode round-trips correctly for CDS (59), CSYNC (62), and null-scheme (0) records
- Security: minimum-6-byte length check on DecodeDSYNC prevents panic on malformed inbound wire data (T-08-01)
- NotifyLimiter: per-source-IP token bucket using x/time/rate with background goroutine that evicts stale visitors (T-08-02, prevents unbounded map growth)
- Full TDD cycle: RED commit (a106109) + GREEN commit (e7a7b2a); all 10 tests pass under go test -v

## Task Commits

1. **Task 1: RED — Write failing tests** - `a106109` (test)
2. **Task 2: GREEN — Implement dsync.go and ratelimit.go** - `e7a7b2a` (feat)

## TDD Gate Compliance

- RED gate: `a106109` — `test(08-01): add failing tests for DSYNC codec and rate limiter (RED)`
- GREEN gate: `e7a7b2a` — `feat(08-01): implement DSYNC codec and NotifyLimiter (GREEN)`

Both gates present in git log. No REFACTOR gate needed (code was clean as written).

## Files Created/Modified

- `internal/dsync/dsync.go` — TypeDSYNC=66, DSYNCSchemeNull/NOTIFY, DSYNCRecord, EncodeDSYNC, DecodeDSYNC, ParseRFC3597
- `internal/dsync/dsync_test.go` — 5 tests: RoundTrip, TooShort, CSYNC, ParseRFC3597, SchemeZeroIgnored
- `internal/dsync/ratelimit.go` — visitor struct, NotifyLimiter, NewNotifyLimiter, Allow, sweepStale, cleanupLoop, Close (sync.Once), test helpers
- `internal/dsync/ratelimit_test.go` — 5 tests: Allows, Blocks, Eviction, DifferentIPs, Close

## Decisions Made

- **TypeDSYNC = 66:** miekg/dns v1.1.72 does not define this; we define it in internal/dsync per RFC 9859 and verified by direct grep of installed module source
- **Plain struct codec:** DSYNCRecord is a plain struct, not a dns.RR implementation. Codec operates on hex strings (dns.RFC3597.Rdata format). Simpler for handler/sender code in later plans
- **sync.Once for Close():** Test pattern uses `defer limiter.Close()` safety guard alongside explicit Close() call, which would panic with a raw `close(ch)`. sync.Once makes Close idempotent
- **Exported test helpers:** ForceLastSeen, SweepStaleForTest, VisitorCount exported on NotifyLimiter to enable deterministic eviction testing without time.Sleep

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed double-close panic in Close()**
- **Found during:** Task 2 (GREEN — first test run)
- **Issue:** TestRateLimiterClose had both `defer limiter.Close()` and explicit `limiter.Close()` in goroutine. Raw `close(nl.stopCh)` in Close() panicked on the second call with "close of closed channel"
- **Fix:** Wrapped close/wait in `nl.closeOnce.Do(...)` using sync.Once — subsequent calls are no-ops
- **Files modified:** internal/dsync/ratelimit.go
- **Verification:** All 10 tests pass; no panic
- **Committed in:** e7a7b2a (Task 2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Fix was essential for correct goroutine lifecycle semantics. sync.Once is the standard Go pattern for idempotent Close(). No scope creep.

## Issues Encountered

None beyond the double-close bug documented above.

## Known Stubs

None — all exported functions are fully implemented. No hardcoded empty values or placeholder text.

## Threat Flags

No new security-relevant surface beyond what the plan's threat model covers.
- T-08-01 mitigated: `if len(raw) < 6 { return ..., "dsync rdata too short: %d bytes" }` before any field access in DecodeDSYNC
- T-08-02 mitigated: sweepStale() evicts visitors with lastSeen > 10 minutes every 5 minutes

## Next Phase Readiness

Plans 02-06 can now import `internal/dsync` for:
- Plan 02 (inbound NOTIFY handler): uses `DSYNCRecord`, `NotifyLimiter.Allow()`
- Plan 03 (outbound sender): uses `EncodeDSYNC`, `DecodeDSYNC`, `TypeDSYNC`
- Plan 04 (discovery): uses `ParseRFC3597`, `DecodeDSYNC`

No blockers. `go build ./internal/dsync/...` and `go test ./internal/dsync/...` both exit 0.

---
*Phase: 08-rfc9859-dsync*
*Completed: 2026-05-16*
