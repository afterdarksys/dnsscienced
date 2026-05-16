---
phase: 08-rfc9859-dsync
plan: "02"
subsystem: dns
tags: [rfc9859, dsync, notify, acl, rate-limit, zerolog, miekg-dns]

requires:
  - phase: 08-01
    provides: TypeDSYNC=66, DSYNCRecord codec, NotifyLimiter per-IP rate limiter

provides:
  - "Handler struct with Allower interface, NewHandler(limiter, acl, log), HandleInbound method"
  - "AllowAllACL() stub that Plan 05 replaces with real SourceACL"
  - "DiscoverDSYNC: _dsync parent label traversal per RFC 9859 s3"
  - "DSYNCNotifier: buffered-channel non-blocking outbound NOTIFY enqueue with propagation delay"
  - "sendNotify: SetNotify + Qtype override (SOA->CDS/CSYNC) per RFC 9859"

affects:
  - 08-03  # server wiring: NewHandler wired into handleDNS
  - 08-05  # ACL plan: replaces AllowAllACL with real SourceACL

tech-stack:
  added: []
  patterns:
    - "Allower interface: Check(net.IP) bool — swappable ACL plug-in point for Plan 05"
    - "ACL-first, rate-limit-second guard ordering (both return REFUSED before NOERROR)"
    - "TDD RED/GREEN: test file committed before implementation"
    - "Mock DNS server: net.ListenPacket(udp, 127.0.0.1:0) for capture testing"
    - "Buffered channel (64) for outbound NOTIFY queue with drop-on-full semantics"
    - "SetNotify + Question[0].Qtype override for non-SOA NOTIFY"

key-files:
  created:
    - internal/dsync/handler.go
    - internal/dsync/discovery.go
    - internal/dsync/sender.go
    - internal/dsync/handler_test.go
    - internal/dsync/discovery_test.go
    - internal/dsync/sender_test.go

key-decisions:
  - "Allower interface with Check(net.IP) bool — Plan 05 provides SourceACL satisfying this; NewHandler signature is FINAL"
  - "ACL check FIRST, rate limit SECOND — both return REFUSED (T-08-03 mitigated); goroutine spawned only after both pass"
  - "scheduleDelegationCheck is stub (log only) — full delegation engine deferred beyond Phase 8"
  - "DiscoverDSYNC loop bounded by len(labels)-1 (T-08-05) — stops before TLD-only candidate"
  - "Malformed DSYNC records silently skipped in queryDSYNC (T-08-04 accept disposition)"
  - "DSYNCNotifier buffered channel of 64 drops events when full + warning log (T-08-07 mitigated)"
  - "sendNotify TrimSuffix trailing dot from FQDN target before JoinHostPort"

patterns-established:
  - "Allower interface: swappable ACL plug-in point (Plan 05 will replace AllowAllACL)"
  - "Mock UDP capture server: net.ListenPacket on 127.0.0.1:0 for zero-port allocation in tests"
  - "TDD gate: RED commit (test), GREEN commit (feat) per plan type=tdd"

requirements-completed:
  - DSYNC-03
  - DSYNC-06
  - DSYNC-07

duration: 16min
completed: 2026-05-16
---

# Phase 08 Plan 02: NOTIFY Handler, Discovery, and Sender Summary

**RFC 9859 inbound NOTIFY handler (ACL+rate-limit->REFUSED), _dsync parent discovery, and outbound NOTIFY sender (SetNotify + Qtype override) with 26 passing tests**

## Performance

- **Duration:** 16 min
- **Started:** 2026-05-16T21:57:04Z
- **Completed:** 2026-05-16T22:13:06Z
- **Tasks:** 2 (each TDD with RED+GREEN commits)
- **Files modified:** 6 (3 implementation + 3 test)

## Accomplishments
- Inbound NOTIFY handler: ACL check first, rate limit second — both return REFUSED; async delegation check stub (log only)
- Allower interface with AllowAllACL() stub; Plan 05 replaces with real SourceACL without changing NewHandler signature
- DiscoverDSYNC: label-by-label traversal of _dsync.<delegation> through parent labels per RFC 9859 §3
- DSYNCNotifier: buffered channel (64) with non-blocking Notify() + worker goroutine with propagation delay
- sendNotify: uses SetNotify (Opcode=4, AA=true) then overrides Question[0].Qtype from SOA to CDS/CSYNC

## Task Commits

Each task was committed atomically with TDD RED then GREEN:

1. **Task 1 RED: Inbound NOTIFY handler tests** - `686f6fe` (test)
2. **Task 1 GREEN: handler.go implementation** - `cbd6fb6` (feat)
3. **Task 2 RED: Discovery and sender tests** - `b58153b` (test)
4. **Task 2 GREEN: discovery.go and sender.go** - `8b1d821` (feat)

**Plan metadata:** (docs commit follows)

_TDD plan: each task has test commit (RED) then implementation commit (GREEN)_

## Files Created/Modified
- `internal/dsync/handler.go` - Handler struct, Allower interface, AllowAllACL stub, HandleInbound, scheduleDelegationCheck stub
- `internal/dsync/discovery.go` - DiscoverDSYNC, queryDSYNC with RFC3597 decode and malformed-record skip
- `internal/dsync/sender.go` - DSYNCNotifier, Notify() enqueue, worker goroutine, sendNotify with Qtype override
- `internal/dsync/handler_test.go` - 6 TestHandleInbound_* tests with mockResponseWriter and rejectAll ACL
- `internal/dsync/discovery_test.go` - 5 TestDiscoverDSYNC_* tests using startMockDNSServer helper
- `internal/dsync/sender_test.go` - 4 tests: qtype correctness, enqueue non-blocking, roundtrip

## Decisions Made
- Allower interface with Check(net.IP) bool is the correct plug-in point; NewHandler signature is FINAL and Plan 05 must NOT change it
- ACL check BEFORE rate limit is the correct order per D-06/D-14; both return REFUSED (not NOERROR then drop)
- DiscoverDSYNC stops at len(labels)-1 (T-08-05) — avoids querying _dsync.<TLD-only>
- Malformed DSYNC records silently skipped with continue (T-08-04 accept disposition — DNSSEC deferred)
- sendNotify strips trailing FQDN dot via strings.TrimSuffix before net.JoinHostPort

## Deviations from Plan

None - plan executed exactly as written. All behavior, interfaces, and implementation details matched the plan specification.

## Issues Encountered
- sender_test.go initial draft had messy port-parsing helper with unused variables; simplified to `net.ResolveTCPAddr("tcp", addr)` pattern (Rule 3 auto-fix, no separate commit needed — caught before RED commit).

## User Setup Required
None - no external service configuration required.

## Known Stubs
- `scheduleDelegationCheck` in handler.go: logs only, no delegation maintenance engine. This is intentional per plan — full engine is a future phase. The stub satisfies RFC 9859's "schedule a check" requirement at the protocol acknowledgement layer.

## Threat Flags

No new threat surface introduced beyond what is documented in the plan's threat model.

## Next Phase Readiness
- handler.go Handler + NewHandler ready for Plan 03 server wiring into handleDNS
- AllowAllACL() ready for Plan 03 as default; Plan 05 ACL replaces it
- DSYNCNotifier ready for Plan 03/04 zone update event wiring
- All 26 dsync package tests passing; `go build ./internal/dsync/...` clean

## Self-Check: PASSED

All 6 implementation/test files exist. All 4 task commits found (686f6fe, cbd6fb6, b58153b, 8b1d821). `go build ./internal/dsync/...` exits 0. 26 tests pass.

---
*Phase: 08-rfc9859-dsync*
*Completed: 2026-05-16*
