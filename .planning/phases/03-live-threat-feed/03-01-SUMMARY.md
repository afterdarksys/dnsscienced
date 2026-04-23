---
phase: 03-live-threat-feed
plan: "01"
subsystem: firewalld
tags: [go, threat-intel, config, feed-client]

requires:
  - phase: 02-grpc-admin
    provides: "FirewallAdminService RPCs; Firewall.LoadSource; GetFirewall chain"

provides:
  - "ThreatIntelConfig with 6 feed fields: FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers"
  - "DefaultConfig with PollInterval=5m, Timeout=30s feed defaults"
  - "RemoveIPScore(ip string) method on *ThreatIntel for full-replace feed semantics"

affects:
  - 03-02-feed-client
  - 03-03-server-wiring

tech-stack:
  added: []
  patterns:
    - "Feed config fields appended to ThreatIntelConfig without reorganizing existing fields"
    - "TDD: failing test committed before implementation (RED → GREEN per task)"
    - "RemoveIPScore mirrors RemoveDomainScore pattern — dynMu Lock, delete, Unlock"

key-files:
  created:
    - internal/firewalld/config_test.go
    - internal/firewalld/threat_intel_test.go
  modified:
    - internal/firewalld/config.go
    - internal/firewalld/threat_intel.go

key-decisions:
  - "AuthToken doc comment states 'Never logged — only presence is logged' — T-03-01 mitigated at config layer; enforcement in feed.go Plan 02"
  - "TLSSkipVerify defaults false with doc comment — T-03-02 accepted; operator must explicitly opt in"
  - "RemoveIPScore has no ToLower — IP keys stored as net.IP.String() normalized form at call site"

patterns-established:
  - "Feed fields grouped under comment '// Feed poller configuration (D-07 through D-14)'"
  - "TDD per task: RED commit (test(03-01): ...) then GREEN commit (feat(03-01): ...)"

requirements-completed:
  - FEED-01
  - FEED-03

duration: 3min
completed: 2026-04-23
---

# Phase 3 Plan 01: Live Threat Feed Foundation Summary

**ThreatIntelConfig extended with 6 feed fields (FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers) and RemoveIPScore added to ThreatIntel, unblocking Plan 02 FeedClient compilation**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-04-23T20:36:09Z
- **Completed:** 2026-04-23T20:38:25Z
- **Tasks:** 2
- **Files modified:** 4 (2 source, 2 test)

## Accomplishments

- Added 6 feed configuration fields to ThreatIntelConfig with yaml tags matching D-07 through D-14 decisions
- DefaultConfig() now sets PollInterval=5*time.Minute and Timeout=30*time.Second; remaining feed fields at zero values
- Added RemoveIPScore(ip string) to *ThreatIntel, enabling full-replace feed semantics in Plan 02

## Task Commits

Each task was committed atomically via TDD (RED then GREEN):

1. **Task 1 RED: Failing test for feed config fields** - `f633635` (test)
2. **Task 1 GREEN: Add feed config fields to ThreatIntelConfig and DefaultConfig** - `1fea11a` (feat)
3. **Task 2 RED: Failing test for RemoveIPScore** - `7011b55` (test)
4. **Task 2 GREEN: Add RemoveIPScore to ThreatIntel** - `d9abfb7` (feat)

**Plan metadata:** (docs commit follows)

_Note: TDD tasks have two commits each (test → feat)_

## Files Created/Modified

- `internal/firewalld/config.go` — ThreatIntelConfig struct: 6 feed fields added; DefaultConfig: PollInterval+Timeout defaults added
- `internal/firewalld/threat_intel.go` — RemoveIPScore method added after RemoveDomainScore
- `internal/firewalld/config_test.go` — New: TestThreatIntelConfig_FeedFields verifying all 6 fields and defaults
- `internal/firewalld/threat_intel_test.go` — New: TestThreatIntel_RemoveIPScore verifying dynIPs deletion under lock

## Decisions Made

- AuthToken doc comment explicitly states it is never logged (T-03-01 mitigation at config layer; runtime enforcement deferred to feed.go in Plan 02)
- TLSSkipVerify field defaults false; doc comment notes operator opt-in only (T-03-02 accepted)
- RemoveIPScore has no strings.ToLower — IPs stored in net.IP.String() normalized form at the call site (AddIPScore), consistent with Score() lookup

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 02 (FeedClient) can now compile: ThreatIntelConfig.FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers all available
- Plan 02 can call RemoveIPScore during full-replace apply step
- go build ./... passes; all firewalld tests pass

---
*Phase: 03-live-threat-feed*
*Completed: 2026-04-23*
