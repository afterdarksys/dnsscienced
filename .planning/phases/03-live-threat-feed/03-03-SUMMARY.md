---
phase: 03-live-threat-feed
plan: "03"
subsystem: firewalld, server
tags: [go, threat-intel, feed-client, server-wiring, unit-tests, full-replace]

requires:
  - phase: 03-live-threat-feed
    plan: "01"
    provides: "ThreatIntelConfig feed fields; RemoveIPScore on *ThreatIntel"
  - phase: 03-live-threat-feed
    plan: "02"
    provides: "FeedClient, StartFeed(ctx, wg) on *Firewall, parseFeed, apply() full-replace"

provides:
  - "StartFeed wiring in server.go New() — goroutine tracked in s.wg for graceful shutdown"
  - "feed_test.go — 6 tests covering FEED-01 through FEED-04 via httptest.Server mock"
  - "TestFeedConfig: ThreatIntelConfig fields and DefaultConfig defaults verified"
  - "TestParseFeed_ValidEntries / TestParseFeed_ScoreClamping: parseFeed behavior proven"
  - "TestFeedClient_Apply_FullReplace: D-05 full-replace semantics proven end-to-end"
  - "TestFeedClient_ErrorHandling: D-14 error resilience (HTTP 500 retains previous scores)"
  - "TestFeedClient_Lifecycle: goroutine exits within 500ms of context cancel"

affects:
  - Phase 3 complete — live threat feed feature end-to-end delivered

tech-stack:
  added: []
  patterns:
    - "httptest.NewServer with sync.Mutex-protected response swap for deterministic cycle testing"
    - "engine.dynMu.RLock/RUnlock for race-safe map inspection in tests (same-package access)"
    - "context.WithCancel + time.After(500ms) for goroutine lifecycle assertion"

key-files:
  created:
    - internal/firewalld/feed_test.go
  modified:
    - internal/server/server.go

key-decisions:
  - "TestThreatIntel_RemoveIPScore omitted from feed_test.go — already present in threat_intel_test.go (pre-existing, created in Phase 3 Plan 01); duplicate would cause build failure"
  - "Tests access engine.dynDomains/dynIPs directly via dynMu.RLock — same-package access avoids exposing test-only accessors on the public API"

decisions:
  - "Removed duplicate TestThreatIntel_RemoveIPScore from feed_test.go — test already exists in threat_intel_test.go"

duration: 8min
completed: 2026-04-23
---

# Phase 3 Plan 03: Server Wiring and Feed Tests Summary

**StartFeed wired into server.go New() with WaitGroup tracking; feed_test.go proves all four FEED requirements via httptest mock with full-replace and error-resilience scenarios**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-04-23T20:42:00Z
- **Completed:** 2026-04-23T20:50:36Z
- **Tasks:** 2
- **Files modified:** 2 (1 modified, 1 created)

## Accomplishments

- Wired `s.firewall.StartFeed(s.ctx, &s.wg)` into `server.go New()` immediately after the `firewalld.New()` block with a nil guard; feed goroutine now participates in graceful shutdown via `s.wg.Wait()` in `Stop()`
- Created `internal/firewalld/feed_test.go` with 6 tests covering the full Phase 3 scope:
  - `TestFeedConfig` — ThreatIntelConfig field accessibility and DefaultConfig defaults
  - `TestParseFeed_ValidEntries` — domain/IP/CIDR detection and malformed-line warnings
  - `TestParseFeed_ScoreClamping` — score clamp to [0, 100]
  - `TestFeedClient_Apply_FullReplace` — D-05 full-replace: cycle-2 removes cycle-1 entries
  - `TestFeedClient_ErrorHandling` — D-14: HTTP 500 leaves previous scores intact
  - `TestFeedClient_Lifecycle` — goroutine exits within 500ms of context cancel
- `go test -race ./internal/firewalld/...` exits 0 — no data races

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire StartFeed into server.go New()** — `28db3ce` (feat)
2. **Task 2: Write feed_test.go — full unit test suite** — `7cbd330` (test)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `internal/server/server.go` — added 7-line StartFeed wiring block after firewalld.New() block (lines 199-205)
- `internal/firewalld/feed_test.go` — 6 tests using httptest.NewServer, testify assert/require, sync.Mutex response swapping

## Decisions Made

- `TestThreatIntel_RemoveIPScore` not duplicated in feed_test.go — it already exists in `threat_intel_test.go` (created in Plan 01); keeping it there avoids a build-time redeclaration error
- Tests use `engine.dynMu.RLock()` for direct map inspection rather than adding test-only accessors — same-package access makes this safe and idiomatic

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Removed duplicate TestThreatIntel_RemoveIPScore declaration**
- **Found during:** Task 2, initial build
- **Issue:** `TestThreatIntel_RemoveIPScore` already declared in `internal/firewalld/threat_intel_test.go` (Plan 01 artifact); adding it to `feed_test.go` caused a build-time redeclaration error
- **Fix:** Removed the duplicate function from `feed_test.go`; the test already satisfies the plan requirement via the existing `threat_intel_test.go`
- **Files modified:** `internal/firewalld/feed_test.go`
- **Commit:** 7cbd330

## Issues Encountered

None beyond the auto-fixed duplicate declaration above.

## Known Stubs

None — all tests exercise real FeedClient logic against httptest.Server mocks. No placeholder assertions.

## Threat Flags

No new trust boundaries introduced beyond those documented in the plan's threat model:
- T-03-10: Mitigated — `wg.Add(1)` inside `StartFeed` before goroutine launch; `Stop()` `wg.Wait()` blocks until feed exits
- T-03-11: Accepted — `StartFeed` called in `New()`; `Stop()` cancels ctx first then calls `wg.Wait()`; no ordering issue

## Phase 3 Completion Status

All three Phase 3 plans complete:
- Plan 01: ThreatIntelConfig feed fields + RemoveIPScore (FEED-01)
- Plan 02: FeedClient with StartFeed, parseFeed, full-replace apply (FEED-02, FEED-03, FEED-04)
- Plan 03: Server wiring + full test coverage (all FEED requirements verified)

Requirements delivered: FEED-01, FEED-02, FEED-03, FEED-04

---
*Phase: 03-live-threat-feed*
*Completed: 2026-04-23*
