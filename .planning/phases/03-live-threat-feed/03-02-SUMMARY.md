---
phase: 03-live-threat-feed
plan: "02"
subsystem: firewalld
tags: [go, threat-intel, feed-client, http-polling, full-replace]

requires:
  - phase: 03-live-threat-feed
    plan: "01"
    provides: "ThreatIntelConfig feed fields (FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers); RemoveIPScore on *ThreatIntel"

provides:
  - "FeedClient struct with prevDomains/prevIPs for full-replace feed semantics"
  - "newFeedClient constructor with configured http.Client (TLS, timeout, redirect support)"
  - "StartFeed(ctx, wg) method on *Firewall — goroutine-based poller, no-op when FeedURL empty"
  - "parseFeed pure function: CIDR→IP→domain detection, skip blanks/#comments, warnings for malformed lines"
  - "apply() full-replace: remove prev cycle entries then inject new with score clamped [0,100]"
  - "fetchAndApply(): error resilience — failed fetch leaves previous scores intact (D-14)"

affects:
  - 03-03-server-wiring

tech-stack:
  added: []
  patterns:
    - "FeedClient wg parameter typed as interface{ Add(int); Done() } to accept *sync.WaitGroup without coupling"
    - "AuthToken never in log output — authDesc computed as 'bearer (set)' or 'none' before any log calls"
    - "parseFeed is package-internal (lowercase) and pure — no side effects, testable in isolation"
    - "Full-replace ordering: remove ALL prev entries FIRST after success, then inject new; error path returns early"

key-files:
  created:
    - internal/firewalld/feed.go
  modified: []

key-decisions:
  - "wg typed as interface{ Add(int); Done() } — accepts *sync.WaitGroup without importing sync in callers; server passes &s.wg directly (Plan 03)"
  - "No context.Background() in feed.go — ctx always server-derived; goroutine lifetime tied to server shutdown"
  - "CIDR entries stored as-is (string) in prevIPs — AddIPScore/RemoveIPScore accept CIDR strings; no net.IPNet expansion needed here"
  - "AuthToken (T-03-03) mitigated: authDesc computed once, AuthToken only referenced in cfg.AuthToken != '' check and Header.Set"

patterns-established:
  - "Error resilience: fetchAndApply() returns immediately on fetch error; apply() not called; prevDomains/prevIPs unchanged"
  - "Goroutine lifecycle: immediate first fetch on run() entry, then ticker; ctx.Done() exits cleanly"

requirements-completed:
  - FEED-02
  - FEED-03
  - FEED-04

duration: 2min
completed: 2026-04-23
---

# Phase 3 Plan 02: FeedClient Summary

**HTTP polling FeedClient with full-replace semantics injecting domain/IP threat scores into ThreatIntel engine, with error resilience, Bearer auth, and StartFeed goroutine entry point on *Firewall**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-04-23T20:42:45Z
- **Completed:** 2026-04-23T20:44:17Z
- **Tasks:** 1
- **Files modified:** 1 (1 created)

## Accomplishments

- Created `internal/firewalld/feed.go` with all 7 functions: newFeedClient, StartFeed, run, fetchAndApply, fetch, parseFeed, apply
- Full-replace semantics implemented: prevDomains/prevIPs track previous cycle; apply() removes all previous entries before injecting new ones
- Error resilience (D-14): failed fetch returns immediately without touching prevDomains/prevIPs; previous scores remain active
- AuthToken redaction (T-03-03, D-12): token never in any log field; only authDesc "bearer (set)" or "none" logged

## Task Commits

Each task was committed atomically:

1. **Task 1: Create internal/firewalld/feed.go with FeedClient and StartFeed** - `e328148` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `internal/firewalld/feed.go` — FeedClient struct, newFeedClient constructor, StartFeed method on *Firewall, run/fetchAndApply/fetch/parseFeed/apply functions

## Decisions Made

- `wg` parameter typed as `interface{ Add(int); Done() }` so server can pass `&s.wg` directly without feed.go importing sync; Plan 03 can wire this without type friction
- No `context.Background()` used anywhere — ctx always passed from server, goroutine lifetime tied to server shutdown signal
- CIDR strings stored as-is in prevIPs map rather than expanding to net.IPNet — AddIPScore/RemoveIPScore operate on string keys so CIDR string round-trips correctly
- authDesc computed once before log call; AuthToken only referenced in `cfg.AuthToken != ""` guard and `req.Header.Set("Authorization", "Bearer "+fc.cfg.AuthToken)` — satisfies T-03-03

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Known Stubs

None — all functions fully implemented with real logic. No placeholder data or TODO markers.

## Threat Flags

No new trust boundaries introduced beyond those documented in the plan's threat model (T-03-03 through T-03-09). All mitigations applied as specified:
- T-03-03: AuthToken never in log output (authDesc pattern)
- T-03-04: No panic anywhere; malformed lines produce warning strings
- T-03-05: StartFeed returns immediately; goroutine runs in background
- T-03-09: apply() only called on success path; error returns early

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 03 (server wiring) can now call `fw.StartFeed(ctx, &s.wg)` to activate the poller
- FeedURL empty → StartFeed is a no-op; servers without feed config are unaffected
- go build ./... passes; all firewalld package tests pass
- FEED-02, FEED-03, FEED-04 requirements delivered

---
*Phase: 03-live-threat-feed*
*Completed: 2026-04-23*
