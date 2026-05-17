---
phase: 08-rfc9859-dsync
plan: "07"
subsystem: dsync
tags: [dsync, rfc9859, wiring, notifier, grpc]
dependency_graph:
  requires: [08-06]
  provides: [dsync-notifier-wired, dsync-admin-service-registered]
  affects: [internal/server/server.go, cmd/dnsscienced/main.go]
tech_stack:
  added: []
  patterns: [setter-post-construction, variadic-param-extension, nil-guard-accessor]
key_files:
  created:
    - internal/server/dsync_wiring_test.go
  modified:
    - internal/server/server.go
    - cmd/dnsscienced/main.go
decisions:
  - "DSYNCNotifier has no Stop() method; worker goroutine exits with process — documented as comment in Stop()"
  - "Per-zone webhook wiring (ZoneDSYNCConfig.WebhookURL) deferred — no server-level webhook URL in DSYNCConfig"
metrics:
  duration: "~5 minutes"
  completed: "2026-05-17"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 3
---

# Phase 08 Plan 07: Wire DSYNCNotifier + DSYNCAdminService Registration Summary

**One-liner:** Wire DSYNCNotifier into server.New() with shared metrics and expose via accessor so main.go can register DSYNCAdminService through the existing variadic RegisterAll extension.

## What Was Built

Three previously-implemented DSYNC components were dead code in the running binary:
- `DSYNCNotifier` was never instantiated
- `DSYNCAdminService` was never registered on the admin gRPC server
- Per-zone webhook wiring was documented as not yet applicable (no server-level WebhookURL)

This plan connects the fully-implemented dsync components to the production lifecycle:

1. `server.go` now creates `DSYNCNotifier` inside the `if cfg.DSYNC.Enabled` block, calls `SetMetrics(dsyncMetrics)` on it (sharing the same `*DSYNCMetrics` instance already passed to the handler), and exposes it via `GetDSYNCNotifier()`.
2. `main.go` passes `srv.GetDSYNCNotifier()` as the 6th arg to `registry.RegisterAll`, triggering the conditional `DSYNCAdminService` registration added in Plan 06.
3. Three integration tests verify the full lifecycle: notifier non-nil when enabled, nil when disabled, and the shared metrics wiring path.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | b5a40af | feat(08-07): wire DSYNCNotifier into server.go and expose accessor |
| 2 | 06f5f4c | feat(08-07): pass DSYNCNotifier to RegisterAll in main.go |
| 3 | 616e386 | test(08-07): add DSYNCNotifier wiring integration tests |

## Verification Results

All plan verification steps passed:
- `go build ./...` exits 0
- `TestDSYNCNotifierWiring` PASS
- `TestDSYNCNotifierNilWhenDisabled` PASS
- `TestDSYNCHandlerAndNotifierShareMetrics` PASS
- `TestHandleDNSNotifyOpcode_Enabled/_Disabled` PASS (no regressions)
- `TestSendDSYNCNotify_*` (5 tests) PASS (no regressions)
- `grep -c "dsyncNotifier \*dsync.DSYNCNotifier" internal/server/server.go` = 1
- `grep -c "GetDSYNCNotifier()" cmd/dnsscienced/main.go` = 1

## Deviations from Plan

None — plan executed exactly as written. The one conditional path (Stop() cleanup) was anticipated by the plan: since DSYNCNotifier has no Stop() method, a comment was added to Stop() instead of a stop call, exactly as the plan's NOTE instructed.

## Known Stubs

None. No placeholder data paths introduced.

## Threat Flags

No new network endpoints, auth paths, or schema changes beyond what the plan's threat model covers. All threats accepted/mitigated as documented in the plan's STRIDE register.

## Self-Check: PASSED

- `internal/server/server.go` — exists and contains all required patterns
- `cmd/dnsscienced/main.go` — contains `GetDSYNCNotifier()` call
- `internal/server/dsync_wiring_test.go` — exists with all 3 test functions
- Commits b5a40af, 06f5f4c, 616e386 — all present in git log
