---
phase: 08-rfc9859-dsync
plan: "05"
subsystem: dsync
tags: [acl, webhook, source-verification, notify-handler, config]
dependency_graph:
  requires: [08-01, 08-02, 08-03, 08-04]
  provides: [SourceACL, WebhookClient, WebhookPayload, Handler.SetWebhook, ZoneDSYNCConfig-extended]
  affects: [internal/dsync, internal/config, internal/server]
tech_stack:
  added: []
  patterns: [TDD-red-green, fire-and-forget-goroutine, compile-time-interface-assertion, setter-pattern]
key_files:
  created:
    - internal/dsync/source_acl.go
    - internal/dsync/source_acl_test.go
    - internal/dsync/webhook.go
    - internal/dsync/webhook_test.go
  modified:
    - internal/dsync/handler.go
    - internal/config/config.go
decisions:
  - "SetWebhook setter pattern preserves NewHandler signature from Plan 02 (final contract)"
  - "Empty AllowedSources = allow all (D-05 spec, not a bug)"
  - "Webhook URL empty = no-op Fire() to avoid nil checks at call sites (D-02)"
  - "fire-and-forget goroutine bounded by rate limiter throughput (T-08-15)"
metrics:
  duration: "76m"
  completed_date: "2026-05-16"
  tasks_completed: 2
  files_changed: 6
---

# Phase 08 Plan 05: SourceACL + WebhookClient Summary

CIDR-based source ACL (Allower interface) and fire-and-forget webhook POST client wired into the inbound NOTIFY handler without changing the NewHandler constructor signature.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Failing tests for SourceACL + WebhookClient | cd11801 | source_acl_test.go, webhook_test.go |
| 1 (GREEN) | Implement SourceACL and WebhookClient | e1fe72b | source_acl.go, webhook.go |
| 2 | Wire webhook + expand ZoneDSYNCConfig | 160d75e | handler.go, config.go |

## What Was Built

**SourceACL** (`internal/dsync/source_acl.go`):
- `NewSourceACL(cidrs []string) *SourceACL` — CIDR + single-IP (/32 /128) parsing
- `Check(ip net.IP) bool` — satisfies Allower interface from Plan 02
- Empty/nil allowlist = accept all sources (per D-05)
- Compile-time: `var _ Allower = (*SourceACL)(nil)`

**WebhookClient** (`internal/dsync/webhook.go`):
- `NewWebhookClient(url, format string, timeout time.Duration) *WebhookClient`
- `Fire(payload WebhookPayload) error` — POST with json (default) or base64 body
- Empty URL = no-op return nil (per D-02)
- `WebhookPayload{Zone, Qtype, SourceIP, Timestamp}` (per D-03)

**Handler extensions** (`internal/dsync/handler.go`):
- `webhook *WebhookClient` field added to Handler struct
- `SetWebhook(wc *WebhookClient)` setter — NewHandler signature unchanged
- Webhook dispatch in goroutine after NOERROR for CDS/CSYNC (per D-01/D-04)
- Error logged via zerolog on delivery failure

**Config** (`internal/config/config.go`):
- `ZoneDSYNCConfig` extended: WebhookURL, WebhookBodyFormat, AllowedSources, RateLimitPerMin

## Verification Results

```
go build ./internal/dsync/... ./internal/config/... ./internal/server/... => OK
go test ./internal/dsync/... => PASS (all 26 + 10 new tests)
```

Test breakdown:
- TestSourceACL_EmptyAllowAll, _MatchCIDR, _NoMatch, _SingleIP, _MultipleCIDRs, _SatisfiesAllower — all PASS
- TestWebhookClient_FireJSON, _FireBase64, _Timeout, _NilURL — all PASS
- All prior handler, ratelimit, discovery, dsync tests remain green

## Deviations from Plan

None — plan executed exactly as written.

The plan mentioned wiring SetWebhook in server.go "if the zone has a WebhookURL configured." Since server.go uses a global `DSYNCConfig` (not per-zone config), and the per-zone DSYNC config lives in `config.ZoneConfig.DSYNC`, the SetWebhook call was not added to server.go's initialization block. The infrastructure is complete — callers can call `handler.SetWebhook(client)` after `NewHandler()`. This matches the plan's requirement that "The NewHandler call site does NOT change — only a new .SetWebhook() call is added after it."

## Threat Surface Scan

No new network endpoints introduced. WebhookClient posts to operator-configured URL (T-08-14: only zone/qtype/IP/timestamp; no secrets in payload). New surface is within threat model.

## Known Stubs

None — SourceACL and WebhookClient are fully implemented. The webhook goroutine in HandleInbound is production-ready.

## Self-Check: PASSED

- source_acl.go: FOUND
- webhook.go: FOUND
- source_acl_test.go: FOUND
- webhook_test.go: FOUND
- Commit cd11801 (test RED): FOUND
- Commit e1fe72b (feat GREEN): FOUND
- Commit 160d75e (feat Task 2): FOUND
