---
phase: 8
slug: rfc9859-dsync
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-16
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go testing (stdlib) + testify v1.11.1 |
| **Config file** | none (go test ./...) |
| **Quick run command** | `go test ./internal/dsync/... -v -run TestUnit` |
| **Full suite command** | `go test ./... -timeout 30s` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/dsync/... -v`
- **After every plan wave:** Run `go test ./... -timeout 30s`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 1 | DSYNC-01 | — | encode→decode roundtrip produces identical record | unit | `go test ./internal/dsync/... -run TestDSYNCCodec` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 1 | DSYNC-02 | — | reject rdata < 6 bytes with error | unit | `go test ./internal/dsync/... -run TestDSYNCDecodeTooShort` | ❌ W0 | ⬜ pending |
| 08-01-03 | 01 | 1 | DSYNC-04 | T-08-01 | rate limiter blocks excess NOTIFY from single IP | unit | `go test ./internal/dsync/... -run TestNotifyRateLimiter` | ❌ W0 | ⬜ pending |
| 08-01-04 | 01 | 1 | DSYNC-05 | — | rate limiter visitor map evicts stale entries | unit | `go test ./internal/dsync/... -run TestRateLimiterEviction` | ❌ W0 | ⬜ pending |
| 08-02-01 | 02 | 2 | DSYNC-03 | — | inbound NOTIFY(CDS) dispatches to handler | unit | `go test ./internal/dsync/... -run TestHandleInboundNotifyCDS` | ❌ W0 | ⬜ pending |
| 08-02-02 | 02 | 2 | DSYNC-06 | — | _dsync discovery returns DSYNC records | unit | `go test ./internal/dsync/... -run TestDiscoverDSYNC` | ❌ W0 | ⬜ pending |
| 08-02-03 | 02 | 2 | DSYNC-07 | — | outbound NOTIFY(CDS) carries correct qtype | unit | `go test ./internal/dsync/... -run TestSendNotifyQtype` | ❌ W0 | ⬜ pending |
| 08-03-01 | 03 | 3 | DSYNC-08 | — | handleDNS dispatches NOTIFY opcode to dsync handler | integration | `go test ./internal/server/... -run TestHandleDNSNotifyOpcode` | ❌ W0 | ⬜ pending |
| 08-04-01 | 04 | 4 | DSYNC-09 | — | zone file with TYPE66 loads and serves correctly | unit | `go test ./internal/zone/... -run TestDSYNCZoneFile` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/dsync/dsync_test.go` — stubs for DSYNC-01, DSYNC-02
- [ ] `internal/dsync/handler_test.go` — stubs for DSYNC-03, DSYNC-04, DSYNC-05
- [ ] `internal/dsync/discovery_test.go` — stubs for DSYNC-06
- [ ] `internal/dsync/sender_test.go` — stubs for DSYNC-07
- [ ] `internal/server/notify_test.go` — stubs for DSYNC-08
- [ ] `internal/zone/parser_dsync_test.go` — stubs for DSYNC-09

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Outbound NOTIFY reaches real parent-zone DSYNC target | DSYNC-07 | Requires live DNS infrastructure | Set up test zone with `_dsync.<parent>` DSYNC record; trigger `SendDSYNCNotify` RPC; observe NOTIFY on parent's port 53 |
| Webhook POST fires on inbound NOTIFY | D-01 | Requires external HTTP endpoint | Configure `webhook_url` for a test zone; send NOTIFY(CDS); confirm POST received with correct JSON body |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
