---
phase: 3
slug: live-threat-feed
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-23
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test (stdlib) + testify v1.11.1 |
| **Config file** | none (standard `go test`) |
| **Quick run command** | `go test ./internal/firewalld/... -run TestFeed -v` |
| **Full suite command** | `go test ./internal/firewalld/... -v` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/firewalld/... -run TestFeed -v`
- **After every plan wave:** Run `go test ./internal/firewalld/... -v`
- **Before `/gsd-verify-work`:** `go test ./... 2>&1 | grep -E "^(ok|FAIL)"` — same pre-existing failures allowed (dnssec build, TestResolver_Resolve, TestFindGlue), no new failures
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | FEED-01 | N/A | build | `grep -E "FeedURL\|PollInterval\|Timeout\|TLSSkipVerify\|AuthToken\|Headers" internal/firewalld/config.go && go build ./...` | ✅ | ⬜ pending |
| 03-01-02 | 01 | 1 | FEED-03 | N/A | build | `grep -A6 "RemoveIPScore" internal/firewalld/threat_intel.go && go build ./...` | ✅ | ⬜ pending |
| 03-02-01 | 02 | 2 | FEED-02, FEED-03, FEED-04 | AuthToken never in logs | build + grep | `go build ./internal/firewalld/... && grep -n "AuthToken" internal/firewalld/feed.go \| grep -v "Bearer\|set\|not set\|zeroValue"` | ❌ W0 | ⬜ pending |
| 03-03-01 | 03 | 3 | FEED-01, FEED-02 | N/A | build | `grep -n "StartFeed" internal/server/server.go && go build ./...` | ✅ | ⬜ pending |
| 03-03-02 | 03 | 3 | FEED-01, FEED-02, FEED-03, FEED-04 | Error paths don't crash | unit | `go test ./internal/firewalld/... -run "TestFeedConfig\|TestFeedClient_Lifecycle\|TestFeedClient_Apply\|TestFeedClient_ErrorHandling\|TestThreatIntel_RemoveIPScore" -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/firewalld/feed_test.go` — covers FEED-01 through FEED-04 + RemoveIPScore (created in Plan 03-03 Wave 3)
- [ ] No framework install needed — `go test` built in, testify already in go.mod

*Note: feed_test.go is created in Wave 3 (Plan 03-03). Waves 1 and 2 use go build + grep verification, which is appropriate for pure additions with no existing test file.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
