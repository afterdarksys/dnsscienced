---
phase: 13
slug: dynamic-dns-updates
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-23
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — standard Go test files |
| **Quick run command** | `go test ./internal/server/ ./internal/zone/ -run TestUpdate -count=1` |
| **Full suite command** | `go test ./... -count=1` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/server/ ./internal/zone/ -run TestUpdate -count=1`
- **After every plan wave:** Run `go test ./... -count=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | DYNUP-01 | — | N/A | unit | `go test ./internal/zone/ -run TestDelete -count=1` | ❌ W0 | ⬜ pending |
| 13-01-02 | 01 | 1 | DYNUP-01 | — | N/A | unit | `go test ./internal/zone/ -run TestClone -count=1` | ❌ W0 | ⬜ pending |
| 13-02-01 | 02 | 1 | DYNUP-02 | — | N/A | unit | `go test ./internal/server/ -run TestUpdatePrerequisites -count=1` | ❌ W0 | ⬜ pending |
| 13-02-02 | 02 | 1 | DYNUP-03 | T-13-01 | Unsigned UPDATE → NOTAUTH | unit | `go test ./internal/server/ -run TestUpdateTSIG -count=1` | ❌ W0 | ⬜ pending |
| 13-02-03 | 02 | 1 | DYNUP-04 | T-13-02 | IP not in allow_update → REFUSED | unit | `go test ./internal/server/ -run TestUpdateACL -count=1` | ❌ W0 | ⬜ pending |
| 13-03-01 | 03 | 2 | DYNUP-01 | — | N/A | integration | `go test ./internal/server/ -run TestUpdateIntegration -count=1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/server/update_test.go` — stubs for TSIG, ACL, prerequisite, and end-to-end UPDATE tests
- [ ] `internal/zone/zone_test.go` additions — stubs for DeleteRecord, DeleteRRSet, DeleteName methods

*Existing go test infrastructure covers the framework; only new test files needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| persist_updates=true writes YAML on disk after UPDATE | DYNUP-01 | Requires filesystem state inspection after live server update | Start server with persist_updates:true, send valid UPDATE, verify zone YAML file is updated on disk |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
