---
phase: 5
slug: redirect-load-balancing
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-23
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — standard Go test files |
| **Quick run command** | `go test ./internal/firewalld/... -count=1` |
| **Full suite command** | `go test -race ./internal/firewalld/... -count=1` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/firewalld/... -count=1`
- **After every plan wave:** Run `go test -race ./internal/firewalld/... -count=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 5-01-01 | 01 | 1 | REDIR-01 | — | N/A | unit | `go test ./internal/firewalld/... -run TestUpstreamPool -count=1` | ❌ W0 | ⬜ pending |
| 5-01-02 | 01 | 1 | REDIR-02 | — | N/A | unit | `go test ./internal/firewalld/... -run TestUpstreamPool_RoundRobin -count=1` | ❌ W0 | ⬜ pending |
| 5-01-03 | 01 | 1 | REDIR-02 | — | N/A | unit | `go test ./internal/firewalld/... -run TestUpstreamPool_Empty -count=1` | ❌ W0 | ⬜ pending |
| 5-01-04 | 01 | 1 | REDIR-03 | — | N/A | unit | `go test ./internal/firewalld/... -run TestStarlark_Redirect_Pool -count=1` | ❌ W0 | ⬜ pending |
| 5-01-05 | 01 | 1 | REDIR-04 | — | N/A | unit | `go test ./internal/firewalld/... -run TestPolicy_Redirect_Pool -count=1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/firewalld/forwarder_test.go` (or `firewalld_test.go`) — stubs for pool round-robin and empty-pool tests
- [ ] Test stubs for REDIR-03 (Starlark redirect uses pool) and REDIR-04 (static rule uses pool)

*Existing go test infrastructure in `internal/firewalld/firewalld_test.go` covers the baseline. Wave 0 adds new test stubs for pool behavior.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Alternating upstream addresses in query logs | REDIR-01 | Requires live DNS forwarder + log inspection | Start server with two upstreams; send repeated redirect queries; grep logs for alternating target addresses |
| Single-upstream config identical to prior behavior | REDIR-01 | Integration behavior | Configure one upstream; verify redirect queries still succeed end-to-end |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
