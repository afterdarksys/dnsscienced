---
phase: 11
slug: resolver-behaviors
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-22
updated: 2026-05-23
---

# Phase 11 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — go test is built-in |
| **Quick run command** | `go test ./internal/resolver/... ./internal/cache/...` |
| **Full suite command** | `go test -race ./internal/resolver/... ./internal/cache/... ./internal/config/...` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/resolver/... ./internal/cache/...`
- **After every plan wave:** Run `go test -race ./internal/resolver/... ./internal/cache/... ./internal/config/...`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Secure Behavior | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------------|-----------|-------------------|--------|
| 11-01-01 | 01 | 1 | RESOLVE-01 | Minimized QNAME per delegation | unit | `go test ./internal/resolver/... -run TestQNAMEMin -count=1` | ✅ green |
| 11-01-02 | 01 | 1 | RESOLVE-01 | RFC 9156 qtype=A at intermediate hops | unit | `go test ./internal/resolver/... -run TestQNAMEMin -count=1` | ✅ green |
| 11-02-01 | 02 | 2 | RESOLVE-02 | NSEC synthesis without upstream query | unit | `go test ./internal/cache/... -run TestNSEC -count=1` | ✅ green |
| 11-02-02 | 02 | 2 | RESOLVE-02 | NSEC3 synthesis via Cover() | unit | `go test ./internal/cache/... -run TestNSECCache_Store_NSEC3 -count=1` | ✅ green |
| 11-03-01 | 03 | 2 | RESOLVE-03 | Stale entry served when upstream fails | unit | `go test ./internal/resolver/... -run TestServeStale -count=1` | ✅ green |
| 11-03-02 | 03 | 2 | RESOLVE-03 | TTL=0 on stale responses | unit | `go test ./internal/resolver/... -run TestServeStale -count=1` | ✅ green |
| 11-03-03 | 03 | 2 | RESOLVE-03 | Stale bounded by stale_max_ttl | unit | `go test ./internal/resolver/... -run TestServeStale_BeyondMaxStaleTTL -count=1` | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No framework installation needed — go test is already in use throughout the project.

- [x] Stub test functions for QNAME minimization in `internal/resolver/recursive_test.go` (TestQNAMEMinimization_ConfigFlag, TestQNAMEMinimization_DisabledByDefault)
- [x] Stub test functions for NSEC3 synthesis in `internal/cache/nsec_test.go` (TestNSECCache_Store_NSEC3, TestNSECCache_SynthesizeNXDOMAIN_NSEC3)
- [x] Stub test functions for serve-stale in `internal/resolver/recursive_test.go` (TestServeStale_ExpiredEntry, TestServeStale_TTLRewrittenToZero, TestServeStale_BeyondMaxStaleTTL, TestServeStale_Disabled)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end QNAME minimization with real DNS | RESOLVE-01 | Non-hermetic; pre-existing TestResolver_Resolve failure | Start server, use `dig +qmin @127.0.0.1` to verify minimized queries in Wireshark/tcpdump |

---

## Validation Sign-Off

- [x] All tasks have automated verify commands
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 stubs created before Wave 1/2 implementation
- [x] No watch-mode flags
- [x] Feedback latency < 10s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** complete — Phase 14 Plan 02 Task 2 (2026-05-23)
