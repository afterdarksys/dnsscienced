---
phase: 12
slug: axfr-server
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-23
---

# Phase 12 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — existing Go test infrastructure |
| **Quick run command** | `go test ./internal/server/... -run TestHandleAXFR -v` |
| **Full suite command** | `go test ./... -count=1` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/server/... -run TestHandleAXFR -v`
- **After every plan wave:** Run `go test ./... -count=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 12-01-01 | 01 | 1 | XFER-01 | — | Full zone stream: SOA + all RRs + closing SOA | unit | `go test ./internal/server/... -run TestHandleAXFR_Success_StreamsSOA -v` | ✓ | ✅ green |
| 12-01-04 | 01 | 1 | XFER-01 | D-08 | UDP AXFR returns TC=1, no answer section | unit | `go test ./internal/server/... -run TestHandleAXFR_UDPTruncation -v` | ✓ | ✅ green |
| 12-01-02a | 01 | 1 | XFER-02 | D-04 | TSIG missing → NOTAUTH | unit | `go test ./internal/server/... -run TestHandleAXFR_NoTSIG_NotAuth -v` | ✓ | ✅ green |
| 12-01-02b | 01 | 1 | XFER-02 | D-05 | TSIG bad → NOTAUTH | unit | `go test ./internal/server/... -run TestHandleAXFR_BadTSIG_NotAuth -v` | ✓ | ✅ green |
| 12-01-05 | 01 | 1 | XFER-02 | D-01 | Empty allow_transfer → REFUSED (secure-by-default) | unit | `go test ./internal/server/... -run TestHandleAXFR_EmptyAllowTransfer_Refused -v` | ✓ | ✅ green |
| 12-01-03a | 01 | 1 | XFER-03 | D-03 | IP not in allow_transfer → REFUSED | unit | `go test ./internal/server/... -run TestHandleAXFR_IPNotAllowed_Refused -v` | ✓ | ✅ green |
| 12-01-03b | 01 | 1 | XFER-03 | — | Non-existent zone → REFUSED | unit | `go test ./internal/server/... -run TestHandleAXFR_NonExistentZone_Refused -v` | ✓ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `internal/server/axfr_test.go` — 7 tests covering XFER-01, XFER-02, XFER-03 (TCP transfer, TSIG enforcement, ACL enforcement, UDP TC=1, empty-ACL deny)
- [x] Existing `internal/server/` test helpers reused — no new infrastructure needed

*Existing `go test` infrastructure covers the phase; only new test file needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Per-message TSIG signing in multi-message stream | XFER-01/02 | Requires a real secondary DNS client (e.g., `dig axfr`) to inspect wire-level TSIG RRs on each envelope | Run `dig @localhost -p 5353 example.com AXFR` with a TSIG key and capture with `tcpdump` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** complete
