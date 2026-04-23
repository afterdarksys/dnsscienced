---
phase: 4
slug: edns0-customerid
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-23
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `testing` (stdlib) + `testify` v1 |
| **Config file** | none — `go test ./...` |
| **Quick run command** | `go test ./internal/firewalld/... -v -run TestEdns0\|TestExtractCustomerID\|TestFirewall_CustomerID` |
| **Full suite command** | `go test ./internal/firewalld/...` |
| **Estimated runtime** | ~2 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/firewalld/... -run TestEdns0\|TestExtractCustomerID\|TestFirewall_CustomerID`
- **After every plan wave:** Run `go test ./internal/firewalld/...`
- **Before `/gsd-verify-work`:** `go test ./...` must be green (excluding pre-existing failures)
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 4-01-01 | 01 | 1 | CUST-01 | T-04-01 | Option 65000 returns correct CustomerID string | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_Present` | Wave 0 | ⬜ pending |
| 4-01-02 | 01 | 1 | CUST-03 | — | No OPT record returns empty string | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_NoOPT` | Wave 0 | ⬜ pending |
| 4-01-03 | 01 | 1 | CUST-03 | — | Wrong option code returns empty string | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_WrongCode` | Wave 0 | ⬜ pending |
| 4-01-04 | 01 | 1 | CUST-01 | T-04-01 | Oversized payload (>64 bytes) returns empty string + debug log | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_Oversized` | Wave 0 | ⬜ pending |
| 4-01-05 | 01 | 1 | CUST-02 | — | Check() populates qctx.CustomerID before evaluation | integration | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDExtracted` | Wave 0 | ⬜ pending |
| 4-01-06 | 01 | 1 | CUST-02 | — | CustomerID visible to ThreatIntel trust bonus | integration | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDTrustBonus` | Wave 0 | ⬜ pending |
| 4-01-07 | 01 | 1 | CUST-03 | — | Check() proceeds normally with no EDNS0 option | integration | `go test ./internal/firewalld/... -run TestFirewall_NoCustomerID_Allowed` | Wave 0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/firewalld/firewalld_test.go` — add `makeQueryWithCustomerID` test helper and unit tests for `extractCustomerID`
- [ ] `internal/firewalld/firewalld_test.go` — integration tests: `TestFirewall_CustomerIDExtracted`, `TestFirewall_CustomerIDTrustBonus`, `TestFirewall_NoCustomerID_Allowed`

*Existing infrastructure (`go test`, `testify`) covers all phase requirements — no installation needed.*

---

## Manual-Only Verifications

All phase behaviors have automated verification.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
