---
phase: 10
slug: record-type-expansion
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-21
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — existing infrastructure |
| **Quick run command** | `go test ./internal/zone/... -count=1` |
| **Full suite command** | `go test ./... -count=1` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/zone/... -count=1`
- **After every plan wave:** Run `go test ./... -count=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 1 | RRTYPE-03 | — | Parse SSHFP rejects invalid algorithm/type codes | unit | `go test ./internal/zone/... -run TestSSHFP -count=1` | ❌ W0 | ⬜ pending |
| 10-01-02 | 01 | 1 | RRTYPE-04 | — | Parse NAPTR with empty regexp field | unit | `go test ./internal/zone/... -run TestNAPTR -count=1` | ❌ W0 | ⬜ pending |
| 10-01-03 | 01 | 1 | RRTYPE-05 | — | Parse SMIMEA reusing TLSARecord struct | unit | `go test ./internal/zone/... -run TestSMIMEA -count=1` | ❌ W0 | ⬜ pending |
| 10-01-04 | 01 | 1 | RRTYPE-06 | — | Parse LOC as string passthrough | unit | `go test ./internal/zone/... -run TestLOC -count=1` | ❌ W0 | ⬜ pending |
| 10-02-01 | 02 | 1 | RRTYPE-07 | — | Round-trip all 6 new types compile→decompile | unit | `go test ./internal/zone/... -run TestRoundTrip -count=1` | ❌ W0 | ⬜ pending |
| 10-02-02 | 02 | 1 | RRTYPE-08 | — | Query returns NOERROR for unknown new types | unit | `go test ./... -run TestQuery -count=1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/zone/parser_dnszone_test.go` — add test stubs for SSHFP, NAPTR, SMIMEA, LOC parsing (RRTYPE-03, RRTYPE-04, RRTYPE-05, RRTYPE-06)
- [ ] `internal/zone/roundtrip_test.go` — add round-trip test stubs for all 6 new record types (RRTYPE-07)

*Existing go test infrastructure covers the framework — only test stubs need to be added.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| BIND zone file with all 6 types loads without errors | RRTYPE-01 | Requires a fixture BIND zone file; miekg/dns delegation tested indirectly | Run `go test ./internal/zone/... -run TestBINDZoneLoad -v` with fixture |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
