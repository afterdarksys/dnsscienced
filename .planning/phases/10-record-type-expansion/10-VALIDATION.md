---
phase: 10
slug: record-type-expansion
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-21
updated: 2026-05-23
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
| 10-01-01 | 01 | 1 | RRTYPE-03 | — | Parse SSHFP rejects invalid algorithm/type codes | unit | `go test ./internal/zone/... -run 'TestParseDNSZone_SSHFP\|TestParseBIND_SSHFP\|TestRoundTrip_SSHFP' -count=1` | YES | ✅ green |
| 10-01-02 | 01 | 1 | RRTYPE-04 | — | Parse NAPTR with empty regexp field | unit | `go test ./internal/zone/... -run 'TestParseDNSZone_NAPTR\|TestParseBIND_NAPTR\|TestRoundTrip_NAPTR' -count=1` | YES | ✅ green |
| 10-01-03 | 01 | 1 | RRTYPE-05 | — | Parse SMIMEA reusing TLSARecord struct | unit | `go test ./internal/zone/... -run 'TestParseDNSZone_SMIMEA\|TestParseBIND_SMIMEA\|TestRoundTrip_SMIMEA' -count=1` | YES | ✅ green |
| 10-01-04 | 01 | 1 | RRTYPE-06 | — | Parse LOC as string passthrough | unit | `go test ./internal/zone/... -run 'TestParseDNSZone_LOC\|TestParseBIND_LOC\|TestRoundTrip_LOC' -count=1` | YES | ✅ green |
| 10-02-01 | 02 | 1 | RRTYPE-07 | — | Round-trip all new types compile→decompile | unit | `go test ./internal/zone/... -run TestRoundTrip -count=1` | YES | ✅ green |
| 10-02-02 | 02 | 1 | RRTYPE-08 | — | Query returns NOERROR for unknown new types | manual | No unit test — server-level behavior verified by integration testing and code review (server.go:790-793 type-agnostic NODATA path; returns RcodeSuccess for HasName+no records for any record type) | N/A | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `internal/zone/parser_dnszone_test.go` — test stubs for SSHFP, NAPTR, SMIMEA, LOC parsing (RRTYPE-03, RRTYPE-04, RRTYPE-05, RRTYPE-06)
- [x] `internal/zone/roundtrip_test.go` (parser_dnszone_test.go) — round-trip tests for all new record types (RRTYPE-07)

*Existing go test infrastructure covers the framework — test stubs confirmed added and passing.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| RRTYPE-08: Query for in-zone name with no records returns NOERROR+empty | RRTYPE-08 | No unit test — server-level type-agnostic path; code-review confirmed | server.go:790-793 handleAuthoritative() returns RcodeSuccess for HasName+no records; covers all record types including new ones |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or manual-only rationale
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** complete — Phase 14 Plan 02 Task 2 (2026-05-23)
