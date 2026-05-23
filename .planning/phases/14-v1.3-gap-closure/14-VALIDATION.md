---
phase: 14
slug: v1-3-gap-closure
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-23
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — existing Go test infrastructure |
| **Quick run command** | `go test ./internal/resolver/... -count=1 -timeout 30s` |
| **Full suite command** | `go test ./internal/... -count=1 -timeout 60s` |
| **Estimated runtime** | ~30 seconds (quick), ~60 seconds (full) |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/resolver/... -count=1 -timeout 30s`
- **After every plan wave:** Run `go test ./internal/... -count=1 -timeout 60s`
- **Before `/gsd-verify-work`:** Full suite must be green (excluding pre-existing failures: TestFindGlue, TestResolver_Resolve)
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 14-01 | 1 | RESOLVE-01, RESOLVE-02, RESOLVE-03 | — | N/A | unit+config | `go build ./... && go test ./internal/resolver/... -run TestQNAMEMin -count=1 && go test ./internal/config/... -count=1` | ✅ | ⬜ pending |
| 14-01-02 | 14-01 | 1 | RESOLVE-03 | — | N/A | unit | `go test ./internal/resolver/... -run TestGetTTL -count=1 -v` | ✅ | ⬜ pending |
| 14-01-03 | 14-01 | 1 | RRTYPE-01, RRTYPE-02 | — | N/A | docs | `grep -c '\[x\] \*\*RRTYPE-01\*\*' .planning/REQUIREMENTS.md` | ✅ | ⬜ pending |
| 14-02-01 | 14-02 | 2 | RRTYPE-01, RRTYPE-02 | — | N/A | regression | `go test ./internal/zone/... -count=1` | ✅ | ⬜ pending |
| 14-02-02 | 14-02 | 2 | RESOLVE-01, RESOLVE-02, RESOLVE-03 | — | N/A | validation | `go test ./internal/zone/... -run 'TestParseDNSZone_SSHFP\|TestParseBIND_SSHFP' -count=1 && grep 'nyquist_compliant: true' .planning/phases/10-record-type-expansion/10-VALIDATION.md` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test stubs needed — this phase fixes config wiring, a test expected-value regression, and documentation/validation tracking.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| REQUIREMENTS.md checkboxes reflect actual status | RRTYPE-01..08 | Documentation audit, not code | Read REQUIREMENTS.md; confirm RRTYPE-01..08 all `[x]`; confirm no checkbox contradicts Phase 10 VERIFICATION.md |
| config.example.yaml resolver section uses correct YAML keys | RESOLVE-02 | Config file validation | Read config.example.yaml; confirm `qname_minimization`, `aggressive_nsec`, `serve_stale`, `stale_max_ttl` present under recursive block |
| Phase 10 VALIDATION.md row 10-02-02 (RRTYPE-08 / NOERROR behavior) | RRTYPE-02 | No zone-package unit test for this server-level behavior | `grep -q 'manual-only' .planning/phases/10-record-type-expansion/10-VALIDATION.md` confirms manual designation |

---

## Validation Architecture

### Wave 1 (Config + Test Fix + Docs)
- `go test ./internal/server/... -count=1` — verifies DefaultConfig embeds resolver.DefaultConfig()
- `go test ./internal/resolver/... -run TestGetTTL -count=1` — verifies expected value is 300
- `go test ./internal/config/... -count=1` — verifies config parsing with corrected YAML keys

### Wave 2 (Verification + Nyquist)
- `go test ./internal/zone/... -count=1` — Phase 10 re-verification base
- `go test ./internal/resolver/... -count=1` — Phase 11 Nyquist baseline

### Pre-existing failures to exclude
- `TestFindGlue` — IPv6 bracket formatting issue (pre-existing, documented in STATE.md)
- `TestResolver_Resolve` — network-dependent (pre-existing, documented in STATE.md)

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
