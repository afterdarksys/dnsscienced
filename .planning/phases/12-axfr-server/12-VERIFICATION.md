---
phase: 12-axfr-server
verified: 2026-05-23T00:00:00Z
status: passed
score: 9/9 must-haves verified
overrides_applied: 0
---

# Phase 12: AXFR Server Verification Report

**Phase Goal:** Implement RFC 5936 AXFR zone transfer server with TSIG authentication and per-zone allow_transfer ACL enforcement
**Verified:** 2026-05-23
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | AXFR request over TCP returns opening SOA + all RRs + closing SOA | VERIFIED | `axfr.go` lines 95-109: channel-driven streaming sends `z.SOA`, batched `z.GetAllRecords()`, `z.SOA`; `TestHandleAXFR_Success_StreamsSOA` PASS |
| 2 | AXFR request signed with a known TSIG key is accepted and transfer proceeds | VERIFIED | `axfr.go` lines 35-50: TSIG presence + validity guards; `TestHandleAXFR_Success_StreamsSOA` verifies `w.closed == true` (transfer path entered) |
| 3 | AXFR request with no TSIG is rejected with NOTAUTH (rcode 9) | VERIFIED | `axfr.go` lines 35-41: `r.IsTsig() == nil` → `RcodeNotAuth`; `TestHandleAXFR_NoTSIG_NotAuth` PASS |
| 4 | AXFR request from IP not in allow_transfer receives REFUSED (rcode 5) | VERIFIED | `axfr.go` lines 75-82: `!acl.Check(clientIP)` → `RcodeRefused`; `TestHandleAXFR_IPNotAllowed_Refused` PASS |
| 5 | AXFR over UDP returns TC=1 truncation flag, not REFUSED | VERIFIED | `axfr.go` lines 24-30: `*net.UDPAddr` check → `m.Truncated = true`; `TestHandleAXFR_UDPTruncation` PASS |
| 6 | Empty allow_transfer list means REFUSED (secure-by-default) | VERIFIED | `server.go` lines 319-322: empty CIDR list stores `nil` in `zoneTransferACLs`; `axfr.go` line 76: `acl == nil` → REFUSED; `TestHandleAXFR_EmptyAllowTransfer_Refused` PASS |
| 7 | Zone transfer CIDRs from config.yaml are available to the AXFR handler at runtime | VERIFIED | `main.go` lines 147-156: iterates `loadedCfg.Zones`, normalizes to FQDN, populates `cfg.ZoneTransferCIDRs` |
| 8 | TSIG keys from config.yaml tsig_keys section are loaded into the server's KeyRing | VERIFIED | `main.go` lines 162-169: field-by-field copy from `config.TsigKeyConfig` to `tsig.KeyConfig`; `go build ./...` exits 0 |
| 9 | Full build passes with all wiring in place | VERIFIED | `go build ./...` exits 0; `go test ./internal/server/... -count=1` exits 0 |

**Score:** 9/9 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/server/axfr.go` | handleAXFR method — guard chain + dns.Transfer.Out streaming | VERIFIED | 113 lines; implements all 7 guards in correct order; uses `dns.Transfer`, `dns.Envelope`; calls `w.Close()` |
| `internal/server/axfr_test.go` | 7 unit tests covering all XFER requirement scenarios | VERIFIED | 281 lines; 7 test functions; all PASS |
| `internal/server/server.go` | ZoneTransferCIDRs config field, zoneTransferACLs server field, ACL init in New(), TypeAXFR early dispatch | VERIFIED | Field at line 70; server field at line 162; ACL init at lines 319-330; dispatch at lines 527-537 (before defensive check at 540) |
| `cmd/dnsscienced/main.go` | ZoneTransferCIDRs and TsigKeys wiring from config.Config to server.Config | VERIFIED | ZoneTransferCIDRs wiring at lines 147-156; TsigKeys wiring at lines 162-169 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `server.go handleDNS` | `axfr.go handleAXFR` | `r.Question[0].Qtype == dns.TypeAXFR` early dispatch | WIRED | Line 527 in server.go confirms dispatch, positioned before pool.GetMessage() and before defensive check |
| `axfr.go` | `dsync.SourceACL` | `acl.Check(clientIP)` for allow_transfer ACL | WIRED | Lines 75-82 in axfr.go; `s.zoneTransferACLs[qname]` returns `*dsync.SourceACL` set in New() |
| `axfr.go` | `zone.Zone` | `z.GetAllRecords()` + `z.SOA` for transfer content | WIRED | Lines 96-109 in axfr.go; direct struct field access confirmed |
| `main.go` | `server.Config.ZoneTransferCIDRs` | `cfg.ZoneTransferCIDRs` populated from `loadedCfg.Zones[].AllowTransfer` | WIRED | `main.go` lines 147-156 |
| `main.go` | `server.Config.TsigKeys` | `cfg.TsigKeys` populated from `loadedCfg.TsigKeys` | WIRED | `main.go` lines 162-169 |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `axfr.go` | `z.SOA`, `z.GetAllRecords()` | `s.cfg.Zones[qname]` — loaded from disk at startup | Yes — zone loaded from actual zone files; `GetAllRecords()` iterates `z.Records` map | FLOWING |
| `axfr.go` | `acl` | `s.zoneTransferACLs[qname]` — built from `cfg.ZoneTransferCIDRs` in `New()` | Yes — populated from config.yaml `allow_transfer` via `main.go` wiring | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| All 7 AXFR tests pass | `go test ./internal/server/... -run TestHandleAXFR -v -count=1` | 7/7 PASS | PASS |
| Full server test suite (no regressions) | `go test ./internal/server/... -count=1` | ok (0.411s) | PASS |
| dsync and tsig package tests | `go test ./internal/dsync/... ./internal/tsig/... -count=1` | ok dsync (10.4s); ok tsig (0.6s) | PASS |
| Full project build | `go build ./...` | exits 0 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| XFER-01 | 12-01, 12-02 | Server responds to AXFR requests with complete zone contents in correct wire format (RFC 5936) — SOA + all RRs + SOA | SATISFIED | `axfr.go` streaming: opening SOA + batched RRs via `GetAllRecords()` + closing SOA; `TestHandleAXFR_Success_StreamsSOA` PASS |
| XFER-02 | 12-01, 12-02 | AXFR transfers are TSIG-authenticated; unsigned requests rejected | SATISFIED | `axfr.go` lines 35-50: TSIG presence guard (NOTAUTH) + TSIG validity guard (NOTAUTH); TSIG keys wired from config in `main.go`; tests for no-TSIG and bad-TSIG pass |
| XFER-03 | 12-01, 12-02 | AXFR access controlled by per-zone allow_transfer ACL; unlisted sources get REFUSED | SATISFIED | `axfr.go` lines 75-82: `acl == nil || !acl.Check(clientIP)` → REFUSED; `zoneTransferACLs` built from `ZoneTransferCIDRs` in `New()`; ACL data wired from config.yaml in `main.go`; tests for IP-not-allowed and empty-allowlist pass |

All 3 XFER requirements verified. REQUIREMENTS.md traceability table marks all 3 as Complete.

### Anti-Patterns Found

None detected. Scanned:
- `internal/server/axfr.go` — no TODOs, no stubs, no empty returns unrelated to guard chain
- `internal/server/axfr_test.go` — no placeholder tests; all 7 asserts real behavior
- `cmd/dnsscienced/main.go` (modified sections) — no hardcoded empty values; wiring is real

### Human Verification Required

None. All behaviors are verifiable programmatically. Full test suite passes.

### Gaps Summary

No gaps. All must-haves from both plans are verified against the actual codebase.

---

_Verified: 2026-05-23_
_Verifier: Claude (gsd-verifier)_
