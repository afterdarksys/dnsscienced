---
phase: 12-axfr-server
plan: 01
subsystem: dns
tags: [axfr, zone-transfer, tsig, acl, rfc5936, miekg-dns]

requires:
  - phase: 06-admin-hardening
    provides: tsig.KeyRing for TSIG key management
  - phase: 08-rfc9859-dsync
    provides: dsync.SourceACL for per-zone CIDR ACL enforcement

provides:
  - AXFR server handler (RFC 5936) with TSIG auth and per-zone allow_transfer ACL
  - ZoneTransferCIDRs config field for per-zone CIDR lists
  - zoneTransferACLs server field (nil entry = deny all, secure-by-default)
  - Early AXFR dispatch in handleDNS before pool.GetMessage()
  - 7 unit tests covering all XFER trust boundary scenarios

affects:
  - phase 13 (dynamic DNS updates — same dispatch pattern and ACL approach)
  - main.go (needs to populate ZoneTransferCIDRs from ZoneConfig.AllowTransfer)

tech-stack:
  added: []
  patterns:
    - "Early opcode dispatch in handleDNS before pool acquisition (NOTIFY and now AXFR)"
    - "Nil ACL = deny all (secure-by-default D-01) — do NOT call NewSourceACL with empty slice"
    - "TSIG presence check before validity check (absent TSIG gives TsigStatus()==nil)"
    - "dns.Transfer.Out channel-driven streaming with opening SOA + batched RRs + closing SOA"

key-files:
  created:
    - internal/server/axfr.go
    - internal/server/axfr_test.go
  modified:
    - internal/server/server.go

key-decisions:
  - "nil ACL in zoneTransferACLs means deny all (D-01 secure-by-default) — not allowAll"
  - "TSIG presence checked BEFORE validity: r.IsTsig()==nil before w.TsigStatus() — absent TSIG yields TsigStatus()==nil which would silently accept unsigned requests"
  - "UDP AXFR returns TC=1 truncation flag, not REFUSED — RFC-compliant clients retry over TCP"
  - "AXFR dispatched before pool.GetMessage() — AXFR streams multiple messages and cannot use pooled single-response path"

requirements-completed: [XFER-01, XFER-02, XFER-03]

duration: 3min
completed: 2026-05-23
---

# Phase 12 Plan 01: AXFR Server Summary

**RFC 5936 AXFR handler with TSIG auth (NOTAUTH on absent/bad TSIG), per-zone CIDR ACL (nil=deny-all), UDP truncation (TC=1), and dns.Transfer.Out multi-message streaming**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-05-23T12:35:00Z
- **Completed:** 2026-05-23T12:38:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- `handleAXFR` method implements full RFC 5936 guard chain: UDP truncation, TSIG presence, TSIG validity, zone lookup, ACL check, then streaming
- `ZoneTransferCIDRs` config field and `zoneTransferACLs` server field added; nil ACL entry enforces D-01 secure-by-default (deny all when no allow_transfer configured)
- AXFR dispatched early in `handleDNS` before `pool.GetMessage()` — essential since Transfer.Out streams multiple messages
- 7 unit tests pass covering all XFER requirements (UDP truncation, TSIG auth, IP ACL, zone lookup, empty-ACL denial, success path)

## Task Commits

Each task was committed atomically:

1. **Task 1: Config field, Server field, ACL init, AXFR dispatch** - `69a3589` (feat)
2. **Task 2: handleAXFR full implementation** - `fe55304` (feat)
3. **Task 3: AXFR test suite** - `74a6a00` (test)

## Files Created/Modified
- `internal/server/axfr.go` - handleAXFR method: guard chain + dns.Transfer.Out streaming
- `internal/server/axfr_test.go` - 7 unit tests covering all XFER trust boundary scenarios
- `internal/server/server.go` - ZoneTransferCIDRs config field, zoneTransferACLs server field, ACL init in New(), TypeAXFR early dispatch in handleDNS

## Decisions Made
- nil ACL in `zoneTransferACLs` means deny all (D-01 secure-by-default): empty CIDR list sets nil, not allowAll
- TSIG presence checked BEFORE validity: `r.IsTsig()==nil` guard must come first — absent TSIG yields `w.TsigStatus()==nil` which would silently accept unsigned requests
- UDP AXFR returns TC=1 (not REFUSED): RFC-compliant secondary DNS clients retry over TCP on TC=1
- AXFR early dispatch before pool.GetMessage(): dns.Transfer.Out streams multiple messages and cannot use the pooled single-response path

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Task 1 compilation required a stub `axfr.go` (handleAXFR stub) to pass `go build` before Task 2 full implementation — created minimal stub, committed Task 1, then replaced stub with full implementation in Task 2 commit. No functional impact.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- AXFR server handler complete; XFER-01, XFER-02, XFER-03 delivered
- main.go needs to populate `server.Config.ZoneTransferCIDRs` from `config.ZoneConfig.AllowTransfer` for production use (not in scope for this plan)
- Phase 13 (Dynamic DNS Updates) can follow the same early dispatch pattern in handleDNS

## Threat Surface Scan
No new threat surface beyond what is documented in the plan's threat model.

---
*Phase: 12-axfr-server*
*Completed: 2026-05-23*
