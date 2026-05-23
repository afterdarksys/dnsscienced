# Security Audit — Phase 12: AXFR Server

**Audit Date:** 2026-05-23
**Phase:** 12 — axfr-server
**Plans Audited:** 12-01, 12-02
**ASVS Level:** 2
**Auditor:** gsd-security-auditor (automated)
**Result:** SECURED — 10/10 threats closed

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-12-01 | Spoofing | mitigate | CLOSED | `internal/server/axfr.go:35` — `r.IsTsig() == nil` returns NOTAUTH before `w.TsigStatus()` check at line 44; ordering is correct and deliberate |
| T-12-02 | Information Disclosure | mitigate | CLOSED | `internal/server/server.go:327-338` — `s.zoneTransferACLs` built from `ZoneTransferCIDRs`; empty slice stored as nil (deny-all). `internal/server/axfr.go:76` — `acl == nil` guard returns REFUSED before any zone data is accessed |
| T-12-03 | Information Disclosure | mitigate | CLOSED | `internal/server/axfr.go:76-82` — ACL check and REFUSED response occur before streaming block begins at line 103; no zone data is accessed or streamed on ACL failure |
| T-12-04 | Spoofing | accept | CLOSED | See Accepted Risks below |
| T-12-05 | Denial of Service | accept | CLOSED | See Accepted Risks below |
| T-12-06 | Tampering | mitigate | CLOSED | `internal/server/server.go:353,367` — `dns.Server.TsigSecret` populated via `s.tsigSecretMap()` for both UDP and TCP servers; miekg/dns `Transfer.Out` uses the same `ResponseWriter` which carries the TsigSecret and automatically signs each outgoing AXFR message when the request had TSIG |
| T-12-07 | Information Disclosure | mitigate | CLOSED | `internal/server/axfr.go:24-30` — `w.RemoteAddr().(*net.UDPAddr)` type assertion; sets `m.Truncated = true` and returns immediately; no zone data or answer section sent on UDP |
| T-12-08 | Tampering | mitigate | CLOSED | `cmd/dnsscienced/main.go:165-169` — field-by-field copy (Name, Algorithm, Secret) into `tsig.KeyConfig`; no `fmt.Print`, `log`, or `fmt.Sprintf` statement references the Secret field anywhere in main.go |
| T-12-09 | Information Disclosure | mitigate | CLOSED | `cmd/dnsscienced/main.go:152-154` — `strings.HasSuffix(zoneName, ".")` guard appends trailing dot; zone map key is always FQDN-normalized before insertion into `ZoneTransferCIDRs`, preventing lookup mismatch ACL bypass |
| T-12-10 | Elevation of Privilege | mitigate | CLOSED | `cmd/dnsscienced/main.go:162-170` — `cfg.TsigKeys = make([]tsig.KeyConfig, len(loadedCfg.TsigKeys))` wiring block present inside `if *configFile != ""` branch; TSIG keys from config file reach `server.New()` which loads them into the KeyRing at `server.go:308-315` |

---

## Accepted Risks

### T-12-04 — Spoofing: TSIG Replay

**Category:** Spoofing
**Component:** handleAXFR TSIG replay protection
**Rationale:** The miekg/dns library's `TsigVerify` function enforces a 300-second timestamp fudge window by default. AXFR requests carrying a TSIG with a timestamp outside that window are rejected with a TSIG error, which `handleAXFR` maps to NOTAUTH at `axfr.go:44-49`. This is an industry-standard mitigation implemented by the cryptographic library. No application-layer replay counter is added; the library behavior is sufficient for ASVS Level 2.

**Residual risk:** An attacker who captures a valid AXFR request can replay it within the 300-second window. The impact is limited to receiving zone data the attacker was already authorized to receive (same TSIG key, same allowed IP). Acceptable.

---

### T-12-05 — Denial of Service: AXFR Flood

**Category:** Denial of Service
**Component:** handleAXFR — zone transfer flood
**Rationale:** The guard chain in `handleAXFR` (axfr.go:24-82) exits before initiating any streaming on ACL or TSIG failure. An unauthenticated or unauthorized attacker cannot trigger expensive zone serialization. For authenticated callers, zone transfer is inherently resource-intensive but is gated behind TSIG authentication and per-zone ACL. Existing Rate Response Limiting (RRL) via `rrl.Limiter` (server.go:256-257) covers general query rate. A per-transfer rate limiter is not implemented; this risk is accepted at ASVS Level 2 given the TSIG+ACL gating.

**Residual risk:** An authorized secondary with a valid TSIG key and allowed IP could trigger repeated full-zone transfers. Monitoring and alerting on transfer volume is recommended at operational level.

---

## Unregistered Threat Flags

The SUMMARY.md files for Plans 01 and 02 explicitly state "No new threat surface beyond what is documented in the plan's threat model." No unregistered flags were raised.

---

## Verification Methods

All `mitigate` threats verified by direct grep match in the cited implementation files. Ordering constraints (e.g., T-12-01 TSIG presence before validity) verified by reading surrounding code context. No mitigation accepted on documentation alone.

---

## Files Audited

- `internal/server/axfr.go` — primary handler implementation
- `internal/server/server.go` — Config struct, Server struct, New(), handleDNS dispatch
- `cmd/dnsscienced/main.go` — ZoneTransferCIDRs and TsigKeys wiring
- `.planning/phases/12-axfr-server/12-01-PLAN.md` — threat model source (Plans 01)
- `.planning/phases/12-axfr-server/12-02-PLAN.md` — threat model source (Plans 02)
- `.planning/phases/12-axfr-server/12-01-SUMMARY.md` — executor threat surface scan
- `.planning/phases/12-axfr-server/12-02-SUMMARY.md` — executor threat surface scan
