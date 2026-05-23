# Phase 12: AXFR Server - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-23
**Phase:** 12-axfr-server
**Areas discussed:** Empty allow_transfer default, Per-zone TSIG requirement, AXFR handler placement, AXFR dispatch in handleDNS, Multi-message streaming, UDP AXFR behavior

---

## Empty allow_transfer Default

| Option | Description | Selected |
|--------|-------------|----------|
| REFUSED | No allow_transfer = no transfers permitted. Secure-by-default; RFC 2182 guidance. | ✓ |
| Allow all | No allow_transfer = open to all. Mirrors DSYNC SourceACL D-05. | |

**User's choice:** REFUSED (Recommended)
**Notes:** Deliberate inversion of DSYNC SourceACL pattern — zone transfer exposure warrants the stricter default.

---

## Per-zone TSIG Requirement

| Option | Description | Selected |
|--------|-------------|----------|
| Always required | TSIG mandatory globally. No new config field. | ✓ |
| New tsig_key field in ZoneConfig | Per-zone key name; empty = no requirement. | |
| require_tsig bool in ZoneConfig | Explicit per-zone opt-in. | |

**User's choice:** Always required (Recommended)
**Notes:** No new config field needed. Simplest model, strongest posture.

---

## TSIG Error Response Code

| Option | Description | Selected |
|--------|-------------|----------|
| NOTAUTH (rcode 9) | RFC 2845 §4 — distinguishes auth failure from policy refusal. | ✓ |
| REFUSED for both | Simpler; consistent with IP ACL response. | |

**User's choice:** NOTAUTH (rcode 9) (Recommended)
**Notes:** Secondaries need to distinguish auth failure (retry with correct key) from access-control refusal (not whitelisted).

---

## miekg/dns TSIG Verification Flow

| Option | Description | Selected |
|--------|-------------|----------|
| You decide | Claude/planner determines how to detect TSIG presence/failure. | ✓ |
| I know the answer | User provides knowledge for planner. | |

**User's choice:** You decide
**Notes:** miekg/dns auto-verifies TSIG when TsigSecret is populated; planner must determine how to check for TSIG absence (miekg/dns verifies present TSIG but doesn't reject missing TSIG).

---

## AXFR Handler Placement

| Option | Description | Selected |
|--------|-------------|----------|
| Inline in internal/server/ | New axfr.go in server package. AXFR lacks DSYNC's rate limiting / webhook / metrics complexity. | ✓ |
| New internal/axfr/ package | Mirrors internal/dsync/ isolation. | |

**User's choice:** Inline in internal/server/ (Recommended)
**Notes:** DSYNC warranted its own package; AXFR's scope is narrow enough to stay in server/.

---

## AXFR Dispatch in handleDNS

| Option | Description | Selected |
|--------|-------------|----------|
| Early dispatch, before pool/defensive | TypeAXFR check at top of handleDNS. Same pattern as NOTIFY. | ✓ |
| Inline in authoritative path | After zone lookup; pool.GetMessage() already called. | |

**User's choice:** Early dispatch, before pool/defensive (Recommended)
**Notes:** AXFR must stream multiple messages — must exit before pool.GetMessage() to avoid the single-response model.

---

## Multi-Message Streaming

| Option | Description | Selected |
|--------|-------------|----------|
| Multi-message, RFC-compliant | Each message independently TSIG-signed; required for production zones. | ✓ |
| Single message | Simpler; fails for zones > ~64KB. | |

**User's choice:** Multi-message, RFC-compliant (Recommended)
**Notes:** RFC 5936 §2.2 requires independent TSIG signing per message for large zones.

---

## UDP AXFR Behavior

| Option | Description | Selected |
|--------|-------------|----------|
| TC=1 (truncated) | RFC 5936 §4.2 — clients auto-retry over TCP. | ✓ |
| REFUSED | Simpler; clients won't auto-retry. | |

**User's choice:** TC=1 (truncated) (Recommended)
**Notes:** TC=1 is the standard DNS signal; well-behaved secondaries retry over TCP automatically.

---

## Claude's Discretion

- How the handler detects TSIG presence/absence in miekg/dns messages (r.IsTsig() or checking r.Extra)
- Message batching strategy for multi-message streaming (RR count vs. byte budget per message)
- ZoneConfig lookup by zone origin at dispatch time (may need indexed map at startup)

## Deferred Ideas

- IXFR server (RFC 1995) — requires change journal; already in REQUIREMENTS.md v2 backlog as XFER-04
- NOTIFY-on-transfer (also_notify) — out of scope for this phase
- Per-zone TSIG key binding (restricting zone to specific named key) — could be follow-up
- Catalog zones (RFC 9432) — already in v2 backlog as XFER-05
