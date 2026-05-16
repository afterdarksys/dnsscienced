# Phase 8: RFC 9859 — Generalized DNS Notifications (DSYNC) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-16
**Phase:** 08-rfc9859-dsync
**Areas discussed:** post-notify-action, source-verification, outbound-trigger, rate-limit-config

---

## Post-Notify Action

| Option | Description | Selected |
|--------|-------------|----------|
| Log + Prometheus counter + webhook POST | All three on accepted NOTIFY | ✓ |
| Log only | Simple but no operator integration | |
| Prometheus counter only | Metrics without webhook | |

**User's choice:** Log + Prometheus counter + webhook POST
**Notes:** Webhook URL is per-zone; body is configurable (JSON default or raw base64 wire format); fire-and-forget, 5s timeout, no retry

---

## Source Verification

| Option | Description | Selected |
|--------|-------------|----------|
| Per-zone allowed_sources (CIDRs/IPs) | Allowlist in ZoneDSYNCConfig; absent = accept any | ✓ |
| Global allowlist | Single list for all zones | |
| No allowlist (rate limit only) | Trust all sources, rely on rate limiting | |

**User's choice:** Per-zone allowed_sources
**Notes:** Rejection code is REFUSED; rate limiting still applies to all accepted sources

---

## Outbound Trigger

| Question | Options | Selected |
|----------|---------|----------|
| What triggers outbound NOTIFY? | Admin RPC / Zone reload hook / File watcher | Admin RPC |
| Destination resolution | Live _dsync lookup / Config override / Both | Live DNS lookup |
| Retry behavior | Fire-and-forget / Single retry 5s / Exponential backoff 3x | Fire-and-forget |
| Transport | Separate dns.Client dialer / Reuse server socket | Separate dialer |

**Notes:** Operator calls `SendDSYNCNotify` RPC explicitly after updating CDS/CSYNC records. Destination resolved at send time via `_dsync.<parent>` query. Failure logged + error counter, no retry. Uses `dns.Client` separate from inbound server socket.

---

## Rate Limit Config

| Question | Options | Selected |
|----------|---------|----------|
| Scope | Per-source IP / Global / Per-zone per-source | Per-source IP |
| Default threshold | 5/min / 1/min / No default | 5 NOTIFY/min |
| Drop response code | REFUSED / Silent drop / SERVFAIL | REFUSED |
| Implementation | Separate in internal/dsync / Reuse internal/rrl | Separate in internal/dsync |

**Notes:** Token bucket via golang.org/x/time/rate (already in go.mod). Visitor map is `sync.Map[string]*rate.Limiter`. RRL not reused — different semantics (response volume vs. NOTIFY opcode).

---

## Claude's Discretion

None — all areas had clear user decisions.

## Deferred Ideas

None — discussion stayed within phase scope.
