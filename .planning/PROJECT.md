# dnsscienced — DNS Firewall (dnsfirewalld)

## What This Is

dnsscienced is a production Go-based authoritative and caching DNS server. The dnsfirewalld subsystem is a programmable DNS firewall wired into the query path — it detects junk queries, evaluates threat intel scores, runs Starlark policy scripts, and can rewrite, redirect, drop, or NXDOMAIN any query in real time. Operators manage the firewall via gRPC RPCs; threat scores are kept fresh by an autonomous feed poller; queries carry per-customer identity via EDNS0; redirect verdicts are distributed across a load-balanced upstream pool.

## Core Value

Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.

## Current State: v1.1 Shipped + Phase 06 Complete

**Shipped:** 2026-04-23
**Test suite:** 44 firewalld tests, all passing under `-race`
**Binary:** `dnsscienced-linux` (Go-only, no CGO)

**Phase 06 complete (2026-05-16):** Admin API fully wired — all AdminService RPCs registered and callable via gRPC; zone/record CRUD persisted to disk; metrics/logging/rate-limit controls wired to live subsystems; TSIG (RFC 2845) key management implemented end-to-end with runtime Add/Remove RPCs.

## Requirements

### Validated

<!-- Shipped in v1.0 (commits 28deead, 091d1e3, 9a1f9f0) -->
- ✓ Firewall.Check() wired into query path — v1.0
- ✓ Static rule evaluation (domain suffix/exact, CIDR, qtype) — v1.0
- ✓ DGA/junk detection (entropy, data exfil, random subdomain) — v1.0
- ✓ Threat intel scoring (IP CIDR, zone scores, customer trust bonus) — v1.0
- ✓ Starlark engine with firewall.* module (nxdomain/drop/rewrite/redirect/allow) — v1.0
- ✓ UDP forwarder with TCP retry on truncation — v1.0
- ✓ Prometheus metrics (sync.Once singleton) — v1.0
- ✓ HTTP/JSON admin handler (stats, script reload, intel injection) — v1.0
- ✓ 19 unit tests passing — v1.0
- ✓ gRPC admin RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore) — v1.1
- ✓ Live threat feed client polls and injects domain/IP scores — v1.1
- ✓ QueryContext.CustomerID populated from EDNS0 option at query intake — v1.1
- ✓ VerdictRedirect selects from multiple upstream targets (load balancing) — v1.1

### Active

*(None — planning next milestone)*

### Out of Scope

- CGO/nftables integration — Go-only policy enforcement is sufficient for v1
- Mobile or web UI for firewall management — CLI + gRPC is the operator interface
- ML-based threat scoring — entropy heuristics cover the junk detection use case
- OAuth/mTLS for feed endpoints — v1 simple URL + interval sufficient
- Offline mode — real-time enforcement is core value

## Context

- Language: Go, targeting Linux production build (`dnsscienced-linux`)
- Proto codegen: `generate.sh` in repo root (uses protoc); run with `$HOME/go/bin` in PATH
- Admin proto: `api/grpc/proto/admin.proto` — FirewallAdminService + AdminService
- HTTP admin stays as fallback; gRPC admin is the target operator interface
- Starlark scripts use `on_query(q, score)` — q is a dict (keys: name, type, client_ip, customer_id), score is int 0-100
- DGA entropy threshold: SLD entropy > 4.2 (requires ~19 unique chars in label)
- ThreatIntelConfig has 6 feed fields; FeedClient polls and applies full-replace semantics
- EDNS0 CustomerID: option code 65000 (private-use per RFC 6891 §6.1.3.1); max 64 bytes
- UpstreamPool: atomic.Uint64 round-robin; empty pool → SERVFAIL at startup
- generate.sh quirk: deletes stray `pb/management.pb.go` after each run (management.proto side-effect)

## Constraints

- **Tech stack**: Go only — no CGO, no new external services
- **Proto**: Must use existing protoc toolchain (generate.sh)
- **Compat**: HTTP admin handler stays in place as fallback; gRPC is additive
- **Tests**: All new code gets unit tests; 44 firewalld tests must stay green

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Starlark for policy scripting | Expressive but sandboxed; no arbitrary code exec risk | ✓ Good |
| HTTP admin as interim | Unblocked ops tooling without proto changes | ✓ Good |
| sync.Once Prometheus metrics | Avoids test panics from double-registration | ✓ Good |
| Firewall.Check() nil from New() when disabled | Zero-cost when disabled; caller guards | ✓ Good |
| gRPC registered via nil-guard on GetFirewall() | Safe no-op when firewall.enabled=false | ✓ Good |
| FeedClient full-replace semantics | Atomic score replacement prevents stale entries accumulating | ✓ Good |
| edns0CustomerIDCode = 65000 (0xFDE8) | Private-use range per RFC 6891; avoids dns.EDNS0LOCALSTART clash | ✓ Good |
| UpstreamPool atomic.Uint64 round-robin | Zero-lock; correct under concurrent goroutines | ✓ Good |
| redirect() rejects server= kwarg | Single source of truth for upstream selection; prevents config drift | ✓ Good |
| AuthToken never logged | Only presence logged; mitigates credential leakage in log aggregators | ✓ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-16 after Phase 06 completion*
