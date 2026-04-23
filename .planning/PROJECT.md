# dnsscienced — DNS Firewall (dnsfirewalld)

## What This Is

dnsscienced is a production Go-based authoritative and caching DNS server. The dnsfirewalld subsystem is a programmable DNS firewall wired into the query path — it detects junk queries, evaluates threat intel scores, runs Starlark policy scripts, and can rewrite, redirect, drop, or NXDOMAIN any query in real time.

## Core Value

Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.

## Current Milestone: v1.1 — dnsfirewalld Completion

**Goal:** Ship the remaining 4 subsystems to make dnsfirewalld production-ready end-to-end.

**Target features:**
- gRPC admin RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore)
- Live threat feed integration (polling client wired to AddDomainScore/AddIPScore)
- EDNS0 CustomerID extraction (populate QueryContext.CustomerID at intake)
- VerdictRedirect load balancing (multi-upstream round-robin/weighted)

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

### Active

- [x] gRPC admin RPCs added to admin.proto and implemented — Phase 2 complete
- [x] Live threat feed client polls and injects domain/IP scores — Phase 3 complete
- [x] QueryContext.CustomerID populated from EDNS0 option at query intake — Phase 4 complete
- [ ] VerdictRedirect selects from multiple upstream targets (load balancing)

### Out of Scope

- CGO/nftables integration — Go-only policy enforcement is sufficient for v1
- Mobile or web UI for firewall management — CLI + gRPC is the operator interface
- ML-based threat scoring — entropy heuristics cover the junk detection use case

## Context

- Language: Go, targeting Linux production build (`dnsscienced-linux`)
- Proto codegen: `generate.sh` in repo root (uses protoc)
- Admin proto: `api/` directory contains existing admin.proto
- HTTP admin is the interim solution; gRPC admin is the target
- Starlark scripts use `on_query(q, score)` — q is a dict, score is int 0-100
- DGA entropy threshold: SLD entropy > 4.2 (requires ~19 unique chars in label)
- ThreatIntelConfig has 6 feed fields; FeedClient polls and applies full-replace semantics
- QueryContext.CustomerID populated from EDNS0 option code 65000 (edns0CustomerIDCode) at Check() entry, before all policy evaluation — Phase 4 complete

## Constraints

- **Tech stack**: Go only — no CGO, no new external services
- **Proto**: Must use existing protoc toolchain (generate.sh)
- **Compat**: HTTP admin handler stays in place as fallback; gRPC is additive
- **Tests**: All new code gets unit tests; existing 19 must stay green

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Starlark for policy scripting | Expressive but sandboxed; no arbitrary code exec risk | ✓ Good |
| HTTP admin as interim | Unblocked ops tooling without proto changes | ✓ Good |
| sync.Once Prometheus metrics | Avoids test panics from double-registration | ✓ Good |
| Firewall.Check() nil from New() when disabled | Zero-cost when disabled; caller guards | ✓ Good |

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
*Last updated: 2026-04-23 — Phase 4 (EDNS0 CustomerID) complete*
