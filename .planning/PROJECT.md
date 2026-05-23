# dnsscienced — DNS Firewall (dnsfirewalld)

## What This Is

dnsscienced is a production Go-based authoritative and caching DNS server. The dnsfirewalld subsystem is a programmable DNS firewall wired into the query path — it detects junk queries, evaluates threat intel scores, runs Starlark policy scripts, and can rewrite, redirect, drop, or NXDOMAIN any query in real time. Operators manage the firewall via gRPC RPCs; threat scores are kept fresh by an autonomous feed poller; queries carry per-customer identity via EDNS0; redirect verdicts are distributed across a load-balanced upstream pool.

## Core Value

Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.

## Current Milestone: v1.3 DNS Protocol Completeness

**Goal:** Close the RFC coverage gaps identified in the v1.2 audit — ship the record types, resolver behaviors, and zone-serving capabilities that a production DNS server is expected to support.

**Target features:**
- HTTPS/SVCB (RFC 9460), TLSA (RFC 6698), SSHFP (RFC 4255), NAPTR (RFC 3403), SMIMEA (RFC 8162), LOC (RFC 1876) record type support
- Query name minimization (RFC 7816/9156)
- Aggressive NSEC/NSEC3 caching (RFC 8198)
- Serve-stale with proper TTL extension (RFC 8767)
- AXFR server — serve zone transfers to secondaries (RFC 5936)
- Dynamic DNS Updates (RFC 2136)

## Current State: Phase 11 Complete (v1.3 in progress)

**Phase 11 complete:** 2026-05-23
**Test suite:** 80+ tests + 14 new Phase 11 tests; pre-existing TestFindGlue/TestResolver_Resolve network-dependent failures documented
**Binary:** `dnsscienced-linux` (Go-only, no CGO)
**Total Go:** ~87,000 LOC across 195 files

Phase 11 delivered QNAME minimization (RFC 7816/9156), aggressive NSEC/NSEC3 synthesis (RFC 8198), and serve-stale (RFC 8767) with two bug fixes (IsExpired guard removal, TTL=0 rewrite on both stale paths). Next: Phase 12 AXFR server.

v1.2 delivered production-complete admin API, hardened gRPC auth (mTLS + API keys + audit logging), full RFC 9859 DSYNC implementation, and TSIG key management. All four v1.2 audit gaps closed.

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

- ✓ All AdminService RPCs registered and implemented (zone/record CRUD, metrics, logging, RRL) — v1.2
- ✓ TSIG key management (RFC 2845/8945) — KeyRing, Verify, Sign, runtime Add/Remove RPCs — v1.2
- ✓ Admin gRPC hardened — mTLS + AND-auth policy, structured audit logging, ConnRegistry, SIGHUP reload — v1.2
- ✓ RFC 9859 DSYNC fully implemented — record type 66, inbound/outbound NOTIFY, rate limiting, webhook, metrics — v1.2
- ✓ v1.2 audit gaps closed — logger/RRL accessors, ConnRegistry wiring, ListZones, stream interceptor key ID — v1.2

### Active

*(Phase 12 AXFR server — in progress)*

### Validated in Phase 11

- ✓ QNAME minimization (RFC 7816/9156) — per-delegation query name rewriting in resolveIterative() — Phase 11
- ✓ Aggressive NSEC/NSEC3 synthesis (RFC 8198) — NSEC/NSEC3 cache storage + dns.NSEC3.Cover() synthesis — Phase 11
- ✓ Serve-stale (RFC 8767) — stale fallback on upstream failure with TTL=0 rewrite on all RRs — Phase 11

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
| AND-auth policy (cert + key) | Cert proves machine, key proves operator intent — both required even with mTLS | ✓ Good |
| TSIG shared-map pattern | KeyRing.secrets = dns.Server.TsigSecret; mutations visible on next request without restart | ✓ Good |
| NOTIFY dispatch before pool/defensive | NOTIFY is control-plane; must bypass query rate limiting and defensive checks | ✓ Good |
| TypeDSYNC=66 defined in-package | miekg/dns v1.1.72 doesn't define it; RFC3597 fallback handles zone file parsing | ✓ Good |
| ConnRegistry via gRPC stats.Handler | UUID per conn; key ID enriched post-auth — no surgery to transport layer required | ✓ Good |
| keyIDStream wrapper for stream interceptor | Enriches ServerStream context without rewriting interceptor chain | ✓ Good |

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
*Last updated: 2026-05-21 after v1.2 milestone completion*
