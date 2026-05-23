# Roadmap: dnsscienced — DNS Firewall

## Milestones

- ✅ **v1.0 MVP** — Phase 1 (shipped 2026-04-22)
- ✅ **v1.1 dnsfirewalld Completion** — Phases 2–5 (shipped 2026-04-23)
- ✅ **v1.2 Fully Operational** — Phases 6–9 (shipped 2026-05-18)
- 🔄 **v1.3 DNS Protocol Completeness** — Phases 10–13 (in progress)

## Phases

<details>
<summary>✅ v1.0 MVP (Phase 1) — SHIPPED 2026-04-22</summary>

- [x] Phase 1: dnsfirewalld Foundation (single-commit greenfield build) — completed 2026-04-22

See archive: `.planning/milestones/v1.0-*` (if present)

</details>

<details>
<summary>✅ v1.1 dnsfirewalld Completion (Phases 2–5) — SHIPPED 2026-04-23</summary>

- [x] Phase 2: gRPC Admin (4/4 plans) — completed 2026-04-23
- [x] Phase 3: Live Threat Feed (3/3 plans) — completed 2026-04-23
- [x] Phase 4: EDNS0 CustomerID (1/1 plan) — completed 2026-04-23
- [x] Phase 5: Redirect Load Balancing (2/2 plans) — completed 2026-04-23

See archive: `.planning/milestones/v1.1-ROADMAP.md`

</details>

## Phases

<details>
<summary>✅ v1.2 — Fully Operational (Phases 6–9) — SHIPPED 2026-05-18</summary>

**Goal:** Make dnsscienced production-complete: all admin RPCs functional, admin API authenticated with mandatory keys + mTLS, and RFC 9859 DSYNC/generalized notifications implemented.

### Phase 6: Admin API — Stubs & Registration

**Goal:** Fix the critical AdminService registration gap (all admin RPCs currently return Unimplemented), implement all 14 stub methods, make zone/record CRUD fully functional, and add TSIG (RFC 2845) key management and verification.

**Scope:**
- Register `AdminService` in `api/grpc/registry/register.go` (critical — currently absent)
- Implement `CreateZone`, `UpdateZone`, `DeleteZone`, `GetZone` (zone CRUD via zone file + reload)
- Implement `CreateRecord`, `UpdateRecord`, `DeleteRecord`, `ListRecords` (zone record CRUD)
- Implement `SetQueryLogging`, `GetQueryLoggingStatus` (hook into logging package)
- Implement `SetRateLimit`, `GetRateLimitStatus` (hook into RRL system)
- Complete `GetMetrics` (add UDP/TCP split counters, latency percentiles)
- Implement `ListConnections`, `KillConnection` (connection tracking in transport layer)
- Fix `ListZones` missing fields: SourceFile, Compiled (.dzc), Serial (from SOA)
- TSIG key management: internal/tsig package with KeyRing, Verify, Sign
- TSIG server wiring: dns.Server.TsigSecret populated from config
- TSIG admin RPCs: AddTsigKey, RemoveTsigKey, ListTsigKeys

**Files:** `internal/admin/service.go`, `api/grpc/registry/register.go`, `internal/server/server.go`, `internal/zone/`, `internal/rrl/`, `internal/logging/`, `internal/tsig/`, `internal/config/config.go`, `api/grpc/proto/admin.proto`

**Plans:** 6 plans

Plans:
- [x] 06-01-PLAN.md — Package extensions: logging dynamic control, rrl RWMutex, server UDP/TCP atomics (Wave 1)
- [x] 06-02-PLAN.md — AdminService registration + SrvAdapter wiring + SrvStats UDP/TCP (Wave 2)
- [x] 06-03-PLAN.md — Zone/record CRUD + ListZones fix + SetQueryLogging + SetRateLimit (Wave 3)
- [x] 06-04-PLAN.md — GetMetrics live stats + ListConnections/KillConnection Unimplemented + build gate (Wave 3, parallel)
- [x] 06-05-PLAN.md — TSIG package: KeyRing + Verify + Sign + config + server wiring (Wave 4)
- [x] 06-06-PLAN.md — TSIG admin RPCs: AddTsigKey + RemoveTsigKey + ListTsigKeys + proto regen (Wave 5)

### Phase 7: Admin Auth Hardening

**Goal:** Make the admin API fully secured — mandatory key enforcement (no auth bypass on empty list), mTLS, per-request audit logging, and complete connection management.

**Scope:**
- Mandatory API key enforcement: reject all requests when `api_keys` is empty (remove bypass)
- mTLS: add `TLSClientCertFile` + `TLSClientCAs` config; enforce mutual TLS on admin connections
- Per-request audit log: log caller identity (key ID or cert CN), method, timestamp, result
- Connection tracking: wire connection registry into transport for `ListConnections`/`KillConnection`
- Key rotation: `ReloadAPIKeys` RPC or SIGHUP-triggered key reload without restart

**Files:** `api/grpc/server/server.go`, `api/grpc/middleware/middleware.go`, `internal/admin/service.go`, `cmd/dnsscienced/main.go`

**Plans:** 6 plans

Plans:
- [x] 07-01-PLAN.md — Config struct extensions (TLSClientCAs) + atomicKeySet type (Wave 1)
- [x] 07-02-PLAN.md — Fix auth bypass, buildCreds() mTLS, update interceptors to atomicKeySet (Wave 2)
- [x] 07-03-PLAN.md — AuditUnaryInterceptor + AuditStreamInterceptor in middleware (Wave 2, parallel)
- [x] 07-04-PLAN.md — ConnRegistry StatsHandler + wire ListConnections + key-ID context injection (Wave 3)
- [x] 07-05-PLAN.md — main.go wiring: TLS fields, audit interceptors, ConnRegistry, SIGHUP reload (Wave 4)
- [x] 07-06-PLAN.md — Test suite: AUTH-01 through AUTH-04, AUDIT-01, CONN-01, RELOAD-01 (Wave 5, TDD)

### Phase 8: RFC 9859 — Generalized DNS Notifications (DSYNC)

**Goal:** Implement RFC 9859: DSYNC record type (type 66), inbound NOTIFY(CDS/CSYNC) handler, outbound notification sender, rate limiting, and zone-level DSYNC record serving.

**Scope:**
- DSYNC record type 66: parser, serializer, zone file support (miekg/dns unknown-type workaround)
- Inbound NOTIFY handler: accept NOTIFY with qtype=CDS (type 59) and NOTIFY with qtype=CSYNC (type 62) on port 53; dispatch to delegation maintenance handler
- Rate limiting on NOTIFY processing (MUST per RFC 9859 §5)
- Outbound notification sender: when zone CDS/CSYNC records change, discover parent via `_dsync.<parent>` lookup and send NOTIFY
- `_dsync` zone entry support: serve DSYNC records from zone files for zones that publish endpoints
- DNSSEC signing of zones containing DSYNC records (RECOMMENDED)

**Files:** `internal/dsync/` (new package), `internal/zone/`, `internal/server/server.go`, `internal/config/config.go`

**Plans:** 6 plans

Plans:
- [x] 08-01-PLAN.md — DSYNC type 66 codec + per-IP rate limiter (TDD, Wave 1)
- [x] 08-02-PLAN.md — Inbound NOTIFY handler + _dsync discovery + outbound sender (Wave 2)
- [x] 08-03-PLAN.md — Config structs + server opcode dispatch wiring (Wave 3)
- [x] 08-04-PLAN.md — Zone file TYPE66 test + full build/test gate (Wave 4)
- [x] 08-05-PLAN.md — Webhook delivery + source IP allowlist (Wave 3)
- [x] 08-06-PLAN.md — SendDSYNCNotify Admin RPC + Prometheus metrics (Wave 4)

</details>

### Phase 9: v1.2 Gap Closure — Admin API Wiring

**Goal:** Wire the 4 production gaps identified in the v1.2 milestone audit: inject `*logging.Logger` and `*rrl.Limiter` into `admin.Service` so SetQueryLogging/SetRateLimit work at runtime; plumb `ConnRegistry` from `grpcserver.New()` to `admin.Service` so ListConnections returns real data; fix ListZones by wiring zone enumeration from `server.Server`.

**Scope:**
- Add `GetLogger() *logging.Logger` accessor to `server.Server` + `serverSrvAdapter`
- Add `GetRRL() *rrl.Limiter` accessor to `server.Server` + `serverSrvAdapter`
- Wire logger + rrlLimiter through `services.SrvAdapter` interface → `RegisterAll` → `admin.NewService`
- Add `SetConnRegistry(*grpcserver.ConnRegistry)` setter to `admin.Service`; call post-construction in `main.go`; remove `_ = connReg` discard
- Fix `ListZones` by adding `GetZoneNames() []string` to `server.Server` or wiring reloadMgr; admin service uses it when reloadMgr is nil
- Fix TSIG bootstrap: always initialize `tsigKeyRing` in `server.New()` (zero-key ring is valid)
- Fix stream interceptor key ID: store key ID in context from `apiKeyStreamInterceptor`
- Update v1.2 milestone audit to `status: passed` after all gaps closed

**Files:** `internal/server/server.go`, `api/grpc/services/management.go`, `cmd/dnsscienced/main.go`, `api/grpc/registry/register.go`, `internal/admin/service.go`, `api/grpc/server/server.go`

**Plans:** 3/3 plans complete

Plans:
- [x] 09-01-PLAN.md — Add server accessors (GetLogger, GetRRL, GetZoneNames) + extend SrvAdapter interface (Wave 1)
- [x] 09-02-PLAN.md — Wire logger/rrlLimiter/reloadMgr into RegisterAll + admin.NewService; fix SetConnRegistry post-construction in main.go (Wave 2)
- [x] 09-03-PLAN.md — Fix TSIG always-init + stream interceptor key ID; verify all 4 gaps closed; update audit status (Wave 3)

<details open>
<summary>🔄 v1.3 — DNS Protocol Completeness (Phases 10–13) — IN PROGRESS</summary>

**Goal:** Close the RFC coverage gaps identified in the v1.2 audit — ship the record types, resolver behaviors, and zone-serving capabilities that a production DNS server is expected to support.

## Phase Details

### Phase 10: Record Type Expansion

**Goal:** Users can load, serve, and round-trip all six new record types through both zone parsers and the compiled .dzc format
**Depends on**: Phase 9
**Requirements**: RRTYPE-01, RRTYPE-02, RRTYPE-03, RRTYPE-04, RRTYPE-05, RRTYPE-06, RRTYPE-07, RRTYPE-08
**Success Criteria** (what must be TRUE):
  1. A BIND zone file containing HTTPS, SVCB, TLSA, SSHFP, NAPTR, SMIMEA, and LOC records loads without parse errors
  2. A .dnszone (YAML) zone file containing all six new record types loads without parse errors
  3. All six record types survive a compile-to-.dzc then decompile round-trip with identical wire data
  4. A query for any new record type where no matching record exists returns NOERROR with empty answer section (not NOTIMP or SERVFAIL)
  5. A query for any new record type where a matching record exists returns the correct NOERROR answer
**Plans**: 2 plans
**UI hint**: no

Plans:
**Wave 1**
- [x] 10-01-PLAN.md — YAML parser: add SSHFP/NAPTR/SMIMEA/LOC struct types, parse functions, RecordSection fields, wire both loops, unit tests (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 10-02-PLAN.md — BIND fixture extension, BIND parse tests, DZC round-trip wire equality tests (Wave 2)

### Phase 11: Resolver Behaviors

**Goal:** The recursive resolver minimizes query names, synthesizes responses from cached NSEC/NSEC3, and serves stale records when upstreams are unreachable
**Depends on**: Phase 10
**Requirements**: RESOLVE-01, RESOLVE-02, RESOLVE-03
**Success Criteria** (what must be TRUE):
  1. Outgoing queries from the resolver contain only the labels required for each nameserver level — not the full QNAME — when QNAME minimization is enabled
  2. A cached NSEC/NSEC3 record that proves nonexistence causes the resolver to return NXDOMAIN without sending any upstream query
  3. When all upstream nameservers are unreachable, the resolver returns a cached record with its TTL extended up to the configured stale-max-ttl rather than returning SERVFAIL
  4. Serve-stale behavior is bounded: records older than stale-max-ttl are not served stale
**Plans**: 2 plans

Plans:
**Wave 1**
- [x] 11-01-PLAN.md — Config extension, serve-stale bug fixes, NSEC3 cache storage (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 11-02-PLAN.md — QNAME minimization in resolveIterative() + comprehensive tests (Wave 2)

### Phase 12: AXFR Server

**Goal:** The server serves complete TSIG-authenticated zone transfers to secondaries and refuses unauthorized requests
**Depends on**: Phase 10
**Requirements**: XFER-01, XFER-02, XFER-03
**Success Criteria** (what must be TRUE):
  1. An AXFR request over TCP receives the full zone contents in correct wire format: opening SOA, all RRs, closing SOA
  2. An AXFR request signed with a known TSIG key is accepted and the transfer proceeds
  3. An AXFR request with no TSIG signature is rejected with REFUSED when the zone requires authentication
  4. An AXFR request from an IP not in the zone's allow_transfer CIDR list receives REFUSED regardless of TSIG
**Plans**: 2 plans

Plans:
**Wave 1**
- [x] 11-01-PLAN.md — Config extension, serve-stale bug fixes, NSEC3 cache storage (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 11-02-PLAN.md — QNAME minimization in resolveIterative() + comprehensive tests (Wave 2)
**UI hint**: no

### Phase 13: Dynamic DNS Updates

**Goal:** The server accepts RFC 2136 UPDATE opcodes, applies them to the in-memory zone immediately, and rejects unauthorized updates
**Depends on**: Phase 12
**Requirements**: DYNUP-01, DYNUP-02, DYNUP-03, DYNUP-04
**Success Criteria** (what must be TRUE):
  1. A valid DNS UPDATE message (RFC 2136) adding a record results in that record being visible to subsequent queries without zone reload
  2. A valid DNS UPDATE message deleting a record causes the record to disappear from subsequent queries without zone reload
  3. An UPDATE request signed with a known TSIG key is accepted; an unsigned UPDATE request is rejected with REFUSED
  4. An UPDATE request from an IP not in the zone's allow_update CIDR list receives REFUSED regardless of TSIG signature
**Plans**: 2 plans

Plans:
**Wave 1**
- [x] 11-01-PLAN.md — Config extension, serve-stale bug fixes, NSEC3 cache storage (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*
- [ ] 11-02-PLAN.md — QNAME minimization in resolveIterative() + comprehensive tests (Wave 2)

- [ ] **Phase 10: Record Type Expansion** — Parse and serve HTTPS/SVCB, TLSA, SSHFP, NAPTR, SMIMEA, LOC from both parsers; .dzc round-trip; correct NOERROR for empty in-zone lookups
- [x] **Phase 11: Resolver Behaviors** — QNAME minimization, aggressive NSEC/NSEC3 caching, serve-stale with TTL extension (completed 2026-05-23)
- [ ] **Phase 12: AXFR Server** — Zone transfer serving (RFC 5936), TSIG authentication, per-zone allow_transfer ACL
- [ ] **Phase 13: Dynamic DNS Updates** — RFC 2136 UPDATE opcode, TSIG auth, per-zone allow_update ACL, immediate visibility

</details>

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|---------------|--------|-----------|
| 1. dnsfirewalld Foundation | v1.0 | 1/1 | Complete | 2026-04-22 |
| 2. gRPC Admin | v1.1 | 4/4 | Complete | 2026-04-23 |
| 3. Live Threat Feed | v1.1 | 3/3 | Complete | 2026-04-23 |
| 4. EDNS0 CustomerID | v1.1 | 1/1 | Complete | 2026-04-23 |
| 5. Redirect Load Balancing | v1.1 | 2/2 | Complete | 2026-04-23 |
| 6. Admin API — Stubs & Registration | v1.2 | 6/6 | Complete   | 2026-05-17 |
| 7. Admin Auth Hardening | v1.2 | 7/7 | Complete   | 2026-05-16 |
| 8. RFC 9859 DSYNC | v1.2 | 7/7 | Complete   | 2026-05-17 |
| 9. v1.2 Gap Closure | v1.2 | 3/3 | Complete   | 2026-05-18 |
| 10. Record Type Expansion | v1.3 | 3/3 | Complete   | 2026-05-21 |
| 11. Resolver Behaviors | v1.3 | 2/2 | Complete    | 2026-05-23 |
| 12. AXFR Server | v1.3 | 0/? | Not started | - |
| 13. Dynamic DNS Updates | v1.3 | 0/? | Not started | - |

---
*Last updated: 2026-05-22 — Phase 11 planned (2 plans, 2 waves)*
