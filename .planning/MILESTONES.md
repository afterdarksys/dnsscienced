# Milestones

## v1.0 — dnsfirewalld Foundation (Completed)

**Shipped:** 2026-04-22 (commits 28deead, 091d1e3, 9a1f9f0)

**What shipped:**
- `internal/firewalld/` package fully wired into `internal/server/server.go`
- Static policy evaluation, DGA/junk detection, threat intel scoring
- Starlark engine with `firewall.*` module
- UDP/TCP forwarder for redirect verdicts
- Prometheus metrics, HTTP/JSON admin handler
- 19 unit tests, all passing
- `config.example.yaml` firewall section, `CLAUDE.md` added

**Phases:** 1 (single-commit milestone — greenfield build)

---

## v1.1 — dnsfirewalld Completion (Completed)

**Shipped:** 2026-04-23
**Phases:** 2–5 (4 phases, 10 plans, 63 commits)
**Git range:** 39930b0..9f287b3
**Files changed:** 73 files, +14,589 / -134 lines
**Test suite:** 19 → 44 firewalld tests (all passing under -race)

**Key accomplishments:**
1. gRPC admin — FirewallAdminService with 4 RPCs (Stats, LoadScript, RemoveScript, InjectScore) conditionally registered via nil-guard
2. Live threat feed — FeedClient polls any HTTP URL, full-replace semantics, auth token never logged, error-resilient
3. EDNS0 CustomerID — extractCustomerID() reads option code 65000; CustomerID in QueryContext before all policy stages
4. Redirect load balancing — UpstreamPool atomic round-robin; Starlark and static rules share the pool; empty pool → SERVFAIL at startup
5. Starlark CustomerID branching verified — q["customer_id"] flows through on_query handler end-to-end

**Archive:** `.planning/milestones/v1.1-ROADMAP.md`, `.planning/milestones/v1.1-REQUIREMENTS.md`

---

## v1.2 — Fully Operational (Completed)

**Shipped:** 2026-05-18
**Phases:** 6–9 (4 phases, 23 plans, ~80 commits)
**Git range:** 106a511..84ca143
**Files changed:** 123 files, +25,176 / -335 lines
**Test suite:** 44 → 80+ tests (all passing under -race)

**Key accomplishments:**
1. Admin API fully operational — all AdminService RPCs registered and implemented; zone/record CRUD, metrics, logging, rate-limit controls wired to live subsystems
2. TSIG key management (RFC 2845/8945) — `internal/tsig` package with KeyRing, Verify, Sign; runtime Add/Remove via gRPC RPCs; secrets never returned or logged
3. Admin gRPC hardened — mandatory AND-auth (API key + mTLS cert), structured audit logging (caller, method, latency, remote_addr), ConnRegistry StatsHandler, atomic SIGHUP reload
4. RFC 9859 DSYNC fully implemented — DSYNC record type 66 codec, inbound NOTIFY(CDS/CSYNC) handler, per-source-IP rate limiting, outbound `_dsync` discovery and sender, source ACL, webhook delivery, Prometheus metrics, `SendDSYNCNotify` Admin RPC
5. v1.2 audit gaps closed — SetQueryLogging/SetRateLimit wired to live logger/rrl; ConnRegistry in admin service; ListZones fixed; TSIG always-initialized; stream interceptor key ID propagated

**Known deferred items at close:** 0

**Archive:** `.planning/milestones/v1.2-ROADMAP.md`, `.planning/milestones/v1.2-MILESTONE-AUDIT.md`
