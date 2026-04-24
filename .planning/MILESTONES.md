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
