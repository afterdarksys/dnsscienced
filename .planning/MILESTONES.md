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

## v1.1 — dnsfirewalld Completion (Active)

**Started:** 2026-04-23

**Goal:** Ship remaining 4 subsystems for production readiness.

**Target features:**
- gRPC admin RPCs
- Live threat feed integration
- EDNS0 CustomerID extraction
- VerdictRedirect load balancing
