# Roadmap: dnsscienced — dnsfirewalld Completion

**Milestone:** v1.1 — dnsfirewalld Completion
**Phases:** 4 (numbered 2-5, continuing from v1.0 Phase 1)
**Requirements:** 16 mapped

## Phases

- [ ] **Phase 2: gRPC Admin** — Expose firewall management via gRPC RPCs
- [ ] **Phase 3: Live Threat Feed** — Poll external feed URL and ingest domain/IP threat scores
- [ ] **Phase 4: EDNS0 CustomerID** — Extract customer identity from DNS queries at intake
- [ ] **Phase 5: Redirect Load Balancing** — Distribute redirect verdicts across multiple upstream targets

## Phase Details

### Phase 2: gRPC Admin

**Goal**: Operators can manage the firewall (stats, script load/remove, score injection) over gRPC in addition to HTTP.
**Depends on**: Phase 1 (v1.0 — HTTP admin baseline)
**Requirements**: GRPC-01, GRPC-02, GRPC-03, GRPC-04, GRPC-05

**Success criteria:**
1. `grpcurl` call to FirewallStats returns current counter values matching the HTTP /stats endpoint
2. `grpcurl` call to LoadScript with a valid Starlark script body causes it to execute on subsequent queries
3. `grpcurl` call to RemoveScript unloads the named script; later queries no longer trigger it
4. `grpcurl` call to InjectScore for a domain raises its threat score, verifiable via FirewallStats

**Plans:** 4 plans

Plans:
- [x] 02-01-PLAN.md — Proto definition + codegen (FirewallAdminService + 8 messages in admin.proto; run generate.sh)
- [ ] 02-02-PLAN.md — Go accessor chain (LoadSource on *Firewall; GetFirewall accessor; SrvAdapter interface extension; serverSrvAdapter + NoopSrvAdapter implementations)
- [ ] 02-03-PLAN.md — FirewallService implementation + unit tests (firewall.go + firewall_test.go)
- [ ] 02-04-PLAN.md — Registry wiring (conditional RegisterFirewallAdminServiceServer in RegisterAll)

---

### Phase 3: Live Threat Feed

**Goal**: Server autonomously pulls domain and IP threat scores from a configured HTTP feed URL and applies them without operator intervention.
**Depends on**: Phase 2
**Requirements**: FEED-01, FEED-02, FEED-03, FEED-04

**Success criteria:**
1. With `feed_url` and `poll_interval` set in config.yaml, the server starts a background poller that fetches the URL on schedule (observable via log lines)
2. Entries from the feed appear in threat intel scores — a domain listed in the feed scores above 0 at query time
3. A feed that returns HTTP errors or malformed lines logs the error and continues polling without crashing the server
4. Removing or blanking `feed_url` from config disables the poller (no polling activity in logs)

**Key tasks:**
- Create `internal/firewalld/feed.go` with a `FeedClient` that polls `ThreatIntelConfig.FeedURL` at `ThreatIntelConfig.PollInterval`
- Parse newline-delimited entries: `domain score` or `IP/CIDR score`
- Call `ThreatIntelEngine().AddDomainScore` / `AddIPScore` for each valid entry
- Log and skip malformed lines; log HTTP errors without exiting
- Wire `FeedClient.Start()` into server startup when feed URL is non-empty
- Add unit tests with a mock HTTP server serving feed content

**Plans**: TBD

---

### Phase 4: EDNS0 CustomerID

**Goal**: Every DNS query carries its customer identity into the firewall policy engine so scripts can apply per-customer rules.
**Depends on**: Phase 2
**Requirements**: CUST-01, CUST-02, CUST-03

**Success criteria:**
1. A query carrying a known EDNS0 option (custom option code) with a CustomerID value results in `q.customer_id` being non-empty inside a Starlark on_query handler
2. A query without the EDNS0 option still resolves normally — `q.customer_id` is an empty string, no error
3. A Starlark script that branches on `q.customer_id` applies the correct per-customer verdict

**Key tasks:**
- Define the EDNS0 option code constant for CustomerID (document in code comment)
- In `internal/server/server.go` query intake, extract the EDNS0 option value before calling `Firewall.Check()`
- Populate `QueryContext.CustomerID` with extracted value or empty string
- Add unit tests covering: option present, option absent, option with empty payload

**Plans**: TBD
**UI hint**: no

---

### Phase 5: Redirect Load Balancing

**Goal**: Redirect verdicts (both static rules and Starlark) are distributed across a configured pool of upstream DNS targets using round-robin selection.
**Depends on**: Phase 3, Phase 4
**Requirements**: REDIR-01, REDIR-02, REDIR-03, REDIR-04

**Success criteria:**
1. With two upstreams configured in `firewall.redirect.upstreams`, repeated redirect queries cycle between both targets (observable via query logs showing alternating upstream addresses)
2. A static rule with VerdictRedirect uses the pool — not a hardcoded single address
3. A Starlark script calling `redirect()` uses the same pool as static rules
4. Config with a single upstream entry behaves identically to the existing single-target behavior

**Key tasks:**
- Add `Upstreams []string` to redirect config struct (under `firewall.redirect.upstreams` in config.yaml)
- Implement an `UpstreamPool` with atomic round-robin counter in `internal/firewalld/forwarder.go`
- Replace the single-target forwarder call with `pool.Next()` selection
- Ensure both `VerdictRedirect` (static rule path) and Starlark `redirect()` call through the same pool instance
- Add unit tests: single upstream, two upstreams round-robin distribution, zero upstreams returns error

**Plans**: TBD

---

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 2. gRPC Admin | 1/4 | In progress | - |
| 3. Live Threat Feed | 0/0 | Not started | - |
| 4. EDNS0 CustomerID | 0/0 | Not started | - |
| 5. Redirect Load Balancing | 0/0 | Not started | - |

---
*Roadmap created: 2026-04-23*
*Milestone: v1.1 — dnsfirewalld Completion*
