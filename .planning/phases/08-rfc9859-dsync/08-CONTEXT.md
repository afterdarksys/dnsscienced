# Phase 8: RFC 9859 — Generalized DNS Notifications (DSYNC) - Context

**Gathered:** 2026-05-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Implement RFC 9859 DSYNC: type 66 record codec, inbound NOTIFY(CDS/CSYNC) handler with per-source-IP rate limiting, outbound NOTIFY sender triggered by admin RPC, and zone-level DSYNC record serving. No DNSSEC signing changes — that is already wired.

</domain>

<decisions>
## Implementation Decisions

### Post-Notify Action (inbound)
- **D-01:** On accepted NOTIFY: emit structured log entry + increment Prometheus counter + fire webhook POST
- **D-02:** Webhook URL is per-zone in `ZoneDSYNCConfig`; zones without a URL skip the webhook
- **D-03:** Webhook body is configurable: JSON default (zone name, qtype, source IP, timestamp) or raw base64 wire format
- **D-04:** Webhook delivery is fire-and-forget: 5s timeout, no retry, failure logged and counted

### Source Verification
- **D-05:** Per-zone `allowed_sources []string` in `ZoneDSYNCConfig` (CIDRs and/or IPs); zones without an allowlist accept NOTIFY from any source
- **D-06:** Rejected sources (not in allowlist) get `REFUSED` response — consistent with rate-limit rejection
- **D-07:** Rate limiting applies to all accepted sources, not just allowlisted ones

### Outbound NOTIFY Trigger
- **D-08:** Trigger is explicit Admin RPC — operator calls `SendDSYNCNotify` RPC after updating CDS/CSYNC records; no automatic file-watch or reload-hook trigger
- **D-09:** Destination resolved at send time via live DNS lookup of `_dsync.<parent-zone>` — no config pin, no fallback
- **D-10:** Outbound delivery is fire-and-forget: no retry, failure logged + error counter incremented
- **D-11:** Outbound transport uses a separate `dns.Client` dialer — not the server's inbound socket

### Rate Limiting
- **D-12:** Scope is per-source IP token bucket — isolates noisy senders, same model as x/time/rate already used in the project
- **D-13:** Default rate: 5 NOTIFY/min per IP; operator-configurable in `ZoneDSYNCConfig` or global DSYNC config
- **D-14:** NOTIFY dropped by rate limit → `REFUSED` response (consistent with D-06)
- **D-15:** Rate limiter lives in `internal/dsync` — separate from `internal/rrl` (which limits response volume for queries, different semantics)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### RFC and Protocol
- `RFC 9859` (https://www.rfc-editor.org/rfc/rfc9859) — Generalized DNS Notifications; defines DSYNC RR type 66, NOTIFY opcode extension, discovery via `_dsync.<parent>`, rate limiting MUST (§5)
- `.planning/phases/08-rfc9859-dsync/08-RESEARCH.md` — Pre-researched: miekg/dns v1.1.72 has no native DSYNC type; wire format verified; architectural responsibility map; standard stack confirmed

### Existing Code Integration Points
- `internal/server/server.go` — `handleDNS` function needs opcode dispatch branch for `dns.OpcodeNotify`; NOTIFY opcode already accepted by `DefaultMsgAcceptFunc` (no setup change needed)
- `internal/zone/parser_dnszone.go` — Already handles `TYPE66` via `Generic map[string]interface{}` for `.dnszone` YAML files
- `internal/rrl/` — Pattern reference for token bucket rate limiter structure (do NOT reuse — see D-15)
- `internal/config/config.go` — `ZoneDSYNCConfig` struct must be added here for per-zone webhook URL, allowed_sources, and rate limit params

### Libraries (already in go.mod — no new deps)
- `github.com/miekg/dns v1.1.72` — `dns.RFC3597` for wire encoding, `dns.Client` for outbound sender, `dns.OpcodeNotify` constant
- `golang.org/x/time/rate` — Token bucket for per-source-IP rate limiter in `internal/dsync`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `golang.org/x/time/rate.Limiter` — Already a project dependency; use for per-IP token bucket in the DSYNC rate limiter (`sync.Map` keyed by IP string → `*rate.Limiter`)
- `dns.RFC3597` struct — Wire encode/decode for DSYNC type 66 on the wire; wrap with a typed `DSYNC` struct internally for handler ergonomics
- `internal/zone/parser_dnszone.go` `Generic` map — Zone loader already passes TYPE66 through; DSYNC codec just needs to be registered so structured access works

### Established Patterns
- Fire-and-forget delivery (5s timeout, no retry) — already decided for webhook and outbound NOTIFY; consistent with Phase 3 feed error resilience pattern (D-14 in feed.go: failed fetch leaves prev state intact)
- Per-zone config structs in `config.go` — follow `ThreatIntelConfig`, `RedirectConfig` pattern with yaml tags and DefaultConfig population
- gRPC admin RPC addition pattern — add to `admin.proto`, regenerate with `generate.sh`, implement in `api/grpc/services/firewall.go` or a new `dsync.go` service file

### Integration Points
- `internal/server/server.go` `handleDNS` — new `if r.Opcode == dns.OpcodeNotify` branch dispatches to `internal/dsync` handler
- `api/grpc/proto/admin.proto` — `SendDSYNCNotify` RPC added to `AdminService`; regenerate with `generate.sh`
- `internal/config/config.go` — `ZoneDSYNCConfig` struct with `WebhookURL`, `WebhookBodyFormat`, `AllowedSources`, `RateLimitPerMin` fields

</code_context>

<specifics>
## Specific Ideas

- DSYNC record type: typed `DSYNC` struct satisfying `dns.RR` internally; use `dns.RFC3597` for wire format — researcher confirmed this is the correct pattern for unsupported types in miekg/dns v1.1.72
- Rate limiter visitor map: `sync.Map[string]*rate.Limiter` keyed by source IP string — straightforward, no custom eviction needed at this scale
- `SendDSYNCNotify` RPC: takes zone name as argument; handler resolves parent, does `_dsync.<parent>` lookup, sends NOTIFY — all synchronous within RPC handler (fire-and-forget on the DNS send itself)

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 8-RFC 9859 DSYNC*
*Context gathered: 2026-05-16*
