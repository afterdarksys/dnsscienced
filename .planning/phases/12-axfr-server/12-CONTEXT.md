# Phase 12: AXFR Server - Context

**Gathered:** 2026-05-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Implement an AXFR server (RFC 5936) that serves complete zone transfers to authorized secondary DNS servers. The server must:
1. Respond to AXFR requests over TCP with the full zone contents: opening SOA, all RRs, closing SOA
2. Require TSIG authentication on every AXFR request, reusing the existing `tsig.KeyRing`
3. Enforce per-zone `allow_transfer` CIDR ACLs; requests from unlisted sources receive REFUSED

AXFR over UDP returns TC=1 (truncation) to signal clients to retry over TCP.

This phase does NOT include IXFR (incremental transfers) or NOTIFY-on-transfer — those are v2 requirements.

</domain>

<decisions>
## Implementation Decisions

### IP ACL — allow_transfer

- **D-01:** Empty `allow_transfer` list = **REFUSED**. No configured ACL means no transfers permitted. Secure-by-default; operators must explicitly grant access. This is the opposite of the DSYNC SourceACL D-05 ("empty = accept all") — zone transfer exposure justifies the more restrictive default.
- **D-02:** `allow_transfer` is already defined as `AllowTransfer []string` in `ZoneConfig` (`internal/config/config.go:103`). No new config field needed. The field already carries per-zone CIDR strings.
- **D-03:** IP ACL failure (source not in allow_transfer) → return **REFUSED** (rcode 5).

### TSIG Authentication

- **D-04:** TSIG is **always required** for every AXFR request, globally. No new `require_tsig` flag or `tsig_key` field in ZoneConfig. Unsigned requests → **NOTAUTH** (rcode 9). This distinguishes authentication failures from access-control failures for secondary DNS clients.
- **D-05:** TSIG verification failure (bad key, bad sig, missing TSIG) → return **NOTAUTH** (rcode 9), per RFC 2845 §4.
- **D-06:** Reuse the existing `tsig.KeyRing` wired to `dns.Server.TsigSecret` (from Phase 6). miekg/dns auto-verifies TSIG on incoming messages; the AXFR handler must additionally check that TSIG was present at all (miekg/dns verifies a present TSIG but does not reject a missing one — the handler must enforce presence).

### AXFR Dispatch

- **D-07:** AXFR dispatches **early in `handleDNS`**, before `pool.GetMessage()` and before the defensive path — same pattern as NOTIFY (line 480 in server.go). Detect `len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR` early. AXFR must exit before pool acquisition because it streams multiple response messages rather than writing a single pooled message.
- **D-08:** AXFR over UDP returns TC=1 (truncated flag set, no answer section). This signals RFC-compliant clients to retry over TCP automatically (RFC 5936 §4.2). Do not return REFUSED on UDP.

### Multi-Message Streaming

- **D-09:** AXFR response is **multi-message, RFC 5936-compliant**: opening SOA message, batches of zone RRs in subsequent messages, closing SOA in the final message. Each message must be independently TSIG-signed (RFC 5936 §2.2). Single-message is not acceptable — it fails for any non-trivial zone.

### Handler Location

- **D-10:** AXFR handler lives **inline in `internal/server/`** as a new `axfr.go` file. The DSYNC handler warranted its own package because of rate limiting, webhook delivery, ACL structs, and Prometheus metrics. AXFR has no such complexity — a dedicated package would be over-engineering for this scope.

### Claude's Discretion

- How the handler detects TSIG presence/absence in the miekg/dns message (r.IsTsig() or checking r.Extra for OPT/TSIG RR) — planner determines the correct miekg/dns API
- Message batching strategy for multi-message streaming (RR count per message vs. byte budget per message)
- How to look up `ZoneConfig` from a zone origin string at dispatch time (may need a server-level `zoneConfigs map[string]config.ZoneConfig` indexed at startup, or linear scan of `s.cfg.Zones`)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Primary Implementation Targets
- `internal/server/server.go` — `handleDNS()` at line 461; dispatch AXFR early at line ~480 (after NOTIFY dispatch, same pattern)
- `internal/config/config.go` — `ZoneConfig` struct with `AllowTransfer []string` at line 103
- `internal/zone/zone.go` — `GetAllRecords()` at line 204 (zone content enumeration for transfer)

### Reusable Infrastructure
- `internal/tsig/` — `KeyRing`, `Verify`, `Sign`; `GetTsigKeyRing()` accessor on Server (wired from Phase 6)
- `internal/dsync/source_acl.go` — `SourceACL`, `NewSourceACL(cidrs)`, `Check(net.IP) bool` — directly reusable for allow_transfer enforcement (same CIDR allowlist pattern)

### Phase 6 TSIG Wiring (reference)
- `internal/server/server.go:122` — `tsigKeyRing` field; wired to all `dns.Server` instances
- `api/grpc/server/server.go` — TsigSecret wiring pattern

### RFCs
- RFC 5936 — DNS Zone Transfer Protocol (AXFR) — primary spec; §2.2 multi-message, §4.2 TCP requirement
- RFC 2845 — Secret Key Transaction Authentication for DNS (TSIG) — §4 NOTAUTH response codes
- RFC 2182 — Selection and Operation of Secondary DNS Servers — transfer access control guidance

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dsync.SourceACL` / `dsync.NewSourceACL(cidrs)` — the `allow_transfer` CIDR check is identical in logic to NOTIFY source ACL from Phase 8; import or replicate the pattern
- `zone.Zone.GetAllRecords()` — returns all RRs in the zone; used as the content source for the transfer stream
- `tsig.KeyRing` / `server.GetTsigKeyRing()` — shared KeyRing already wired to `dns.Server.TsigSecret`; miekg/dns auto-verifies any TSIG present on incoming messages

### Established Patterns
- **Early opcode/type dispatch** (`handleDNS` line 480): NOTIFY dispatches before pool/defensive. AXFR follows the same pattern — check `r.Question[0].Qtype == dns.TypeAXFR` right after the NOTIFY block.
- **Empty allowlist = REFUSED** (this phase): Inverts DSYNC SourceACL D-05 ("empty = accept all"); documents the deliberate difference for zone transfer security.
- **Nil-guard accessors**: `GetTsigKeyRing()` returns nil when TSIG not configured — AXFR handler must nil-guard before use.
- **TCP vs. UDP detection**: `w.RemoteAddr()` type-assert to `*net.TCPAddr` vs. `*net.UDPAddr` (already used in handleDNS for counter split)

### Integration Points
- `handleDNS()` — new early-dispatch block for TypeAXFR, placed after NOTIFY block (line ~500)
- `server.go` — new `handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP)` method (or call into axfr.go)
- `ZoneConfig` lookup — server needs a way to find `ZoneConfig` for a given zone origin at request time (server.cfg.Zones is a slice; may need an indexed map built at startup)

### Pre-existing Test Failures (not our code)
- `internal/engine/TestResolver_Resolve` — live DNS query; not a regression
- `internal/resolver/TestFindGlue` — pre-existing assertion bug; not a regression

</code_context>

<specifics>
## Specific Requirements

- **XFER-01**: AXFR request over TCP receives complete zone: opening SOA + all RRs + closing SOA
- **XFER-02**: AXFR request signed with a known TSIG key is accepted; unsigned requests → NOTAUTH
- **XFER-03**: AXFR request from IP not in `allow_transfer` → REFUSED regardless of TSIG

</specifics>

<deferred>
## Deferred Ideas

- **IXFR server** — incremental zone transfers (RFC 1995); requires per-zone change journal; deferred to v2 (already in REQUIREMENTS.md v2 backlog as XFER-04)
- **NOTIFY-on-transfer** — sending NOTIFY to `also_notify` targets when zone changes; out of scope for this phase
- **Per-zone TSIG key binding** — restricting a zone to a specific named key (rather than any valid key in KeyRing); could be a follow-up if multi-tenant key isolation is needed
- **Catalog zones (RFC 9432)** — zone provisioning; deferred to v2 as XFER-05

None of the above were user-requested — noted to prevent scope confusion.

</deferred>

---

*Phase: 12-axfr-server*
*Context gathered: 2026-05-23*
