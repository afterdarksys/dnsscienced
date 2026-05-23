# Phase 13: Dynamic DNS Updates - Context

**Gathered:** 2026-05-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Implement RFC 2136 Dynamic DNS Update support. The server accepts UPDATE opcodes, applies add/delete operations to the in-memory zone atomically, authenticates with TSIG, and enforces per-zone `allow_update` CIDR ACLs. Successful updates are immediately visible to subsequent queries.

This phase does NOT include: NOTIFY-on-update to secondaries, journaling/IXFR history of dynamic changes, or DNSSEC re-signing after updates.

</domain>

<decisions>
## Implementation Decisions

### Prerequisites (RFC 2136 §2)

- **D-01:** Implement **full prerequisites** — all 5 RFC 2136 §2 prerequisite types: rrset-exists, rrset-not-exists, name-in-use, name-not-in-use, RR-value-exists.
- **D-02:** Per-spec rcodes per prerequisite failure type per RFC 2136 §3.2 (e.g., NXRRSET=8, YXRRSET=6, NXDOMAIN=3, YXDOMAIN=6, REFUSED=5). Planner implements exactly per RFC — no simplification to a single rcode.
- **D-03:** Evaluate ALL prerequisites atomically before applying any update. If any prerequisite fails, return the appropriate error rcode and apply **zero** updates.
- **D-04:** Enforce illegal update detection — reject: delete-SOA, delete-all-NS records (would leave zone without nameservers), CNAME coexistence violations. Return REFUSED for these.
- **D-05:** All-or-nothing atomic apply — stage all changes on `zone.Clone()`, apply to the clone, run `zone.Validate()`, then atomically swap the server's zone reference on success. On any failure the original zone is untouched (no rollback logic needed).
- **D-06:** Per-zone mutex serializes concurrent UPDATE messages for the same zone. Add `updateMu sync.Mutex` to `zone.Zone`. Concurrent updates to different zones proceed in parallel.

### Delete Operation Variants

- **D-07:** Implement all 3 RFC 2136 §2.5 delete variants:
  - Delete all rrsets at a name: class=ANY, type=ANY, rdlength=0
  - Delete an rrset: class=ANY, type=X, rdlength=0
  - Delete a specific RR: class=NONE, type=X, rdata=present
- **D-08:** Add zone-level mutation methods to `zone.Zone` for delete operations: `DeleteRecord(rr dns.RR) error`, `DeleteRRSet(owner string, rrtype uint16) error`, `DeleteName(owner string) error`. These are called on the cloned zone during the atomic apply step (D-05).

### SOA Serial Management

- **D-09:** Always auto-increment the SOA serial after every successful UPDATE using the existing `zone.IncrementSerial()`. RFC 2136 §3.7 SHOULD requirement is treated as MUST.
- **D-10:** SOA records in the Update section are ignored (server owns the serial). A client attempting to set the serial via UPDATE will have the attempt silently discarded; the server increments its own serial.

### Zone File Persistence

- **D-11:** Add `PersistUpdates *bool` to `ZoneConfig` (`internal/config/config.go`). Default `nil`/absent = false (in-memory only). Operators explicitly set `persist_updates: true` to opt in to disk persistence.
- **D-12:** Default behavior (absent or false): updates apply to the in-memory zone only. A server restart re-reads the zone file and loses any dynamic updates.
- **D-13:** When `persist_updates: true`: write the updated zone back in YAML zone config format (matching the existing `config.go` ZoneConfig format). No new serializer needed beyond yaml.Marshal of the updated ZoneConfig.
- **D-14:** Write strategy for `persist_updates: true` — planner decides (synchronous vs. debounced async). Claude's discretion based on codebase patterns.

### ACL and Authentication (carried forward from Phase 12)

- **D-15:** Add `AllowUpdate []string` to `ZoneConfig` (CIDR list). Empty `allow_update` list = **REFUSED**. Secure-by-default, same semantics as `allow_transfer` (D-01 from Phase 12 CONTEXT.md).
- **D-16:** TSIG is **always required** for every UPDATE request. Unsigned requests → **NOTAUTH** (rcode 9). Reuse existing `tsig.KeyRing` and miekg/dns TSIG auto-verify — handler must additionally check that TSIG was present (miekg/dns verifies a present TSIG but does not reject a missing one).
- **D-17:** IP ACL failure (source not in allow_update) → **REFUSED** (rcode 5). Reuse `dsync.SourceACL` / `dsync.NewSourceACL(cidrs)` for the CIDR check.

### Handler Location and Dispatch

- **D-18:** UPDATE opcode dispatches **early in `handleDNS`**, before `pool.GetMessage()` and before the defensive path — same pattern as NOTIFY (line ~512) and AXFR (line ~535). Detect `r.Opcode == dns.OpcodeUpdate` right after the AXFR block.
- **D-19:** Handler lives in **`internal/server/update.go`** as a new file (same as `axfr.go`). No new package — complexity is comparable to AXFR, not DSYNC.

### Claude's Discretion

- Write strategy for `persist_updates: true` (D-14): synchronous on every UPDATE vs. debounced async goroutine — planner determines based on simplicity and existing patterns.
- How the handler maps zone name from UPDATE Zone section to the server's loaded zone (linear scan of `s.cfg.Zones` vs. a lookup map built at startup) — same open question as AXFR's ZoneConfig lookup.
- miekg/dns API for detecting TSIG presence/absence (`r.IsTsig()` or inspecting `r.Extra`) — planner confirms correct API.
- Message batching/encoding for the UPDATE response (single NOERROR reply, not multi-message like AXFR).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Primary Implementation Targets
- `internal/server/server.go` — `handleDNS()` dispatch block; add UPDATE opcode detection after AXFR block (~line 535). New `handleUpdate()` method or call into `update.go`.
- `internal/config/config.go` — `ZoneConfig` struct (line 74–); add `AllowUpdate []string` and `PersistUpdates *bool` fields.
- `internal/zone/zone.go` — add `updateMu sync.Mutex`, `DeleteRecord()`, `DeleteRRSet()`, `DeleteName()` methods; `Clone()` (line 326) and `IncrementSerial()` (line 300) are reused.

### Reusable Infrastructure
- `internal/tsig/` — `KeyRing`, `Verify`, `Sign`; `GetTsigKeyRing()` accessor on Server
- `internal/dsync/source_acl.go` — `SourceACL`, `NewSourceACL(cidrs)`, `Check(net.IP) bool` — directly reusable for `allow_update` CIDR enforcement

### Phase 12 AXFR Reference (patterns to follow)
- `.planning/phases/12-axfr-server/12-CONTEXT.md` — ACL/TSIG decisions (D-01 to D-10) that Phase 13 extends
- `internal/server/axfr.go` — handler structure pattern (TSIG presence check, ACL check, early dispatch)

### RFCs
- RFC 2136 — Dynamic Updates in the Domain Name System (DNS UPDATE) — primary spec; §2 prerequisites, §2.5 delete operations, §3.2 evaluation order, §3.4 update processing, §3.7 serial increment
- RFC 2845 — Secret Key Transaction Authentication for DNS (TSIG) — §4 NOTAUTH response code

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dsync.SourceACL` / `dsync.NewSourceACL(cidrs)` — the `allow_update` CIDR check is identical in logic to NOTIFY and AXFR source ACL; import directly
- `zone.Zone.Clone()` — used for atomic apply: clone → mutate → validate → swap reference
- `zone.Zone.IncrementSerial()` — called after every successful UPDATE (line 300)
- `zone.Zone.AddRecord(rr dns.RR)` — used for the Add operation in Update section
- `zone.Zone.Validate()` — called on the cloned zone after mutation to catch zone integrity violations before swap
- `tsig.KeyRing` / `server.GetTsigKeyRing()` — shared KeyRing already wired to `dns.Server.TsigSecret`

### Established Patterns
- **Early opcode dispatch** (`handleDNS` lines 510–548): NOTIFY checks `r.Opcode == dns.OpcodeNotify`, AXFR checks `r.Question[0].Qtype == dns.TypeAXFR`. UPDATE adds `r.Opcode == dns.OpcodeUpdate` right after.
- **Empty allowlist = REFUSED** (same as Phase 12 `allow_transfer`): `allow_update` follows identical ACL semantics.
- **TSIG presence enforcement**: AXFR handler checks TSIG was present (not just valid) — UPDATE handler replicates same two-step check (miekg auto-verifies presence TSIG; handler must additionally require it).
- **Nil-guard accessors**: `GetTsigKeyRing()` returns nil when TSIG not configured — UPDATE handler nil-guards before use.

### Integration Points
- `handleDNS()` in `server.go` — new early-dispatch block for `dns.OpcodeUpdate`, placed after the AXFR block (~line 548)
- `ZoneConfig` in `config.go` — new fields `AllowUpdate []string` and `PersistUpdates *bool`
- `zone.Zone` struct in `zone.go` — new `updateMu sync.Mutex` field and 3 delete methods
- Zone reference swap — server needs to replace its in-memory zone pointer after a successful update (same challenge as zone reload; check how existing zone reload works)

### Pre-existing Test Failures (not our code)
- `internal/engine/TestResolver_Resolve` — live DNS query; not a regression
- `internal/resolver/TestFindGlue` — pre-existing assertion bug; not a regression

</code_context>

<specifics>
## Specific Ideas

- The clone-and-swap atomicity model (D-05) avoids any rollback logic: the original zone is untouched until the clone passes validation. This is a deliberate simplicity choice over in-place mutation with a transaction journal.
- Prerequisites evaluation (D-03) must complete entirely before the Update section processing begins (D-05). RFC 2136 §3.4 evaluation order: Zones → Prerequisites → Update → Notifies. We skip Notifies (out of scope).
- The three delete methods (D-08) should mirror `AddRecord()`'s signature style and error semantics for consistency.

</specifics>

<deferred>
## Deferred Ideas

- **NOTIFY-on-update to secondaries** — sending NOTIFY to `also_notify` targets after a dynamic update changes a zone. Out of scope for this phase; secondaries detect changes via periodic SOA serial polling or manual AXFR.
- **IXFR journal of dynamic changes** — tracking the diff for incremental zone transfers (RFC 1995). Would require a per-zone change log; deferred to v2.
- **DNSSEC re-signing after dynamic updates** — automatically re-signing affected RRsets after an UPDATE. Requires DNSSEC signing infrastructure; deferred.
- **Per-zone TSIG key binding for UPDATE** — restricting UPDATE to a specific named key per zone (rather than any valid key in KeyRing); could be a follow-up for multi-tenant key isolation.

</deferred>

---

*Phase: 13-dynamic-dns-updates*
*Context gathered: 2026-05-23*
