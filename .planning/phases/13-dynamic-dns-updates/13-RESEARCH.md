# Phase 13: Dynamic DNS Updates - Research

**Researched:** 2026-05-23
**Domain:** RFC 2136 DNS UPDATE opcode — server-side implementation in Go using miekg/dns
**Confidence:** HIGH

## Summary

Phase 13 adds server-side RFC 2136 Dynamic DNS Update support. The server receives UPDATE opcodes, validates TSIG authentication and per-zone IP ACLs, evaluates up to 5 prerequisite types atomically, applies add/delete mutations on a zone clone, swaps the zone reference on success, and auto-increments the SOA serial. The implementation follows the established pattern from Phase 12 AXFR: early-dispatch in `handleDNS`, new file `internal/server/update.go`, reuse of `dsync.SourceACL` and `tsig.KeyRing`.

The codebase is in excellent shape for this phase. All required infrastructure is already present: `zone.Zone.Clone()`, `zone.Zone.IncrementSerial()`, `zone.Zone.AddRecord()`, `zone.Zone.Validate()`, `dsync.SourceACL`/`NewSourceACL`, and the AXFR handler as a structural template. The zone map is `s.cfg.Zones map[string]*zone.Zone` with no existing mutex — the per-zone `updateMu sync.Mutex` (D-06) must be added to `zone.Zone` to serialize concurrent UPDATEs for the same zone.

**Primary recommendation:** Mirror the AXFR handler pattern exactly (TSIG presence → TSIG validity → zone lookup → ACL check → processing), add the three delete methods and `updateMu` to `zone.Zone`, extend `ZoneConfig` with `AllowUpdate` and `PersistUpdates`, wire a new `ZoneUpdateCIDRs` map through `main.go` into `server.Config`, and write the swap as `s.cfg.Zones[zoneName] = clonedZone`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| UPDATE opcode dispatch | API / Backend (DNS server) | — | DNS protocol is server-side; no client-side component |
| TSIG authentication | API / Backend (DNS server) | — | Key verification done at server intake |
| IP ACL enforcement | API / Backend (DNS server) | — | Source IP only knowable at server transport layer |
| Prerequisite evaluation | API / Backend (DNS server) | Zone layer | Logic in handler; zone provides read access |
| Zone mutation (add/delete) | Zone layer | — | Zone owns its own state; handler delegates to zone methods |
| Atomic clone-and-swap | Zone layer + Server | — | Clone in zone, reference swap in server |
| SOA serial increment | Zone layer | — | Existing `IncrementSerial()` already owned by zone |
| Persistence to disk | Config / Storage | Zone layer | YAML marshal of ZoneConfig; separate from in-memory mutation |

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Implement full prerequisites — all 5 RFC 2136 §2 prerequisite types: rrset-exists, rrset-not-exists, name-in-use, name-not-in-use, RR-value-exists.
- **D-02:** Per-spec rcodes per prerequisite failure type per RFC 2136 §3.2 (NXRRSET=8, YXRRSET=6 [note: miekg uses 7 for YXRrset], NXDOMAIN=3, YXDOMAIN=6, REFUSED=5). Planner implements exactly per RFC.
- **D-03:** Evaluate ALL prerequisites atomically before applying any update. If any prerequisite fails, return the appropriate error rcode and apply zero updates.
- **D-04:** Enforce illegal update detection — reject: delete-SOA, delete-all-NS records, CNAME coexistence violations. Return REFUSED.
- **D-05:** All-or-nothing atomic apply — stage on `zone.Clone()`, apply to clone, run `zone.Validate()`, then atomically swap the server's zone reference. On any failure the original zone is untouched.
- **D-06:** Per-zone mutex serializes concurrent UPDATE messages for the same zone. Add `updateMu sync.Mutex` to `zone.Zone`. Concurrent updates to different zones proceed in parallel.
- **D-07:** Implement all 3 RFC 2136 §2.5 delete variants: delete-all-rrsets-at-name (ANY/ANY), delete-rrset (ANY/type), delete-specific-RR (NONE/type with rdata).
- **D-08:** Add zone-level mutation methods: `DeleteRecord(rr dns.RR) error`, `DeleteRRSet(owner string, rrtype uint16) error`, `DeleteName(owner string) error`. Called on the cloned zone.
- **D-09:** Always auto-increment SOA serial after every successful UPDATE using existing `zone.IncrementSerial()`. Treated as MUST.
- **D-10:** SOA records in the Update section are ignored (server owns the serial). Client's attempted SOA SET is silently discarded.
- **D-11:** Add `PersistUpdates *bool` to `ZoneConfig`. Default nil/absent = false (in-memory only).
- **D-12:** Default behavior: updates apply to in-memory zone only. Server restart re-reads zone file and loses dynamic updates.
- **D-13:** When `persist_updates: true`: write the updated zone back in YAML zone config format via `yaml.Marshal` of the updated `ZoneConfig`. No new serializer.
- **D-14:** Write strategy for `persist_updates: true`: Claude's discretion (synchronous vs. debounced async).
- **D-15:** Add `AllowUpdate []string` to `ZoneConfig` (CIDR list). Empty `allow_update` = REFUSED. Secure-by-default.
- **D-16:** TSIG is always required for every UPDATE request. Unsigned requests → NOTAUTH (rcode 9). Reuse existing `tsig.KeyRing`.
- **D-17:** IP ACL failure → REFUSED (rcode 5). Reuse `dsync.SourceACL` / `dsync.NewSourceACL(cidrs)`.
- **D-18:** UPDATE opcode dispatches early in `handleDNS`, before `pool.GetMessage()` and before the defensive path — same pattern as NOTIFY (~line 512) and AXFR (~line 535). Detect `r.Opcode == dns.OpcodeUpdate` right after the AXFR block.
- **D-19:** Handler lives in `internal/server/update.go` as a new file. No new package.

### Claude's Discretion

- Write strategy for `persist_updates: true` (D-14): synchronous on every UPDATE vs. debounced async goroutine.
- How the handler maps zone name from UPDATE Zone section to the server's loaded zone (linear scan vs. lookup map).
- miekg/dns API for detecting TSIG presence/absence (`r.IsTsig()` or inspecting `r.Extra`).
- Message batching/encoding for the UPDATE response (single NOERROR reply, not multi-message).

### Deferred Ideas (OUT OF SCOPE)

- NOTIFY-on-update to secondaries
- IXFR journal of dynamic changes
- DNSSEC re-signing after dynamic updates
- Per-zone TSIG key binding for UPDATE
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DYNUP-01 | Server accepts DNS UPDATE opcode (RFC 2136) and applies add/delete operations to the in-memory zone | Dispatcher at `handleDNS` line ~548; `zone.AddRecord()`, three new delete methods on zone.Zone; clone-and-swap pattern |
| DYNUP-02 | Dynamic updates are TSIG-authenticated; unauthenticated UPDATE requests are rejected | `r.IsTsig()` presence check (same as AXFR); `w.TsigStatus()` validity check; NOTAUTH rcode 9 |
| DYNUP-03 | Update access controlled by per-zone `allow_update` ACL (CIDR list); requests from unlisted sources receive REFUSED | `dsync.SourceACL` / `NewSourceACL`; new `ZoneUpdateCIDRs` in server.Config; same empty=deny semantics as AXFR |
| DYNUP-04 | Successful updates are immediately visible to subsequent queries without zone reload | Atomic pointer swap: `s.cfg.Zones[zoneName] = updatedClone`; `handleAuthoritative()` reads `s.cfg.Zones` on every query |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| github.com/miekg/dns | v1.1.72 | DNS message parsing, OpcodeUpdate, ClassNONE/ClassANY constants, IsTsig(), TsigStatus() | Already the project's DNS library; RFC 2136 UPDATE is a standard opcode miekg supports |
| sync (stdlib) | Go stdlib | `sync.Mutex` for per-zone updateMu | No external dep needed for mutex |
| gopkg.in/yaml.v3 | v3.x | YAML marshal for persist_updates write-back | Already used in config package |

[VERIFIED: go.mod — github.com/miekg/dns v1.1.72]

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| internal/dsync.SourceACL | project-local | CIDR allowlist check for allow_update | Reuse directly; identical semantics to AXFR ACL |
| internal/tsig.KeyRing | project-local | TSIG key store already wired to dns.Server.TsigSecret | GetTsigKeyRing() accessor already on Server |
| zone.Zone.Clone() | project-local | Deep copy for atomic apply | Called before any mutation |
| zone.Zone.Validate() | project-local | Integrity check after mutation | Called on clone before swap |
| zone.Zone.IncrementSerial() | project-local | YYYYMMDDNN serial bump | Called after successful clone validation |

[VERIFIED: internal/zone/zone.go — Clone() line 326, IncrementSerial() line 300, Validate() line 232, AddRecord() line 104]

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Synchronous persist write | Debounced goroutine | Sync is simpler and correct; debounced risks data loss on crash; sync chosen per simplicity principle |
| Linear zone scan for zone lookup | Dedicated lookup map | s.cfg.Zones is already `map[string]*zone.Zone`; O(1) map lookup by FQDN is the correct approach — same as AXFR does at line 63 of axfr.go |

**Installation:** No new dependencies required. All needed libraries are already in go.mod.

## Architecture Patterns

### System Architecture Diagram

```
DNS Client (nsupdate / ddns client)
  |
  | DNS UPDATE message (UDP or TCP, RFC 2136)
  v
handleDNS() in server.go
  |
  +-- r.Opcode == dns.OpcodeUpdate? --> YES --> handleUpdate(w, r, clientIP)
  |                                              |
  |                                              +-- clientIP nil? --> REFUSED
  |                                              |
  |                                              +-- TSIG absent (r.IsTsig()==nil)? --> NOTAUTH
  |                                              |
  |                                              +-- TSIG invalid (w.TsigStatus()!=nil)? --> NOTAUTH
  |                                              |
  |                                              +-- Zone section empty? --> FORMERR
  |                                              |
  |                                              +-- Zone lookup (s.cfg.Zones[zoneName])? --> miss: REFUSED
  |                                              |
  |                                              +-- ACL check (ZoneUpdateACLs[zoneName])? --> fail: REFUSED
  |                                              |
  |                                              +-- Lock zone.updateMu
  |                                              |
  |                                              +-- Evaluate Prerequisites (r.Answer section)
  |                                              |     Each prereq type checked against LIVE zone
  |                                              |     Any failure: unlock, return error rcode
  |                                              |
  |                                              +-- Clone live zone
  |                                              |
  |                                              +-- Apply Update section (r.Ns) to CLONE
  |                                              |     Add: clone.AddRecord(rr)
  |                                              |     Delete-rrset: clone.DeleteRRSet(owner, type)
  |                                              |     Delete-name: clone.DeleteName(owner)
  |                                              |     Delete-RR: clone.DeleteRecord(rr)
  |                                              |     Skip SOA records (D-10)
  |                                              |     Reject delete-SOA, delete-all-NS, CNAME conflict (D-04)
  |                                              |
  |                                              +-- clone.Validate()? --> fail: unlock, SERVFAIL
  |                                              |
  |                                              +-- clone.IncrementSerial()
  |                                              |
  |                                              +-- s.cfg.Zones[zoneName] = clone (atomic swap)
  |                                              |
  |                                              +-- Unlock zone.updateMu
  |                                              |
  |                                              +-- persist_updates: true? --> write YAML to disk
  |                                              |
  |                                              +-- Reply NOERROR
  |
  +-- Normal query path (pool.GetMessage(), handleAuthoritative(), etc.)
```

### Recommended Project Structure
```
internal/
├── server/
│   ├── server.go          # handleDNS: add UPDATE dispatch after AXFR block (~line 548)
│   ├── axfr.go            # Existing — structural template for update.go
│   └── update.go          # NEW: handleUpdate() with full guard chain + RFC 2136 logic
├── zone/
│   └── zone.go            # Add: updateMu sync.Mutex, DeleteRecord(), DeleteRRSet(), DeleteName()
└── config/
    └── config.go          # Add to ZoneConfig: AllowUpdate []string, PersistUpdates *bool
cmd/dnsscienced/
└── main.go                # Wire ZoneUpdateCIDRs from ZoneConfig.AllowUpdate (same as ZoneTransferCIDRs)
```

### Pattern 1: TSIG Presence + Validity Guard (from axfr.go)

**What:** Two-step TSIG check — presence first, validity second. MUST be in this order because an absent TSIG yields `TsigStatus()==nil` (indicating "no error checking was done"), which would silently accept unsigned requests.

**When to use:** Every handler that requires TSIG authentication.

```go
// Source: internal/server/axfr.go lines 35-50 (VERIFIED)

// Step 1: TSIG presence — absent TSIG → NOTAUTH immediately.
if r.IsTsig() == nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m)
    return
}

// Step 2: TSIG validity — bad key, bad sig, replay → NOTAUTH.
if w.TsigStatus() != nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m)
    return
}
```

### Pattern 2: Zone Lookup from UPDATE Zone Section

**What:** RFC 2136 UPDATE uses `r.Question[0]` as the ZONE section (zone FQDN + TypeSOA). This is identical in structure to AXFR zone lookup.

**When to use:** UPDATE zone name extraction.

```go
// Source: internal/server/axfr.go lines 62-70 + miekg/dns defaults.go line 72-80 (VERIFIED)

// In an UPDATE message, Question[0].Name = zone FQDN, Question[0].Qtype = TypeSOA.
zoneName := r.Question[0].Name
z, ok := s.cfg.Zones[zoneName]
if !ok {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m)
    return
}
```

### Pattern 3: ACL Check with Deny-All-on-Empty (from axfr.go)

**What:** `nil` ACL entry (empty allow list) means deny all — secure by default. This differs from DSYNC `SourceACL` which treats empty as allow-all.

**When to use:** `allow_update` enforcement (D-15).

```go
// Source: internal/server/axfr.go lines 75-82 (VERIFIED)
// CRITICAL: Do NOT call NewSourceACL with empty slice for allow_update.
// Empty/absent allow_update => store nil in ZoneUpdateACLs, not allowAll SourceACL.

acl := s.zoneUpdateACLs[zoneName]
if acl == nil || !acl.Check(clientIP) {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m)
    return
}
```

### Pattern 4: RFC 2136 Message Section Mapping

**What:** In UPDATE messages, miekg/dns reuses standard message fields with different semantic meanings.

```
r.Question  = ZONE section      (one entry: zone FQDN, TypeSOA, ClassINET)
r.Answer    = PREREQUISITE section
r.Ns        = UPDATE section    (the actual add/delete instructions)
r.Extra     = ADDITIONAL section (includes TSIG)
```

[VERIFIED: miekg/dns msg.go lines 899-943]

### Pattern 5: Delete Operation Classification (RFC 2136 §2.5)

**What:** Three delete variants distinguished by RR header fields in the UPDATE section (r.Ns).

```go
// Source: miekg/dns update.go (VERIFIED) + RFC 2136 §2.5

// Variant 1: Delete all RRsets at a name (§2.5.3)
//   rr.Header().Class == dns.ClassANY  AND  rr.Header().Rrtype == dns.TypeANY  AND  rdlength==0
if rr.Header().Class == dns.ClassANY && rr.Header().Rrtype == dns.TypeANY {
    clone.DeleteName(owner)
}

// Variant 2: Delete an RRset (§2.5.2)
//   rr.Header().Class == dns.ClassANY  AND  rr.Header().Rrtype == specific type  AND  rdlength==0
if rr.Header().Class == dns.ClassANY && rr.Header().Rrtype != dns.TypeANY {
    clone.DeleteRRSet(owner, rr.Header().Rrtype)
}

// Variant 3: Delete a specific RR (§2.5.4)
//   rr.Header().Class == dns.ClassNONE  AND  rr.Header().Rrtype == specific type  AND  rdata present
if rr.Header().Class == dns.ClassNONE {
    clone.DeleteRecord(rr)
}
```

### Pattern 6: Per-Zone Mutex for Concurrent Updates

**What:** `updateMu sync.Mutex` added to `zone.Zone` struct. Handler locks before prerequisite evaluation, unlocks after zone swap or error. Serializes concurrent UPDATEs for the same zone; different zones are independent.

```go
// Source: D-06 decision (CONTEXT.md) — pattern mirrors sync.Mutex standard usage

z.updateMu.Lock()
defer z.updateMu.Unlock()

// Evaluate prereqs against live zone z (still locked)
// Clone z -> work on clone
// Swap: s.cfg.Zones[zoneName] = updatedClone
```

**Important:** The mutex is locked on the LIVE zone (`z`), not the clone. After swap, the next UPDATE will find the new zone pointer in `s.cfg.Zones` — they must lock the same underlying zone object, so the pointer read from `s.cfg.Zones` must happen under a server-level read lock, or the UPDATE handler must re-read the zone pointer inside the per-zone lock. The simplest safe pattern: read zone pointer, lock its `updateMu`, validate zone is still current (re-read from map), then proceed.

### Pattern 7: Prerequisite Evaluation (RFC 2136 §3.2)

**What:** Five prereq types, identified by (class, type) combinations in `r.Answer`.

```
(class=ANY,  type=ANY,  name=X, rdata=empty) → "Name is in use"         (§2.4.4) → fail: NXDOMAIN (3)
(class=NONE, type=ANY,  name=X, rdata=empty) → "Name is not in use"     (§2.4.5) → fail: YXDOMAIN (6)
(class=ANY,  type=T,   name=X, rdata=empty) → "RRset exists (any)"     (§2.4.1) → fail: NXRRSET (8)
(class=NONE, type=T,   name=X, rdata=empty) → "RRset does not exist"   (§2.4.3) → fail: YXRRSET (7)
(class=ZCLASS,type=T,  name=X, rdata=full)  → "RRset exists (value)"   (§2.4.2) → fail: NXRRSET (8)
```

[VERIFIED: miekg/dns update.go helper methods + RFC 2136 §3.2]

**Note on rcodes:** CONTEXT.md D-02 lists YXRRSET=6 but miekg/dns defines `RcodeYXRrset=7` and `RcodeYXDomain=6`. The RFC 2136 §3.2 table is authoritative: use miekg constants directly:
- `dns.RcodeYXDomain` = 6 (name exists when shouldn't)
- `dns.RcodeYXRrset` = 7 (rrset exists when shouldn't) — **CONTEXT.md D-02 has a typo; miekg value 7 is correct per RFC**
- `dns.RcodeNXRrset` = 8 (rrset should exist, doesn't)
- `dns.RcodeNameError` = 3 (NXDOMAIN)
- `dns.RcodeRefused` = 5

[VERIFIED: miekg/dns types.go lines 129-149]

### Anti-Patterns to Avoid

- **Empty allow_update → NewSourceACL([]string{}) → allowAll=true**: `NewSourceACL` with empty slice returns `allowAll=true` (DSYNC semantics). For `allow_update`, intercept empty case and store `nil` — same as AXFR does for `zoneTransferACLs`. [VERIFIED: dsync/source_acl.go line 27-28 comment]
- **Locking only the clone**: The lock must protect the prereq evaluation against the LIVE zone. Clone after lock, not before.
- **Not nil-guarding GetTsigKeyRing()**: Returns nil when TSIG not configured. UPDATE handler must handle nil keyring (return NOTAUTH for all requests when no keyring configured).
- **SOA records in Update section**: RFC 2136 §3.4.2.7 — SOA records in the Update section are processed but the serial is discarded. Server keeps its own serial. D-10 decision: silently skip SOA RRs in the Update section.
- **Missing CNAME coexistence check for Add operations**: Adding a non-CNAME at a name that has a CNAME, or adding a CNAME at a name with other records, must be rejected. `zone.Validate()` catches this after apply — confirm Validate() covers the CNAME check before relying on it.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TSIG verification | Custom HMAC logic | miekg auto-verify via `dns.Server.TsigSecret` + `w.TsigStatus()` | Already wired; hand-roll would miss replay/time attacks |
| IP CIDR matching | Custom IP range parser | `dsync.NewSourceACL(cidrs)` | Already in codebase; handles /32, /128, invalid CIDR errors |
| Zone deep copy | Manual field copy | `zone.Clone()` | Already deep-copies all records including SOA; misses DNSSEC fields if done by hand |
| YAML serialization for persist | Custom zone file writer | `yaml.Marshal` of `ZoneConfig` | D-13: no new serializer needed |
| DNS message construction | Manual wire encoding | `m.SetReply(r)` + `m.Rcode = ...` + `w.WriteMsg(m)` | Standard miekg response pattern |

**Key insight:** The entire guard chain (TSIG presence, TSIG validity, zone lookup, ACL) is already proven by Phase 12 AXFR. The UPDATE handler is an AXFR handler with the streaming section replaced by RFC 2136 prerequisite + update logic.

## Common Pitfalls

### Pitfall 1: Zone Pointer Race After Swap
**What goes wrong:** Two concurrent UPDATE goroutines for the same zone. Goroutine A reads zone pointer, clones it, makes changes. Goroutine B reads the same pointer, clones it, swaps a different clone. A's swap overwrites B's update.
**Why it happens:** `s.cfg.Zones` is an unprotected map. Zone pointer reads are not serialized.
**How to avoid:** Per-zone `updateMu sync.Mutex` on `zone.Zone` (D-06). Lock before reading prereqs, unlock after swap. The mutex is on the `zone.Zone` object itself, so it survives the swap — BUT the handler must lock the zone it read from the map before the clone, and only proceed if that zone is still the current one. Simplest correct pattern: read pointer from map, lock its mutex, re-read pointer from map, assert same pointer (or restart), then proceed.
**Warning signs:** Occasional lost updates under concurrent load. Race detector (`-race`) will flag the map write.

### Pitfall 2: Missing SOA / NS Protection for Delete-Name
**What goes wrong:** `DeleteName(zoneName)` removes ALL rrsets at the apex, including SOA and NS. This leaves the zone invalid.
**Why it happens:** RFC 2136 §3.4.2.4 permits delete-name on the zone apex but implementations must protect SOA and NS at the apex.
**How to avoid:** D-04 enforcement in the Update section processing loop: before calling `clone.DeleteName(owner)`, if `owner == zone.Origin`, return REFUSED. Alternatively, `clone.Validate()` catches missing SOA/NS and returns SERVFAIL — but REFUSED is the correct pre-apply rejection.

### Pitfall 3: TSIG Presence Order (critical, already documented)
**What goes wrong:** Checking `w.TsigStatus() == nil` first. When no TSIG is present, `TsigStatus()` returns `nil` (no verification error), silently accepting unsigned requests.
**Why it happens:** Intuitive but wrong — `nil` means "no TSIG to check", not "TSIG verified OK".
**How to avoid:** Always check `r.IsTsig() == nil` FIRST. If nil, return NOTAUTH immediately. Then check `w.TsigStatus()`.
**Warning signs:** Unsigned UPDATE requests succeed in tests.

### Pitfall 4: Empty allow_update Treated as Allow-All
**What goes wrong:** Calling `dsync.NewSourceACL([]string{})` for an empty `allow_update`. `NewSourceACL` with empty slice returns `allowAll=true` (DSYNC open-by-default semantics).
**Why it happens:** Same function used for DSYNC (open) and AXFR/UPDATE (closed) contexts with different empty-list semantics.
**How to avoid:** In `main.go` wiring, intercept empty `AllowUpdate` slice: store `nil` in `ZoneUpdateACLs[zoneName]` instead of calling `NewSourceACL`. The handler treats `nil` as deny-all. [VERIFIED: axfr.go lines 73-76, source_acl.go comment lines 27-28]

### Pitfall 5: YXRrset Rcode Value Discrepancy
**What goes wrong:** CONTEXT.md D-02 lists "YXRRSET=6" but miekg/dns defines `RcodeYXRrset=7` and `RcodeYXDomain=6`.
**Why it happens:** Typo/transposition in the discussion document.
**How to avoid:** Use miekg constants by name (`dns.RcodeYXRrset`, `dns.RcodeYXDomain`) — never hardcode numeric rcode values.
**Warning signs:** RFC 2136 clients receiving wrong rcode 6 when rrset-exists prereq fails on a name that exists.

### Pitfall 6: Clone.Validate() Glue Check May SERVFAIL Valid Updates
**What goes wrong:** `zone.Validate()` checks that in-zone nameservers have glue (A/AAAA). A valid RFC 2136 update that adds an NS record before adding its A record will fail validation mid-update.
**Why it happens:** `Validate()` checks the whole zone for consistency, but RFC 2136 allows multi-step updates within one message (the entire Update section is atomic, but the message itself may add both NS and glue in one shot).
**How to avoid:** Apply ALL update operations to the clone before calling `Validate()`. The loop over `r.Ns` applies all adds/deletes first, then a single `Validate()` call at the end. Do not validate after each individual operation.

### Pitfall 7: Persist Write on Failure Path
**What goes wrong:** Accidentally writing the zone file when update fails (e.g., after a prereq failure before the swap has happened).
**Why it happens:** Misplaced persist call.
**How to avoid:** Only write to disk after `s.cfg.Zones[zoneName] = clone` is executed. The persist write is the last step before the success reply.

## Code Examples

### Prerequisite RR Classification
```go
// Source: RFC 2136 §2.4 + miekg/dns update.go (VERIFIED)

func classifyPrereq(rr dns.RR, zoneClass uint16) prereqType {
    h := rr.Header()
    switch {
    case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY:
        return prereqNameInUse        // §2.4.4
    case h.Class == dns.ClassNONE && h.Rrtype == dns.TypeANY:
        return prereqNameNotInUse     // §2.4.5
    case h.Class == dns.ClassANY:
        return prereqRRSetExists      // §2.4.1 (value independent)
    case h.Class == dns.ClassNONE:
        return prereqRRSetNotExists   // §2.4.3
    case h.Class == zoneClass:
        return prereqRRSetExistsValue // §2.4.2 (value dependent)
    default:
        return prereqFormatError
    }
}
```

### Zone Method Signatures to Add
```go
// Source: D-08 decision (CONTEXT.md), mirrors AddRecord() style (VERIFIED: zone.go line 104)

// DeleteRecord removes a specific RR by exact match (class, type, rdata).
// Returns nil if the record was not found (no-op, per RFC 2136 §3.4.2.5).
func (z *Zone) DeleteRecord(rr dns.RR) error

// DeleteRRSet removes all records of the given type at the given owner.
// Returns nil if no such rrset exists (no-op).
func (z *Zone) DeleteRRSet(owner string, rrtype uint16) error

// DeleteName removes all rrsets at the given owner name.
// Returns nil if the name does not exist (no-op).
func (z *Zone) DeleteName(owner string) error
```

### Wire ZoneUpdateCIDRs in main.go
```go
// Source: cmd/dnsscienced/main.go lines 144-157 (VERIFIED — ZoneTransferCIDRs wiring)

// Wire per-zone allow_update CIDRs from zone config into server config.
if len(loadedCfg.Zones) > 0 {
    cfg.ZoneUpdateCIDRs = make(map[string][]string, len(loadedCfg.Zones))
    for _, zc := range loadedCfg.Zones {
        zoneName := zc.Name
        if !strings.HasSuffix(zoneName, ".") {
            zoneName += "."
        }
        cfg.ZoneUpdateCIDRs[zoneName] = zc.AllowUpdate
    }
}
```

### Dispatch in handleDNS
```go
// Source: internal/server/server.go lines 533-550 (VERIFIED — AXFR block placement)
// Insert AFTER the AXFR/IXFR block, BEFORE pool.GetMessage():

if r.Opcode == dns.OpcodeUpdate {
    if clientIP == nil {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m)
        return
    }
    s.handleUpdate(w, r, clientIP)
    return
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| RFC 2136 implementation from scratch | Build on Phase 12 AXFR infrastructure | Phase 12 (this milestone) | Guard chain, TSIG, and ACL patterns are proven and tested |
| Custom TSIG handling | miekg auto-verify + explicit presence check | Phase 6 Plan 05 | Correct two-step guard is established project pattern |
| In-place zone mutation | Clone-and-swap atomicity | D-05 decision | Eliminates rollback complexity; aligns with Phase 12 zone pointer write |

## Runtime State Inventory

Step 2.5: SKIPPED — Phase 13 is greenfield addition, not a rename or migration. No runtime state uses a string that this phase renames.

## Environment Availability

Step 2.6: All required tools already confirmed available.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| go toolchain | Build + test | Yes | go1.23+ (project baseline) | — |
| github.com/miekg/dns | UPDATE parsing | Yes | v1.1.72 | — |
| gopkg.in/yaml.v3 | persist_updates write-back | Yes | existing in go.mod | — |

[VERIFIED: go build ./... exits 0; go test ./internal/server/... exits 0]

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go testing stdlib |
| Config file | none — standard `go test` |
| Quick run command | `go test ./internal/server/... ./internal/zone/... -run TestHandleUpdate -v` |
| Full suite command | `go test -race ./internal/server/... ./internal/zone/... ./internal/dsync/...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DYNUP-01 | Add RR via UPDATE visible in subsequent query | integration | `go test ./internal/server/... -run TestHandleUpdate_AddRecord` | ❌ Wave 0 |
| DYNUP-01 | Delete RR via UPDATE invisible in subsequent query | integration | `go test ./internal/server/... -run TestHandleUpdate_DeleteRecord` | ❌ Wave 0 |
| DYNUP-01 | All 5 prereq types evaluated correctly | unit | `go test ./internal/server/... -run TestHandleUpdate_Prereq` | ❌ Wave 0 |
| DYNUP-02 | Unsigned UPDATE → NOTAUTH (9) | unit | `go test ./internal/server/... -run TestHandleUpdate_NoTSIG_NotAuth` | ❌ Wave 0 |
| DYNUP-02 | Bad TSIG signature → NOTAUTH (9) | unit | `go test ./internal/server/... -run TestHandleUpdate_BadTSIG_NotAuth` | ❌ Wave 0 |
| DYNUP-03 | IP not in allow_update → REFUSED (5) | unit | `go test ./internal/server/... -run TestHandleUpdate_IPNotAllowed_Refused` | ❌ Wave 0 |
| DYNUP-03 | Empty allow_update → REFUSED (5) | unit | `go test ./internal/server/... -run TestHandleUpdate_EmptyAllowUpdate_Refused` | ❌ Wave 0 |
| DYNUP-04 | Successful update immediately visible | integration | `go test ./internal/server/... -run TestHandleUpdate_ImmediateVisibility` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/server/... ./internal/zone/... -run TestHandleUpdate`
- **Per wave merge:** `go test -race ./internal/server/... ./internal/zone/... ./internal/dsync/...`
- **Phase gate:** `go test -race ./internal/server/... ./internal/zone/... ./internal/dsync/... ./internal/config/...` all green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/server/update_test.go` — all DYNUP requirement tests (mirrors axfr_test.go structure)
- [ ] `internal/zone/zone_mutation_test.go` — covers DeleteRecord, DeleteRRSet, DeleteName methods

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | TSIG via miekg auto-verify + explicit presence check (r.IsTsig()) |
| V3 Session Management | no | DNS is stateless; TSIG covers per-message auth |
| V4 Access Control | yes | Per-zone allow_update CIDR ACL via dsync.SourceACL |
| V5 Input Validation | yes | RFC 2136 §3.2 prerequisite validation; illegal update rejection (D-04) |
| V6 Cryptography | yes | TSIG HMAC — never hand-rolled; handled by miekg + existing tsig.KeyRing |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unauthorized zone modification | Tampering | TSIG required (D-16) + IP ACL (D-15/D-17) |
| Replay attack via old TSIG | Spoofing | miekg TSIG time window + fudge check (handled by TsigStatus) |
| Zone exhaustion via infinite adds | DoS | Not in scope for this phase; mitigated by existing RRL (rrl.Limiter) on query path |
| Delete-all-NS attack | Tampering | D-04: reject delete-all-NS; detected in illegal update check before clone apply |
| CNAME injection | Tampering | D-04: CNAME coexistence check; zone.Validate() catches after apply |
| Race condition on zone pointer | Tampering | D-06: per-zone updateMu serializes concurrent updates |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `zone.Validate()` checks CNAME coexistence violations | Architecture Patterns (Anti-Patterns) | If Validate() doesn't check CNAMEs, D-04 CNAME protection fails silently; handler must add explicit CNAME check before add operations |
| A2 | Synchronous persist write is appropriate for `persist_updates: true` (discretion item D-14) | Standard Stack Alternatives | If write latency is unacceptable under high update rate, debounced async is preferred; low risk since persist is opt-in and rare |

[VERIFIED: zone.go lines 267-277 — Validate() does check CNAME coexistence. A1 is confirmed, not assumed.]

**If this table is empty after A1 verification:** All claims were verified. A2 remains as a discretion-area assumption (low risk, opt-in feature).

## Sources

### Primary (HIGH confidence)
- `internal/server/axfr.go` — TSIG guard pattern, ACL pattern, zone lookup pattern, early dispatch (VERIFIED: read in session)
- `internal/zone/zone.go` — Clone(), IncrementSerial(), AddRecord(), Validate(), HasName(), GetRecords() (VERIFIED: read in session)
- `internal/dsync/source_acl.go` — NewSourceACL empty-list semantics, Check() interface (VERIFIED: read in session)
- `internal/server/server.go` — handleDNS dispatch blocks, Server struct, cfg.Zones map, zone accessor methods (VERIFIED: read in session)
- `internal/config/config.go` — ZoneConfig struct, existing AllowTransfer field as template (VERIFIED: read in session)
- `github.com/miekg/dns@v1.1.72/types.go` — OpcodeUpdate=5, ClassNONE=254, ClassANY=255, all RFC 2136 rcodes (VERIFIED: read in session)
- `github.com/miekg/dns@v1.1.72/update.go` — UPDATE section helpers, delete variant classification (VERIFIED: read in session)
- `github.com/miekg/dns@v1.1.72/defaults.go` — SetUpdate() showing Question[0]=zone/TypeSOA/ClassINET structure (VERIFIED: read in session)
- `github.com/miekg/dns@v1.1.72/msg.go` — UPDATE message section semantics (Question=ZONE, Answer=PREREQ, Ns=UPDATE) (VERIFIED: read in session)
- `cmd/dnsscienced/main.go` — ZoneTransferCIDRs wiring pattern (VERIFIED: read in session)

### Secondary (MEDIUM confidence)
- RFC 2136 (Dynamic Updates in the Domain Name System) — prerequisite types §2.4, delete variants §2.5, evaluation order §3.4, rcode assignments §3.2 [ASSUMED from training knowledge; miekg constants cross-verified]
- RFC 2845 (TSIG) — NOTAUTH response code semantics [ASSUMED from training; cross-verified with miekg RcodeNotAuth=9]

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries verified in go.mod and source
- Architecture: HIGH — all integration points verified by direct source reading
- Pitfalls: HIGH — critical pitfalls (TSIG order, empty ACL) verified directly from axfr.go and source_acl.go comments
- RFC rcode values: HIGH — verified from miekg/dns types.go; noted D-02 typo in CONTEXT.md

**Research date:** 2026-05-23
**Valid until:** 2026-06-23 (stable library; miekg/dns API changes slowly)
