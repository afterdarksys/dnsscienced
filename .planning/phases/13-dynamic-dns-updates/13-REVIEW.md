---
phase: 13-dynamic-dns-updates
reviewed: 2026-05-23T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - cmd/dnsscienced/main.go
  - internal/config/config.go
  - internal/server/server.go
  - internal/server/update.go
  - internal/server/update_test.go
  - internal/zone/zone.go
  - internal/zone/zone_mutation_test.go
findings:
  critical: 5
  warning: 6
  info: 3
  total: 14
status: issues_found
---

# Phase 13: Code Review Report

**Reviewed:** 2026-05-23T00:00:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

This phase introduces RFC 2136 dynamic DNS update support including a full
guard chain (TSIG presence → TSIG validity → ACL → prerequisites → clone →
apply → validate → swap), SOA/NS deletion guards, and optional persist-to-disk
with atomic rename. The structural design is sound but there are five blockers
that must be fixed before this ships: a race condition on zone map reads, a
case-sensitivity hole in zone lookup, the NS-delete-rrset guard allowing
deletion by counting records in the clone rather than verifying the live count,
missing TSIG in the NOERROR reply leaking authentication state to the client,
and unsafe IncrementSerial wrap-around that could silently roll a production
serial to zero.

---

## Critical Issues

### CR-01: Data Race — Zone Map Read in handleUpdate Is Not Protected

**File:** `internal/server/update.go:156-158`

**Issue:** `handleUpdate` reads `s.cfg.Zones[zoneName]` (step 4) without holding
any lock. `s.cfg.Zones` is a plain `map[string]*zone.Zone`; concurrent goroutines
from other DNS handlers (`handleAuthoritative`, AXFR, gRPC `AddZone`/`RemoveZone`)
read and write this map simultaneously. Go's race detector will flag this as a
data race. The zone-level `updateMu` lock is only acquired *after* the lookup
(step 6), leaving the map access itself unprotected.

```go
// Buggy:
z, ok := s.cfg.Zones[zoneName]   // ← bare map read, no lock held
if !ok {
    sendRcode(dns.RcodeRefused)
    return
}
// ...
z.Lock()
```

**Fix:** Protect the zone map with a `sync.RWMutex` on `Server` (or convert
`s.cfg.Zones` to a `sync.Map`). Acquire an `RLock` around the lookup:

```go
s.zonesMu.RLock()
z, ok := s.cfg.Zones[zoneName]
s.zonesMu.RUnlock()
if !ok {
    sendRcode(dns.RcodeRefused)
    return
}
```

The atomic swap at step 12 (`s.cfg.Zones[zoneName] = clone`) has the same
problem and must be done under a write lock.

---

### CR-02: Zone Lookup Uses Wire-Format Name Without Canonicalization

**File:** `internal/server/update.go:155-158`

**Issue:** `zoneName` is taken directly from `r.Question[0].Name`, which the
`miekg/dns` library preserves in its original case (clients may send any
mix of uppercase/lowercase per RFC 4343). The zone map (`s.cfg.Zones`) is
keyed by lowercase FQDN strings (e.g. `"example.com."`). A client sending
`"EXAMPLE.COM."` in the UPDATE's Zone section will receive REFUSED even though
the zone exists, because the map key does not match.

```go
zoneName := r.Question[0].Name   // e.g. "EXAMPLE.COM." — map key miss
z, ok := s.cfg.Zones[zoneName]
```

**Fix:** Canonicalize the zone name to lowercase before map lookup:

```go
zoneName := strings.ToLower(r.Question[0].Name)
z, ok := s.cfg.Zones[zoneName]
```

The same pattern is already used in `handleAuthoritative` via `dns.IsSubDomain`
(which is case-insensitive), but the UPDATE path performs a direct map key
comparison and is therefore case-sensitive.

---

### CR-03: NS Delete-RRSet Guard Counts Records in Clone, Not Live Zone

**File:** `internal/server/update.go:244-250`

**Issue:** When processing a `ClassANY / TypeNS` delete-rrset directive at the
zone apex, the guard checks `clone.GetRecords(owner, dns.TypeNS)` to decide
whether this would be the last NS record. But `clone` has already had earlier
update operations in the same message applied to it (the loop processes
`r.Ns` sequentially, mutating `clone` in place). If a previous update entry
in the same message *added* an NS record, the count will be inflated and a
subsequent delete-all-NS directive will be incorrectly permitted.

RFC 2136 §3.4.2 requires that the guard logic operate on the zone's *final*
state only after all update directives are applied; but the intent of the
SOA/NS guard is a hard floor, not a sequencing issue. The real problem is
that the count check uses the mid-mutation clone rather than a stable snapshot.

```go
// Buggy:
existing := clone.GetRecords(owner, dns.TypeNS)  // may include NS added earlier in this loop
if len(existing) <= 1 {
    sendRcode(dns.RcodeRefused)
    return
}
```

**Fix:** Evaluate the guard against the live zone (`z`), which is the stable
pre-update snapshot, or perform a post-apply validation check in `clone.Validate()`
that enforces a minimum NS count at the apex:

```go
// Use the live zone for the floor check:
liveNS := z.GetRecords(owner, dns.TypeNS)
if len(liveNS) <= 1 {
    sendRcode(dns.RcodeRefused)
    return
}
```

---

### CR-04: NOERROR Reply Does Not Include TSIG — Client Cannot Verify Response Authenticity

**File:** `internal/server/update.go:297-299`

**Issue:** The success response is built as a bare `*dns.Msg` without a TSIG
record. RFC 2845 §3.2 requires that the server TSIG-sign its response when
the request was TSIG-authenticated. The `miekg/dns` library performs automatic
TSIG signing only on messages sent via a `dns.Server` whose `TsigSecret` map
is populated *and* when writing through the regular server path — direct
`w.WriteMsg(m)` calls from opcode handlers bypass that path.

A client that enforces TSIG on responses (which RFC 2845 mandates) will reject
the NOERROR reply as unauthenticated, or — if it does not enforce — it will
silently accept a spoofed NOERROR from an on-path attacker.

```go
// Buggy:
m := new(dns.Msg)
m.SetReply(r)
w.WriteMsg(m)   // no TSIG added
```

**Fix:** Use `dns.MsgTsigGenerateWithConf` or the convenience wrapper to sign
the response before writing it. Check how `handleAXFR` signs its responses for
the correct pattern in this codebase:

```go
if tsig := r.IsTsig(); tsig != nil && s.tsigKeyRing != nil {
    secret, ok := s.tsigKeyRing.TsigSecretMap()[tsig.Hdr.Name]
    if ok {
        m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
        _ = dns.TsigGenerate(m, secret)
    }
}
w.WriteMsg(m)
```

---

### CR-05: IncrementSerial Overflow — Serial Can Silently Wrap to Zero

**File:** `internal/zone/zone.go:410-433`

**Issue:** `IncrementSerial` uses `uint32` arithmetic. When `currentSerial`
equals `math.MaxUint32` (4294967295), the fallback `z.SOA.Serial++` wraps
silently to 0. A serial of 0 is valid per the wire format but will cause
secondaries to perceive the zone as older than any non-zero serial they hold,
halting replication until the serial catches up (RFC 1982). This is a silent
data integrity bug — no error is returned.

Additionally, the `todaySerial+99` branch (line 424) itself overflows to 0 if
`todaySerial` is near `MaxUint32`, though in practice `YYYYMMDD` values are
safely below 2^32 until the year 5888.

```go
} else {
    // Fallback: just increment
    z.SOA.Serial++   // silent overflow if serial == MaxUint32
}
```

**Fix:** Add an overflow guard:

```go
} else {
    if z.SOA.Serial == math.MaxUint32 {
        return fmt.Errorf("zone %s: SOA serial at MaxUint32, cannot increment", z.Origin)
    }
    z.SOA.Serial++
}
```

---

## Warnings

### WR-01: Delete-Specific-RR for SOA Not Guarded (ClassNONE Path)

**File:** `internal/server/update.go:258-268`

**Issue:** The `ClassNONE` (delete specific RR) path guards against
`rrtype == dns.TypeSOA` and returns REFUSED — correct for deleting the SOA
record itself. However, the guard only applies when `rrtype` is `TypeSOA`.
A client can send a `ClassNONE` delete for a `TypeNS` RR at the apex,
removing the last NS record one-by-one. The single-RR NS floor check that
exists in the `ClassANY` path (WR-01 above, CR-03) has no equivalent in the
`ClassNONE` path.

```go
case dns.ClassNONE:
    if rrtype == dns.TypeSOA {
        sendRcode(dns.RcodeRefused)
        return
    }
    // ← no floor check for NS at apex
    if err := clone.DeleteRecord(rr); err != nil {
```

**Fix:** Before calling `clone.DeleteRecord`, check whether this would remove
the last NS at the zone apex:

```go
case dns.ClassNONE:
    if rrtype == dns.TypeSOA {
        sendRcode(dns.RcodeRefused)
        return
    }
    if rrtype == dns.TypeNS && strings.EqualFold(owner, strings.ToLower(clone.Origin)) {
        if len(clone.GetRecords(owner, dns.TypeNS)) <= 1 {
            sendRcode(dns.RcodeRefused)
            return
        }
    }
    if err := clone.DeleteRecord(rr); err != nil {
```

Note: this check has the same mid-mutation clone issue as CR-03 and should
ultimately count against the live zone `z`.

---

### WR-02: Delete-Name at Zone Apex Bypasses SOA Guard

**File:** `internal/server/update.go:228-235`

**Issue:** The `ClassANY / TypeANY` (delete-all-at-name) path correctly returns
REFUSED when `owner == clone.Origin` (the zone apex). However, the comment says
this is because "deleting all at apex would remove SOA/NS". The guard is present
but the justification and the REFUSED rcode imply the caller should use per-type
deletes instead. RFC 2136 §3.4.2.3 mandates REFUSED for this exact operation at
apex. The guard is implemented correctly here; this WR is flagging that the
REFUSED for this path sends no explanation to the caller and the returned rcode
for all the apex-protection paths is uniformly REFUSED, while RFC 2136 is silent
on whether FORMERR or REFUSED is preferred.

Actually the core finding here is narrower: `clone.DeleteName` removes the entry
from `clone.Records[owner]` but the `clone.SOA` field remains pointing to the
same `*dns.SOA` copied from the live zone. If `clone.Validate()` is called
*after* a successful `DeleteName` on a non-apex owner, the `clone.SOA != nil`
check passes even though SOA's backing data may be inconsistent if the SOA was
also in `clone.Records`. There is no bug in the current flow (delete-name at
apex is REFUSED before reaching `DeleteName`, and `clone.SOA` is always set from
the original clone), but the dual-storage of SOA in both `clone.SOA` and
`clone.Records[apex][TypeSOA]` creates a consistency hazard: if `DeleteRecord`
ever removes the SOA RR from `clone.Records` without clearing `clone.SOA`, the
zone will serialize incorrectly.

**Fix:** `DeleteRecord` for a SOA should update `z.SOA = nil` (or be rejected
earlier as it currently is at the guard in update.go:261). Confirm `DeleteRecord`
in zone.go does NOT clear `z.SOA` when the SOA record is removed:

```go
// zone.go DeleteRecord — does not clear z.SOA:
// (no code to set z.SOA = nil when TypeSOA is deleted)
```

The SOA field becomes stale if the SOA RR is ever removed via `DeleteRecord`
called outside the UPDATE guard chain (e.g. directly from code). Add in
`DeleteRecord`:

```go
if rrtype == dns.TypeSOA {
    z.SOA = nil
}
```

---

### WR-03: CNAME Coexistence Check Reads From Clone, Not Live Zone

**File:** `internal/server/update.go:204-218`

**Issue:** The CNAME coexistence check calls `clone.GetTypeMap(owner)` and
`clone.GetRecords(owner, dns.TypeCNAME)` to determine whether adding a CNAME
would conflict. This is correct for the final-state check (RFC 2136 §3.4.2
says to check the updated zone state), but since multiple update directives
in one message are applied sequentially to `clone`, an earlier directive in the
same message could have removed the conflicting records. The check is therefore
order-dependent: if a client sends (1) delete all A records at `foo`, (2) add
CNAME at `foo` in the same UPDATE message, the CNAME check at step (2) will see
the already-mutated `clone` correctly and the result is fine. This is not a bug
in isolation, but it is fragile — it relies on the sequential processing order
being the correct one, which RFC 2136 §3.4.2 actually requires. No change
needed, but document the ordering dependency explicitly.

**Fix:** Add a comment at the CNAME check site:

```go
// CNAME coexistence check against clone (mutated state), not live zone.
// RFC 2136 §3.4.2 requires update directives to be applied in order;
// earlier directives in this message will already be reflected in clone.
```

---

### WR-04: persistZone Is Called After Releasing the Zone Lock (Reply Already Sent)

**File:** `internal/server/update.go:301-303`

**Issue:** The NOERROR reply is sent at line 298-299 and the zone lock (`z.Unlock()`)
is released by `defer` at function exit, which happens *after* `persistZone` returns.
This means `persistZone` executes with the lock still held. That part is fine, but
`persistZone` performs blocking I/O (file write + rename) while holding `z.Lock()`.

Any concurrent UPDATE for the same zone that arrives during a large file write
will block on `z.Lock()` for the entire duration of the disk write. For zones
with many records, this is a latency spike for subsequent UPDATE clients.

Additionally, the reply is sent before `persistZone` runs (line 298 comes before
the function returns and defer fires). If the process crashes between the reply
and `persistZone`, the zone file on disk will be one serial behind the response
already sent to the client — a consistency gap the comment at line 307 acknowledges
but callers may not expect.

**Fix:** Run `persistZone` in a goroutine after releasing the lock, accepting the
acknowledged in-memory-only guarantee:

```go
// Release lock before blocking I/O.
clone := clone  // capture for goroutine
go s.persistZone(zoneName, clone)
```

Alternatively, make the disk write synchronous but move it *before* `w.WriteMsg`
so a failed write can still be signalled to the client.

---

### WR-05: `New()` in zone.go Does Not Protect Against Empty Name

**File:** `internal/zone/zone.go:94-106`

**Issue:** `New(name string)` indexes `name[len(name)-1]` without checking that
`name` is non-empty. Calling `zone.New("")` will panic with an index-out-of-range
at runtime:

```go
func New(name string) *Zone {
    if name[len(name)-1] != '.' {  // ← panics if name == ""
```

This is reachable wherever the zone name comes from external input (e.g., gRPC
`AddZone` with a malformed zone name).

**Fix:**

```go
func New(name string) *Zone {
    if name == "" {
        panic("zone.New: empty name")  // or return nil, error
    }
    if name[len(name)-1] != '.' {
```

---

### WR-06: `GetRecords` and `HasName` Panic on Empty Owner

**File:** `internal/zone/zone.go:248-249`, `internal/zone/zone.go:293-294`

**Issue:** Both `GetRecords` and `HasName` index `owner[len(owner)-1]` without
a nil/empty guard:

```go
func (z *Zone) GetRecords(owner string, rrtype uint16) []dns.RR {
    if owner[len(owner)-1] != '.' {   // ← panics if owner == ""
```

If a DNS message contains a zero-length owner name (which `miekg/dns` permits
in certain edge cases, e.g. for the root zone `"."`), this will panic. The root
`.` is one byte long, so the root zone is safe, but the empty string `""` is not.

**Fix:** Add a guard before the index:

```go
if len(owner) == 0 {
    return nil
}
```

---

## Info

### IN-01: Comment Mentions "All prerequisites evaluated" But Code Does Early Return

**File:** `internal/server/update.go:51`

**Issue:** The doc comment for `evaluatePrereqs` states "Per RFC 2136 §3.2, all
prerequisites are evaluated; the first failure wins." RFC 2136 §3.2 actually
says prerequisites are evaluated in order and processing stops at the first
failure — which is what the code correctly does with early `return`. The phrase
"all prerequisites are evaluated" contradicts the actual behavior. While the
behavior is correct, the comment is misleading.

**Fix:** Update the comment:

```go
// Per RFC 2136 §3.2, prerequisites are evaluated in order; the first
// failure stops evaluation and returns the appropriate error rcode.
```

---

### IN-02: Magic Number 99 in IncrementSerial

**File:** `internal/zone/zone.go:424`

**Issue:** The `todaySerial+99` bound is a magic number with no named constant
or explanatory comment. YYYYMMDDNN format allows NN in [00, 99] for 100 updates
per day.

**Fix:**

```go
const maxDailyUpdates = 99
if currentSerial >= todaySerial && currentSerial < todaySerial+maxDailyUpdates {
```

---

### IN-03: testServerWithUpdate Creates a Real Server with Goroutines in Every Test

**File:** `internal/server/update_test.go:16-31`

**Issue:** Every test calls `testServerWithUpdate`, which calls `server.New(cfg)`.
`server.New` initializes the TSIG key ring, builds ACL maps, and creates
`dns.Server` structs. The tests then call `s.Stop()` via defer, which starts
and stops goroutines. None of the tests call `s.Start()`, so the goroutines
never actually start — but `s.Stop()` still calls `Shutdown()` on unstarted
`dns.Server` instances. In the current `miekg/dns` implementation this is a
no-op, but it is fragile. The test helper creates more infrastructure than
`handleUpdate` needs.

**Fix:** For unit testing `handleUpdate` (a method on `*Server`), consider
constructing a `Server` struct directly with only the fields `handleUpdate`
reads, rather than calling `New`. This removes the dependency on full server
startup in unit tests.

---

_Reviewed: 2026-05-23T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
