---
phase: 13-dynamic-dns-updates
fixed_at: 2026-05-23T12:24:00Z
review_path: .planning/phases/13-dynamic-dns-updates/13-REVIEW.md
iteration: 1
findings_in_scope: 11
fixed: 11
skipped: 0
status: all_fixed
---

# Phase 13: Code Review Fix Report

**Fixed at:** 2026-05-23T12:24:00Z
**Source review:** .planning/phases/13-dynamic-dns-updates/13-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 11 (5 Critical + 6 Warning)
- Fixed: 11
- Skipped: 0

## Fixed Issues

### CR-01: Data race on zone map

**Files modified:** `internal/server/server.go`, `internal/server/update.go`
**Commit:** 4d02ec9
**Applied fix:** Added `zonesMu sync.RWMutex` field to the `Server` struct.
Wrapped all reads of `cfg.Zones` with `RLock`/`RUnlock` in `handleAuthoritative`,
`handleUpdate` (zone lookup), `GetZone`, and `GetZoneNames`. Wrapped all writes
(`AddZone`, `RemoveZone`, `LoadZone`, atomic swap in `handleUpdate`) with
`Lock`/`Unlock`.

### CR-02: Zone lookup not lowercased in handleUpdate

**Files modified:** `internal/server/update.go`
**Commit:** 4d02ec9
**Applied fix:** Changed `zoneName := r.Question[0].Name` to
`zoneName := strings.ToLower(r.Question[0].Name)` before the map lookup,
fixing the case-sensitivity hole (RFC 4343). Applied in the same commit as CR-01
since both changes affect the same code block.

### CR-03: NS floor guard counts mid-mutation clone instead of live zone

**Files modified:** `internal/server/update.go`
**Commit:** 4d02ec9
**Applied fix:** Changed the ClassANY/TypeNS delete-rrset guard to read from
`z.GetRecords(owner, dns.TypeNS)` (live zone) instead of
`clone.GetRecords(owner, dns.TypeNS)` (mid-mutation clone). This prevents an
earlier ADD NS in the same message from inflating the count and bypassing the guard.

### CR-04: NOERROR reply missing TSIG signing

**Files modified:** `internal/server/update.go`
**Commit:** 4d02ec9
**Applied fix:** After building the NOERROR reply, the code now checks
`r.IsTsig()` and, if the request was TSIG-authenticated, calls
`s.tsigKeyRing.Secret(keyName)`, `s.tsigKeyRing.Algorithm(keyName)`,
`m.SetTsig(...)`, and `dns.TsigGenerate(...)` to sign the response before
writing it, per RFC 2845 §3.2.

### CR-05: IncrementSerial wraps silently to zero

**Files modified:** `internal/zone/zone.go`
**Commit:** 79f65c9
**Applied fix:** Added `import "math"` and an overflow guard in the fallback
branch of `IncrementSerial`: if `z.SOA.Serial == math.MaxUint32`, return an
error instead of incrementing, preventing silent wrap-around to 0.

### WR-01: ClassNONE delete-specific-RR has no NS floor guard

**Files modified:** `internal/server/update.go`
**Commit:** 0028728
**Applied fix:** Added an NS floor guard in the `ClassNONE` case: before calling
`clone.DeleteRecord`, check if the RR is a TypeNS at the zone apex and whether
removing it would leave zero NS records. Guard checks the live zone `z` (not clone)
consistent with the CR-03 fix.

### WR-02: Dual SOA storage hazard in DeleteRecord

**Files modified:** `internal/zone/zone.go`
**Commit:** 79f65c9
**Applied fix:** Added `if rrtype == dns.TypeSOA { z.SOA = nil }` after the
splice-out logic in `DeleteRecord`, ensuring the fast-path `z.SOA` field is
cleared whenever a SOA record is removed via this method.

### WR-03: CNAME coexistence check ordering dependency undocumented

**Files modified:** `internal/server/update.go`
**Commit:** 0028728
**Applied fix:** Added a comment at the CNAME coexistence check explaining that
the check runs against `clone` (mid-mutation state), that this is correct per
RFC 2136 §3.4.2 sequential ordering, and that earlier directives in the same
message are already reflected in clone.

### WR-04: persistZone blocks disk I/O while holding zone lock

**Files modified:** `internal/server/update.go`
**Commit:** 0028728
**Applied fix:** Changed `s.persistZone(zoneName, clone)` to
`go s.persistZone(zoneNameCopy, cloneCopy)` with explicit local variable captures.
Disk I/O now runs in a goroutine after the zone lock is released (via defer),
eliminating the lock-held blocking I/O latency spike for concurrent UPDATE clients.

### WR-05: zone.New("") panics

**Files modified:** `internal/zone/zone.go`
**Commit:** 79f65c9
**Applied fix:** Added an empty-name guard at the top of `New()`:
`if name == "" { panic("zone.New: empty zone name") }`. This replaces the
opaque index-out-of-range panic with a descriptive message.

### WR-06: GetRecords and HasName panic on empty owner

**Files modified:** `internal/zone/zone.go`
**Commit:** 79f65c9
**Applied fix:** Added `if len(owner) == 0 { return nil }` guard at the top of
`GetRecords` and `if len(owner) == 0 { return false }` at the top of `HasName`,
preventing index-out-of-range panics on zero-length owner strings.

---

_Fixed: 2026-05-23T12:24:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
