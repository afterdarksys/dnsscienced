---
phase: 13-dynamic-dns-updates
plan: "02"
subsystem: dns
tags: [rfc2136, dynamic-dns, update-handler, tsig, acl, atomic-swap, go]

# Dependency graph
requires:
  - phase: 13-01
    provides: Zone.DeleteRecord/DeleteRRSet/DeleteName, updateMu, ZoneConfig.AllowUpdate
provides:
  - "handleUpdate: full RFC 2136 UPDATE handler with TSIG auth, IP ACL, prereq eval, atomic clone-and-swap"
  - "classifyPrereq/evaluatePrereqs: all 5 RFC 2136 prerequisite types"
  - "ZoneUpdateCIDRs config + zoneUpdateACLs server field + ACL init in New()"
  - "UPDATE opcode dispatch in handleDNS before pool.GetMessage()"
  - "Zone.Lock/Unlock: exported concurrency primitives wrapping updateMu"
  - "Zone.GetTypeMap: CNAME coexistence check helper"
  - "22 passing tests in update_test.go covering all DYNUP requirements"
affects: [13-03-update-persistence]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Two-step TSIG guard: r.IsTsig()==nil FIRST, w.TsigStatus()!=nil SECOND (T-13-04)"
    - "Empty CIDR = nil ACL = deny all (T-13-09): interception in New() before NewSourceACL"
    - "Clone-and-swap: all mutations on z.Clone(); s.cfg.Zones[name] = clone only after Validate()"
    - "D-10 SOA-skip applies only to zone-class (add) path, not ClassANY/ClassNONE delete paths"
    - "DeleteRecord RFC 2136 normalization: class+TTL set to stored values before String() comparison"

key-files:
  created:
    - internal/server/update.go
    - internal/server/update_test.go
  modified:
    - internal/server/server.go
    - internal/zone/zone.go

key-decisions:
  - "SOA skip (D-10) moved inside the zone-class (add) case, not before the class switch — delete-SOA via ClassANY must still be rejected, not silently skipped"
  - "DeleteRecord class/TTL normalization: RFC 2136 §3.4.2.3 delete-specific-RR matches owner+type+rdata only; TTL and class from the delete request are ignored by normalizing to stored values before String() comparison"
  - "Zone.Lock/Unlock exported wrappers over unexported updateMu — keeps updateMu unexported (only handler serializes on it) while allowing the server package to acquire the lock"
  - "persistZone stub deferred to Plan 03 — update.go calls it so the call site compiles, but Plan 03 wires s.persistPaths from ZoneConfig.PersistUpdates"
  - "GetTypeMap exported for CNAME coexistence check in update.go (D-04); returns nil for absent owner, safe for range iteration"

patterns-established:
  - "UPDATE handler guard chain: TSIG-presence → TSIG-validity → zone-section → zone-lookup → ACL → lock → prereqs → clone → apply → validate → increment-serial → swap → NOERROR"
  - "sendRcode local closure: eliminates repeated new(dns.Msg)/SetReply/WriteMsg boilerplate in handler"

requirements-completed:
  - DYNUP-01
  - DYNUP-02
  - DYNUP-03
  - DYNUP-04

# Metrics
duration: 7min
completed: 2026-05-23
---

# Phase 13 Plan 02: UPDATE Handler Summary

**RFC 2136 UPDATE handler with full guard chain, prerequisite evaluation, atomic clone-and-swap, auto-serial-increment, and 22 comprehensive tests covering all DYNUP requirements**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-05-23T15:40:58Z
- **Completed:** 2026-05-23T15:48:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Implemented `handleUpdate()` with full 14-step RFC 2136 guard chain (TSIG presence, TSIG validity, zone lookup, ACL, lock, prereqs, clone, apply, validate, serial increment, atomic swap)
- Implemented `classifyPrereq()` and `evaluatePrereqs()` covering all 5 RFC 2136 prerequisite types (name-in-use, name-not-in-use, rrset-exists, rrset-not-exists, rrset-exists-value)
- Added all server.go wiring: `ZoneUpdateCIDRs` Config field, `zoneUpdateACLs` Server field, ACL init in `New()`, `OpcodeUpdate` dispatch in `handleDNS`
- Added `Zone.Lock()`, `Zone.Unlock()`, `Zone.GetTypeMap()` to zone.go for UPDATE handler needs
- 22 unit tests in update_test.go covering guard chain, all prereq types, all delete variants, atomicity, serial increment, immediate visibility
- Race detector clean: `go test -race ./internal/server/ -run TestHandleUpdate` passes

## Task Commits

1. **Task 1: server.go config + ACL + dispatch** — `3dda603` (feat)
2. **Task 2: update.go + update_test.go + zone.go helpers** — `a11102f` (feat)

## Files Created/Modified

- `/Users/ryan/development/dnsscienced/internal/server/update.go` — handleUpdate, classifyPrereq, evaluatePrereqs, persistZone stub
- `/Users/ryan/development/dnsscienced/internal/server/update_test.go` — 22 TestHandleUpdate_* tests
- `/Users/ryan/development/dnsscienced/internal/server/server.go` — ZoneUpdateCIDRs, zoneUpdateACLs, persistPaths, ACL init block, OpcodeUpdate dispatch
- `/Users/ryan/development/dnsscienced/internal/zone/zone.go` — Lock(), Unlock(), GetTypeMap(), DeleteRecord RFC 2136 class/TTL normalization fix

## Decisions Made

- SOA-skip (D-10) placed inside the zone-class (add) switch case, not before the class switch. The early `if rrtype == dns.TypeSOA { continue }` was incorrectly bypassing the delete-SOA rejection check (D-04). Fix: SOA is only silently skipped when it appears as an add (zone class) operation; delete attempts (ClassANY/ClassNONE) still reach the REFUSED guards.
- `DeleteRecord` TTL/class normalization: RFC 2136 §3.4.2.3 specifies that delete-specific-RR match is on owner+type+rdata only. The stored records have ClassINET and original TTL; the delete RR has ClassNONE and TTL=0. Fix: normalize the incoming RR's class and TTL to match the stored record before String() comparison.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SOA-skip (D-10) bypassed delete-SOA REFUSED guard (D-04)**
- **Found during:** Task 2 — `TestHandleUpdate_DeleteSOA_Refused` returned NOERROR instead of REFUSED
- **Issue:** The `if rrtype == dns.TypeSOA { continue }` check ran before the class switch, so ClassANY/TypeSOA (delete-rrset) and ClassNONE/TypeSOA (delete-specific) operations were silently skipped instead of being rejected with REFUSED
- **Fix:** Moved the SOA-skip into the `case z.Class:` (add) branch only; delete paths now correctly reach D-04 guards
- **Files modified:** `internal/server/update.go`
- **Commit:** `a11102f`

**2. [Rule 1 - Bug] DeleteRecord string comparison includes TTL and class (RFC 2136 ClassNONE mismatch)**
- **Found during:** Task 2 — `TestHandleUpdate_DeleteRecord` left the record in the zone after delete
- **Issue:** RFC 2136 delete-specific-RR uses ClassNONE+TTL=0 but stored records have ClassINET+original TTL. The `dns.RR.String()` output includes class and TTL, so the stored `"300 IN A 198.51.100.5"` never matched the delete `"0 NONE A 198.51.100.5"`
- **Fix:** Before calling `.String()`, set the normalized copy's class and TTL to match the first stored record, so only rdata differs (RFC 2136 §3.4.2.3 semantics)
- **Files modified:** `internal/zone/zone.go` (DeleteRecord)
- **Commit:** `a11102f`

**3. [Rule 2 - Missing functionality] Zone.Lock/Unlock/GetTypeMap needed by update.go**
- **Found during:** Task 2 — `updateMu` is unexported; update.go cannot call `z.updateMu.Lock()` directly from another package
- **Fix:** Added `Lock()`, `Unlock()` exported wrappers over `updateMu`; added `GetTypeMap()` for CNAME coexistence check (D-04)
- **Files modified:** `internal/zone/zone.go`
- **Commit:** `a11102f`

---

**Total deviations:** 3 auto-fixed (2 Rule 1 bugs, 1 Rule 2 missing functionality)
**Impact on plan:** All fixes required for correctness. No scope creep.

## Known Stubs

| Stub | File | Line | Reason |
|------|------|------|--------|
| `persistZone` no-op stub | `internal/server/update.go` | ~303 | Plan 03 wires `s.persistPaths` from `ZoneConfig.PersistUpdates`; call site present so Plan 03 only needs to implement the method body |

The stub is intentional: in-memory UPDATE is complete; write-back is Plan 03's scope.

## Issues Encountered

None beyond the two bugs above (both caught by tests and fixed inline).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 03 (main.go wiring + persistence) can wire `ZoneUpdateCIDRs` from `ZoneConfig.AllowUpdate` (pattern in 13-PATTERNS.md)
- `persistZone` stub body in update.go is Plan 03's only implementation target in this file
- All DYNUP-01 through DYNUP-04 requirements are verified by tests

## Self-Check: PASSED

- `internal/server/update.go` — EXISTS
- `internal/server/update_test.go` — EXISTS
- `internal/server/server.go` (modified) — EXISTS with `zoneUpdateACLs`, `ZoneUpdateCIDRs`, `r.Opcode == dns.OpcodeUpdate`
- `internal/zone/zone.go` (modified) — EXISTS with `Lock()`, `Unlock()`, `GetTypeMap()`
- Commits `3dda603` and `a11102f` verified in git log
- `go test ./internal/server/ -run TestHandleUpdate -count=1` — PASS (22 tests)
- `go test -race ./internal/server/ -run TestHandleUpdate -count=1` — PASS (no races)
- `go build ./...` — PASS

---
*Phase: 13-dynamic-dns-updates*
*Completed: 2026-05-23*
