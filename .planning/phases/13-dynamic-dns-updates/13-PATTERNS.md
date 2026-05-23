# Phase 13: Dynamic DNS Updates - Pattern Map

**Mapped:** 2026-05-23
**Files analyzed:** 5 new/modified files
**Analogs found:** 5 / 5

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/server/update.go` | handler | request-response | `internal/server/axfr.go` | exact |
| `internal/server/server.go` (modify) | dispatcher + config | request-response | `internal/server/server.go` lines 317–339 (AXFR ACL wiring) | self-reference (exact) |
| `internal/zone/zone.go` (modify) | model | CRUD | `internal/zone/zone.go` lines 104–135 (`AddRecord`) | self-reference (exact) |
| `internal/config/config.go` (modify) | config | — | `internal/config/config.go` lines 103–104 (`AllowTransfer`, `AllowAXFRFallback *bool`) | exact |
| `cmd/dnsscienced/main.go` (modify) | wiring | — | `cmd/dnsscienced/main.go` lines 144–157 (ZoneTransferCIDRs wiring) | exact |

---

## Pattern Assignments

### `internal/server/update.go` (handler, request-response)

**Analog:** `internal/server/axfr.go`

**Package and imports pattern** (axfr.go lines 1–8):
```go
package server

import (
    "net"

    "github.com/miekg/dns"
)
```
Note: `update.go` will also need `"sync"` (for defer unlock) and `"fmt"` (for error wrapping) and `"os"` + `"gopkg.in/yaml.v3"` only if `persist_updates` support is in this file.

**Guard chain order** (axfr.go lines 22–82 — full guard chain comment block):
```go
// handleUpdate handles RFC 2136 Dynamic DNS Update requests.
//
// Guard chain (each failure returns immediately with the specified rcode):
//  1. clientIP nil guard → REFUSED
//  2. TSIG presence (D-16): absent TSIG → NOTAUTH (rcode 9)
//  3. TSIG validity (D-16): bad/replayed TSIG → NOTAUTH
//  4. Empty Zone section guard → FORMERR
//  5. Zone lookup: unknown zone → REFUSED
//  6. ACL check (D-15, D-17): nil ACL (no allow_update) or IP not allowed → REFUSED
//  7. Lock zone.updateMu
//  8. Evaluate prerequisites (r.Answer) against live zone
//  9. Clone live zone
// 10. Apply Update section (r.Ns) to clone
// 11. clone.Validate() → SERVFAIL on failure
// 12. clone.IncrementSerial()
// 13. Atomic swap: s.cfg.Zones[zoneName] = clone
// 14. Unlock zone.updateMu
// 15. Persist to disk if persist_updates: true
// 16. Reply NOERROR
func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
```

**TSIG presence check** (axfr.go lines 32–41):
```go
// TSIG presence check (D-16): no TSIG record at all → NOTAUTH.
// This MUST come before the validity check — an absent TSIG yields
// TsigStatus() == nil, which would incorrectly allow unsigned requests.
if r.IsTsig() == nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

**TSIG validity check** (axfr.go lines 43–50):
```go
// TSIG validity check (D-16): bad key, bad sig, replay attack.
if w.TsigStatus() != nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

**Zone lookup pattern** (axfr.go lines 61–70):
```go
// Zone lookup. In UPDATE messages, Question[0].Name = zone FQDN (TypeSOA class).
qname := r.Question[0].Name
z, ok := s.cfg.Zones[qname]
if !ok {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

**ACL check with deny-all-on-empty** (axfr.go lines 72–82):
```go
// ACL check (D-15, D-17):
//    nil ACL = no allow_update configured = deny all (secure-by-default).
//    non-nil ACL = source IP must be in the allowlist.
acl := s.zoneUpdateACLs[qname]
if acl == nil || !acl.Check(clientIP) {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

**NOERROR success reply pattern** (standard miekg pattern, used everywhere):
```go
m := new(dns.Msg)
m.SetReply(r)
// Rcode defaults to dns.RcodeSuccess (0)
w.WriteMsg(m) //nolint:errcheck
```

**Error reply helper** (extracted from axfr.go inline pattern — replicate as inline or local helper):
```go
sendRcode := func(rcode int) {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = rcode
    w.WriteMsg(m) //nolint:errcheck
}
```

---

### `internal/server/server.go` — dispatch block addition (lines ~549–563)

**Analog:** Existing AXFR dispatch block at server.go lines 533–550.

**NOTIFY dispatch pattern to mirror** (server.go lines 510–531):
```go
// RFC 9859: dispatch NOTIFY opcode before query processing.
if r.Opcode == dns.OpcodeNotify {
    if clientIP == nil {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    if s.dsyncHandler != nil {
        s.dsyncHandler.HandleInbound(w, r, clientIP)
    } else {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeNotImplemented
        w.WriteMsg(m) //nolint:errcheck
    }
    return
}
```

**New UPDATE dispatch block** (insert after AXFR block at ~line 550, before `// Check blackhole/ACL first`):
```go
// RFC 2136: dispatch UPDATE opcode before pool.GetMessage() — UPDATE requires
// TSIG authentication and must NOT use the pooled single-response path.
if r.Opcode == dns.OpcodeUpdate {
    if clientIP == nil {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    s.handleUpdate(w, r, clientIP)
    return
}
```

**zoneUpdateACLs field addition to Server struct** (mirror of server.go line 162):
```go
// Before:
zoneTransferACLs map[string]*dsync.SourceACL // Per-zone transfer ACLs. nil entry = deny all (D-01).

// After (add on next line):
zoneUpdateACLs   map[string]*dsync.SourceACL // Per-zone update ACLs.  nil entry = deny all (D-15).
```

**ZoneUpdateCIDRs field addition to Config struct** (mirror of server.go lines 67–70):
```go
// ZoneUpdateCIDRs maps zone FQDN origin to CIDR strings allowed to send RFC 2136 UPDATE.
// Populated by main.go from config.ZoneConfig.AllowUpdate.
// Empty/absent = deny all (D-15).
ZoneUpdateCIDRs map[string][]string `yaml:"-"`
```

**ACL wiring in New()** (mirror of server.go lines 317–339):
```go
// Build per-zone update ACLs from ZoneUpdateCIDRs.
// D-15: zones with no entry or empty CIDR list get nil ACL = deny all.
// CRITICAL: Do NOT pass empty slice to NewSourceACL — returns allowAll=true.
s.zoneUpdateACLs = make(map[string]*dsync.SourceACL)
for zoneName, cidrs := range cfg.ZoneUpdateCIDRs {
    if len(cidrs) == 0 {
        s.zoneUpdateACLs[zoneName] = nil // deny-all: no allow_update configured
        continue
    }
    acl, err := dsync.NewSourceACL(cidrs)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("zone %s allow_update: %w", zoneName, err)
    }
    s.zoneUpdateACLs[zoneName] = acl
}
```

---

### `internal/zone/zone.go` — new mutation methods + updateMu (modify)

**Analog:** `zone.AddRecord()` at zone.go lines 104–135.

**AddRecord signature and style to mirror** (zone.go lines 104–135):
```go
// AddRecord adds a resource record to the zone
func (z *Zone) AddRecord(rr dns.RR) error {
    if rr == nil {
        return fmt.Errorf("cannot add nil record")
    }
    owner := strings.ToLower(rr.Header().Name)
    rr.Header().Name = owner
    if !dns.IsSubDomain(z.Origin, owner) {
        return fmt.Errorf("record %s not in zone %s", owner, z.Origin)
    }
    rrtype := rr.Header().Rrtype
    if z.Records[owner] == nil {
        z.Records[owner] = make(map[uint16][]dns.RR)
    }
    z.Records[owner][rrtype] = append(z.Records[owner][rrtype], rr)
    if rrtype == dns.TypeSOA {
        z.SOA = rr.(*dns.SOA)
    }
    return nil
}
```

**New method signatures to add** (mirror AddRecord style, per D-08 from CONTEXT.md):
```go
// DeleteRecord removes a specific RR by exact match (class, type, rdata).
// Returns nil if the record was not found (no-op, per RFC 2136 §3.4.2.5).
func (z *Zone) DeleteRecord(rr dns.RR) error

// DeleteRRSet removes all records of the given type at the given owner name.
// Returns nil if no such rrset exists (no-op).
func (z *Zone) DeleteRRSet(owner string, rrtype uint16) error

// DeleteName removes all rrsets at the given owner name.
// Returns nil if the name does not exist (no-op).
func (z *Zone) DeleteName(owner string) error
```

**updateMu field addition to Zone struct** (mirror existing Zone struct at zone.go lines 13–31):
```go
// Zone struct addition — place before or after DNSSEC field:
// updateMu serializes concurrent RFC 2136 UPDATE requests for this zone (D-06).
// The mutex is held for the full duration: prereq evaluation → clone → apply → swap.
updateMu sync.Mutex
```
Note: Add `"sync"` to zone.go imports.

**HasName and GetRecords patterns for prerequisite evaluation** (zone.go lines 138–202):
```go
// Use z.HasName(owner) for name-in-use / name-not-in-use prereqs.
// Use z.GetRecords(owner, rrtype) for rrset-exists / rrset-not-exists / rrset-exists-value prereqs.
// These are already exported and safe to call on the live zone while updateMu is held.
```

**Clone pattern** (zone.go lines 326–355) — called before any mutation on the live zone:
```go
clone := z.Clone()
// ... apply all mutations to clone ...
if err := clone.Validate(); err != nil {
    // return SERVFAIL — original zone untouched
}
if err := clone.IncrementSerial(); err != nil {
    // return SERVFAIL
}
s.cfg.Zones[zoneName] = clone // atomic swap
```

---

### `internal/config/config.go` — ZoneConfig field additions (modify)

**Analog:** Existing `AllowTransfer []string` at config.go line 103 and `AllowAXFRFallback *bool` at config.go line 113.

**AllowTransfer pattern to mirror** (config.go lines 102–104):
```go
// AXFR/IXFR configuration
AllowTransfer []string `yaml:"allow_transfer,omitempty"` // CIDRs allowed to AXFR
AlsoNotify    []string `yaml:"also_notify,omitempty"`    // Additional NOTIFY targets
```

**New fields to add to ZoneConfig** (place adjacent to AllowTransfer, before or after the AXFR block):
```go
// Dynamic DNS Update configuration (RFC 2136)
AllowUpdate    []string `yaml:"allow_update,omitempty"`    // CIDRs allowed to send UPDATE; empty = REFUSED
PersistUpdates *bool    `yaml:"persist_updates,omitempty"` // nil/false = in-memory only; true = write-back to zone file
```

---

### `cmd/dnsscienced/main.go` — ZoneUpdateCIDRs wiring (modify)

**Analog:** ZoneTransferCIDRs wiring at main.go lines 144–157.

**ZoneTransferCIDRs wiring to mirror** (main.go lines 144–157):
```go
// Wire per-zone allow_transfer CIDRs from zone config into server config.
// config.Config.Zones holds AllowTransfer; server.Config.ZoneTransferCIDRs
// carries them to the AXFR handler. Wired here to avoid import cycle.
if len(loadedCfg.Zones) > 0 {
    cfg.ZoneTransferCIDRs = make(map[string][]string, len(loadedCfg.Zones))
    for _, zc := range loadedCfg.Zones {
        // Ensure zone name is FQDN (trailing dot)
        zoneName := zc.Name
        if !strings.HasSuffix(zoneName, ".") {
            zoneName += "."
        }
        cfg.ZoneTransferCIDRs[zoneName] = zc.AllowTransfer
    }
}
```

**New ZoneUpdateCIDRs wiring** (add immediately after the ZoneTransferCIDRs block):
```go
// Wire per-zone allow_update CIDRs from zone config into server config.
// Same pattern as ZoneTransferCIDRs; wired here to avoid import cycle.
// Empty AllowUpdate slice is passed as-is; server.New() intercepts empty → nil (deny all).
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

---

## Shared Patterns

### TSIG Two-Step Guard
**Source:** `internal/server/axfr.go` lines 32–50
**Apply to:** `internal/server/update.go` — always in order: presence check (`r.IsTsig() == nil`) THEN validity check (`w.TsigStatus() != nil`). Reversing the order silently accepts unsigned requests.

### Nil ACL = Deny All
**Source:** `internal/server/server.go` lines 317–339; `internal/server/axfr.go` lines 72–82
**Apply to:** `internal/server/update.go` ACL check, `internal/server/server.go` ACL build loop for `zoneUpdateACLs`.
```go
// In New(): intercept empty CIDR slice BEFORE calling NewSourceACL.
if len(cidrs) == 0 {
    s.zoneUpdateACLs[zoneName] = nil // deny-all
    continue
}
// In handler:
acl := s.zoneUpdateACLs[qname]
if acl == nil || !acl.Check(clientIP) { /* REFUSED */ }
```

### RFC Error Response
**Source:** Used throughout `axfr.go` and `server.go`
**Apply to:** All error paths in `update.go`
```go
m := new(dns.Msg)
m.SetReply(r)
m.Rcode = dns.Rcode<X>
w.WriteMsg(m) //nolint:errcheck
return
```

### Test Writer Mock
**Source:** `internal/server/axfr_test.go` lines 13–48
**Apply to:** `internal/server/update_test.go` — copy `axfrTestResponseWriter` verbatim (or rename to `updateTestResponseWriter`). The struct implements `dns.ResponseWriter` with `tsigStatus error` field for simulating bad TSIG and `msgs []dns.Msg` for capturing responses.

### testServerWith* Factory Pattern
**Source:** `internal/server/axfr_test.go` lines 91–109
**Apply to:** `internal/server/update_test.go` — create `testServerWithUpdate(allowUpdate []string) (*Server, error)` using the same `Config{Zones: ..., ZoneUpdateCIDRs: ...}` shape.

### testZone() Minimal Valid Zone
**Source:** `internal/server/axfr_test.go` lines 51–82
**Apply to:** `internal/server/update_test.go` — reuse `testZone()` directly (same package). No duplication needed.

---

## No Analog Found

All files have close analogs. No entries in this section.

---

## Metadata

**Analog search scope:** `internal/server/`, `internal/zone/`, `internal/config/`, `cmd/dnsscienced/`
**Files scanned:** 6 source files read directly
**Pattern extraction date:** 2026-05-23
