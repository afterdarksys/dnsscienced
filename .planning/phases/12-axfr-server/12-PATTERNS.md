# Phase 12: AXFR Server - Pattern Map

**Mapped:** 2026-05-23
**Files analyzed:** 4 (2 new, 2 modified)
**Analogs found:** 4 / 4

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/server/axfr.go` | handler (method on Server) | streaming (TCP, multi-message) | `internal/server/server.go` NOTIFY dispatch block (lines 480-501) + dsync Handler | role-match |
| `internal/server/axfr_test.go` | test | request-response + streaming | `internal/server/notify_test.go` | exact |
| `internal/server/server.go` (modified) | config + init | CRUD | `internal/server/server.go` DSYNC init block (lines 253-293) | exact (same file) |
| `cmd/dnsscienced/main.go` (modified) | wiring / startup | config | `cmd/dnsscienced/main.go` lines 120-132 (`cfg = loadedCfg.Server`) | exact (same file) |

---

## Pattern Assignments

### `internal/server/axfr.go` (handler, streaming)

**Primary analog:** `internal/server/server.go` — NOTIFY early-dispatch block + DSYNC init
**Secondary analog:** `internal/dsync/source_acl.go` — CIDR ACL (directly imported)

#### Imports pattern
Copy from `internal/server/server.go` lines 1-26, adding `sync` and removing unused items:

```go
package server

import (
    "fmt"
    "net"
    "sync"

    "github.com/afterdarksys/dnsscienced/internal/dsync"
    "github.com/afterdarksys/dnsscienced/internal/zone"
    "github.com/miekg/dns"
)
```

Key import notes:
- Module path prefix: `github.com/afterdarksys/dnsscienced/` (verified from `server.go` lines 12-26)
- `dsync` already imported in `server.go` for DSYNC handler — same import path applies
- No new external dependencies; `sync` is stdlib

#### Core handler pattern — UDP truncation guard (D-08)
Copy transport detection from `internal/server/server.go` lines 466-478 (RemoteAddr type assertion):

```go
// handleAXFR handles AXFR (zone transfer) requests (RFC 5936).
func (s *Server) handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
    // RFC 5936 §4.2: AXFR over UDP — return TC=1 to signal retry over TCP.
    // Do NOT return REFUSED; TC=1 is the RFC-mandated redirect signal.
    if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Truncated = true
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    // TCP path continues below...
}
```

Pattern source: `internal/server/server.go` lines 466-470 show the exact `*net.UDPAddr` type assertion idiom used for transport detection.

#### TSIG presence + validity check pattern (D-04, D-05, D-06)
**CRITICAL ORDER**: presence check (`r.IsTsig() == nil`) BEFORE validity check (`w.TsigStatus()`).
An absent TSIG yields `TsigStatus() == nil`, so checking validity first silently accepts unsigned requests.

```go
// TSIG presence — miekg/dns auto-verifies *present* TSIG but does NOT reject absent TSIG.
// Handler must enforce presence per D-04.
if r.IsTsig() == nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth // 9 per RFC 2845 §4
    w.WriteMsg(m) //nolint:errcheck
    return
}
// TSIG was present; miekg/dns has already verified the signature. Check result.
if w.TsigStatus() != nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

Pattern source: `internal/server/server.go` lines 486-499 show the error-response pattern (`new(dns.Msg)` + `SetReply` + `Rcode` + `WriteMsg` + `return`) used identically for NOTIFY guards. Apply same structure here.

#### Zone lookup + ACL check pattern (D-01, D-03)
Zone lookup via `s.cfg.Zones` map (same as authoritative query path). ACL via `s.zoneTransferACLs` (new field — see server.go modifications below).

```go
if len(r.Question) == 0 {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
qname := r.Question[0].Name

z, ok := s.cfg.Zones[qname]
if !ok {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}

// D-01: nil ACL (no allow_transfer configured) = REFUSED. D-03: unlisted source = REFUSED.
// This inverts dsync.SourceACL D-05 behavior (empty = allow-all is WRONG here).
acl := s.zoneTransferACLs[qname]
if acl == nil || !acl.Check(clientIP) {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

Pattern source: Error response structure copied from `internal/server/server.go` lines 486-499. `dsync.SourceACL.Check()` from `internal/dsync/source_acl.go` lines 55-65.

#### Multi-message streaming pattern — dns.Transfer.Out (D-09)
`zone.Zone.GetAllRecords()` (lines 204-215 of `zone.go`) iterates `z.Records` map — does NOT include `z.SOA` (SOA is a separate struct field, not stored in the Records map). Therefore: no SOA filtering needed on the GetAllRecords output; send `z.SOA` explicitly as opening and closing frames.

```go
ch := make(chan *dns.Envelope)
tr := new(dns.Transfer)
var wg sync.WaitGroup
wg.Add(1)
go func() {
    if err := tr.Out(w, r, ch); err != nil {
        // log transfer error — connection likely dropped by client
        _ = err
    }
    wg.Done()
}()

// Opening SOA (RFC 5936 §2.2)
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}

// Middle: all zone RRs (GetAllRecords excludes SOA — it iterates z.Records, not z.SOA)
const batchSize = 100
rrs := z.GetAllRecords()
for i := 0; i < len(rrs); i += batchSize {
    end := i + batchSize
    if end > len(rrs) {
        end = len(rrs)
    }
    ch <- &dns.Envelope{RR: rrs[i:end]}
}

// Closing SOA (RFC 5936 §2.2)
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}
close(ch)
wg.Wait()
w.Close() //nolint:errcheck  // Transfer.Out does not close the TCP conn; handler must.
```

Pattern source: `dns.Transfer.Out` is verified from miekg/dns xfr.go:206-240. `zone.GetAllRecords()` iterates `z.Records` map only (zone.go lines 205-215) — SOA lives in `z.SOA` field (zone.go line 20) exclusively.

---

### `internal/server/axfr_test.go` (test)

**Analog:** `internal/server/notify_test.go` (lines 1-141) — exact role match, same package, same test infrastructure.

#### Test file structure pattern
Copy from `internal/server/notify_test.go` lines 1-33:

```go
package server   // white-box test — same package as server

import (
    "net"
    "testing"

    "github.com/miekg/dns"
)
```

#### testResponseWriter pattern (from notify_test.go lines 11-32)
The existing `testResponseWriter` in `notify_test.go` captures only the last `Rcode` — insufficient for AXFR multi-message verification. A new `axfrTestResponseWriter` or TCP-capable writer is needed. Copy the interface structure, extend to accumulate messages:

```go
// testResponseWriter (existing, notify_test.go lines 11-32) — single-message only:
type testResponseWriter struct {
    rcode      int
    written    bool
    remoteAddr net.Addr
}
func (t *testResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (t *testResponseWriter) RemoteAddr() net.Addr        { return t.remoteAddr }
func (t *testResponseWriter) WriteMsg(m *dns.Msg) error   { t.rcode = m.Rcode; t.written = true; return nil }
func (t *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (t *testResponseWriter) Close() error                { return nil }
func (t *testResponseWriter) TsigStatus() error           { return nil }
func (t *testResponseWriter) TsigTimersOnly(b bool)       {}
func (t *testResponseWriter) Hijack()                     {}
```

For AXFR tests, define a new writer that:
1. Uses `*net.TCPAddr` as `RemoteAddr` (TCP path)
2. Accumulates all `WriteMsg` calls into a `[]dns.Msg` slice
3. Supports `TsigStatus()` returning nil (TSIG OK) or a controllable error for negative tests

#### Test setup pattern — Server with zones + TSIG keys
Copy from `notify_test.go` lines 53-78 (`New(cfg)` + `defer s.Stop()`), extend with:
- `cfg.TsigKeys` populated with a test key
- `cfg.Zones` populated with a minimal zone containing `z.SOA`
- `cfg.ZoneTransferCIDRs` set to `{"example.com.": ["127.0.0.1/32"]}` for positive ACL tests

```go
// Pattern: create minimal server with zone + TSIG + ACL
cfg := Config{
    TsigKeys: []tsig.KeyConfig{
        {Name: "test-key.", Algorithm: "hmac-sha256", Secret: "<base64>"},
    },
    ZoneTransferCIDRs: map[string][]string{
        "example.com.": {"127.0.0.1/32"},
    },
}
cfg.Zones = map[string]*zone.Zone{
    "example.com.": testZone(), // helper that returns a zone.Zone with SOA set
}
s, err := New(cfg)
// ...
defer s.Stop()
```

#### makeAXFRRequest helper — follow makeNotifyRequest pattern (notify_test.go lines 34-40)

```go
func makeAXFRRequest(qname string) *dns.Msg {
    m := new(dns.Msg)
    m.SetQuestion(qname, dns.TypeAXFR)
    m.RecursionDesired = false
    return m
}
```

---

### `internal/server/server.go` (modified — Config struct + New() init + handleDNS dispatch)

**Analog:** Same file — DSYNC init block at lines 253-293 for the `New()` pattern; NOTIFY dispatch at lines 480-501 for the `handleDNS` pattern.

#### Config struct addition — ZoneTransferCIDRs field
Add after `DSYNC DSYNCConfig` field (line 68), before `ReadTimeout`:

```go
// ZoneTransferCIDRs maps zone FQDN origin → list of CIDR strings allowed to AXFR.
// Populated by main.go from config.Config.Zones[*].AllowTransfer at startup.
// Empty slice for a zone = REFUSED (D-01: secure-by-default, inverts DSYNC behavior).
// Use string slices (not dsync.SourceACL) to avoid import cycle; ACL objects are
// built in New() and stored in s.zoneTransferACLs.
ZoneTransferCIDRs map[string][]string `yaml:"-"`
```

#### Server struct addition — zoneTransferACLs field
Add after `dsyncNotifier` field (line 156):

```go
// zoneTransferACLs holds per-zone CIDR ACLs for AXFR allow_transfer enforcement.
// nil entry for a zone = deny all (D-01). Built from cfg.ZoneTransferCIDRs in New().
zoneTransferACLs map[string]*dsync.SourceACL
```

#### New() init block — build zoneTransferACLs (copy DSYNC ACL pattern, lines 269-272)
Add after TSIG key ring initialization (after line 309), following the DSYNC `NewSourceACL` pattern:

```go
// Build per-zone transfer ACLs from ZoneTransferCIDRs.
// D-01: zones with no entry or empty CIDR list get nil ACL = deny all.
s.zoneTransferACLs = make(map[string]*dsync.SourceACL)
for zoneName, cidrs := range cfg.ZoneTransferCIDRs {
    if len(cidrs) == 0 {
        // Explicit empty = deny all; store nil (already zero value, but be explicit)
        s.zoneTransferACLs[zoneName] = nil
        continue
    }
    acl, err := dsync.NewSourceACL(cidrs)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("zone %s allow_transfer: %w", zoneName, err)
    }
    s.zoneTransferACLs[zoneName] = acl
}
```

Pattern source: `internal/server/server.go` lines 269-272 (DSYNC `NewSourceACL` call). `internal/dsync/source_acl.go` lines 25-52. Error wrapping pattern (`fmt.Errorf("...: %w", err)` + `cancel()` + `return nil, err`) from lines 203-205.

#### handleDNS dispatch addition — early TypeAXFR block (D-07)
Insert after the NOTIFY dispatch block (line 501), before the `s.defensive` blackhole check (line 504):

```go
// RFC 5936: dispatch AXFR before pool.GetMessage() — AXFR streams multiple
// messages and must NOT use the pooled single-response path.
if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR {
    if clientIP == nil {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    s.handleAXFR(w, r, clientIP)
    return
}
```

Pattern source: `internal/server/server.go` lines 480-501 (NOTIFY dispatch block) — identical structure. The nil-guard on `clientIP` is copied verbatim from lines 484-490.

---

### `cmd/dnsscienced/main.go` (modified — ZoneTransferCIDRs wiring)

**Analog:** `cmd/dnsscienced/main.go` lines 120-132 — `cfg = loadedCfg.Server` wiring pattern. Also lines 134-142 for defensive manager wiring (same "copy field from loadedCfg into cfg" pattern).

#### ZoneTransferCIDRs population — after `cfg = loadedCfg.Server` (line 132)
Add immediately after line 132 or after the defensive manager block:

```go
// Wire per-zone allow_transfer CIDRs from zone config into server config.
// config.Config.Zones holds AllowTransfer ([]string); server.Config.Zones holds zone data.
// They are separate structs; wiring is done here to avoid import cycles.
if len(loadedCfg.Zones) > 0 {
    cfg.ZoneTransferCIDRs = make(map[string][]string, len(loadedCfg.Zones))
    for _, zc := range loadedCfg.Zones {
        zoneName := dns.Fqdn(zc.Name) // ensure trailing dot (FQDN)
        cfg.ZoneTransferCIDRs[zoneName] = zc.AllowTransfer
    }
}
```

Also add TsigKeys wiring if absent (open question A2 in RESEARCH.md — no wiring found in main.go):

```go
// Wire TSIG keys from config into server config (server.Config.TsigKeys uses yaml:"-").
if len(loadedCfg.TsigKeys) > 0 {
    cfg.TsigKeys = make([]tsig.KeyConfig, len(loadedCfg.TsigKeys))
    for i, kc := range loadedCfg.TsigKeys {
        cfg.TsigKeys[i] = tsig.KeyConfig{
            Name:      kc.Name,
            Algorithm: kc.Algorithm,
            Secret:    kc.Secret,
        }
    }
}
```

Pattern source for conversion struct: `internal/admin/service.go` lines 1026-1030 (same `tsig.KeyConfig{Name, Algorithm, Secret}` literal pattern).

---

## Shared Patterns

### Error response (REFUSED / NOTAUTH)
**Source:** `internal/server/server.go` lines 486-499 (NOTIFY guard blocks)
**Apply to:** Every guard check in `axfr.go`

```go
m := new(dns.Msg)
m.SetReply(r)
m.Rcode = dns.RcodeRefused  // or dns.RcodeNotAuth for TSIG failures
w.WriteMsg(m) //nolint:errcheck
return
```

Never use `pool.GetMessage()` in `axfr.go` — AXFR exits before pool acquisition (D-07).

### CIDR ACL construction (NewSourceACL)
**Source:** `internal/dsync/source_acl.go` lines 25-52; used in `server.go` lines 269-272
**Apply to:** `server.go` New() init block for `zoneTransferACLs`

CRITICAL DIFFERENCE from DSYNC: `NewSourceACL(nil)` returns `allowAll: true`. For AXFR, do NOT call `NewSourceACL` with an empty slice — store `nil` to enforce D-01 (empty = deny all).

```go
// DSYNC pattern (allow-all on empty — wrong for AXFR):
sourceACL, _ := dsync.NewSourceACL(cfg.DSYNC.AllowedSources) // empty → allow all

// AXFR pattern (deny-all on empty — D-01):
if len(cidrs) == 0 {
    s.zoneTransferACLs[zoneName] = nil  // nil → deny all
} else {
    acl, err := dsync.NewSourceACL(cidrs)
    // ...
}
```

### RemoteAddr transport detection
**Source:** `internal/server/server.go` lines 466-478
**Apply to:** UDP truncation guard at top of `handleAXFR`

```go
if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP { ... }
```

### nil-guard accessors
**Source:** `internal/server/server.go` lines 438-449 (`tsigSecretMap`, `GetTsigKeyRing`)
**Apply to:** Any new exported accessor on Server; follow the pattern of checking for nil before use.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| — | — | — | All files have analogs; dns.Transfer.Out streaming has no in-codebase analog but is covered by miekg/dns xfr.go patterns in RESEARCH.md |

The multi-message streaming pattern (`dns.Transfer.Out` + channel + `sync.WaitGroup`) has no existing in-codebase analog (no other AXFR-style streaming exists). Use RESEARCH.md Pattern 5 (lines 224-256) as the primary reference for this section.

---

## Critical Verification Tasks for Planner

These must be confirmed at implementation time (not resolvable from static analysis alone):

1. **Does GetAllRecords() include the SOA?**
   `zone.Zone.GetAllRecords()` (zone.go lines 204-215) iterates `z.Records map[string]map[uint16][]dns.RR`. The SOA field is `z.SOA *dns.SOA` (zone.go line 20) — a separate struct field. Zone parsers must be checked: do they also store SOA in `z.Records`? If yes, filter SOA from the middle batch to avoid triple-SOA. If no (most likely, given the separate field), no filtering needed.
   Verification: `go test ./internal/zone/... -run TestGetAllRecords` or inspect zone loader.

2. **Is TsigKeys wiring in main.go missing?**
   Grep of `cmd/dnsscienced/main.go` found zero matches for `TsigKeys`, `tsig.KeyConfig`, or `cfg.TsigKeys`. The wiring block described above is NOT currently present. Plan 01 must add it, or TSIG auth will always fail (server starts with empty KeyRing, no keys ever loaded from config).

---

## Metadata

**Analog search scope:** `internal/server/`, `internal/dsync/`, `internal/zone/`, `internal/tsig/`, `internal/config/`, `cmd/dnsscienced/`
**Files scanned:** 8 source files read
**Pattern extraction date:** 2026-05-23
