# Phase 12: AXFR Server - Research

**Researched:** 2026-05-23
**Domain:** DNS Zone Transfer Protocol (RFC 5936), TSIG Authentication (RFC 2845), miekg/dns server-side AXFR
**Confidence:** HIGH

## Summary

Phase 12 implements a server-side AXFR handler that streams complete zone contents to authorized secondary DNS servers. The implementation sits inside `internal/server/` as a new `axfr.go` file, dispatched early from `handleDNS()` following the identical pattern established for NOTIFY in Phase 8.

The key implementation substrate is `miekg/dns v1.1.72`'s `dns.Transfer.Out()` API, which handles multi-message streaming and per-message TSIG signing automatically when fed an envelope channel. The handler must enforce two guards before invoking `Transfer.Out`: (1) TSIG presence (the library verifies valid TSIG but does not reject absent TSIG — the handler must enforce presence), and (2) IP ACL via `dsync.SourceACL` (inverted semantics: empty allowlist = REFUSED, the opposite of DSYNC).

The critical design question from CONTEXT.md — "how to look up ZoneConfig at dispatch time" — has a clear answer: `server.Config.Zones` (`map[string]*zone.Zone`) holds zone data, but `config.Config.Zones` (`[]ZoneConfig`) holds the AllowTransfer list. The server currently has no indexed map of ZoneConfig. The handler must either receive a `map[string]config.ZoneConfig` built at startup or do a linear scan. Building a `zoneTransferACLs map[string]*dsync.SourceACL` field on `Server` at init time is the correct approach — it indexes per-zone ACLs for O(1) dispatch-time lookup.

**Primary recommendation:** Implement `handleAXFR()` as a method on `*Server` in `internal/server/axfr.go`, dispatched early in `handleDNS()`, using `dns.Transfer.Out()` for multi-message streaming with automatic per-message TSIG signing.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Empty `allow_transfer` list = REFUSED. Secure-by-default; operators must explicitly grant access.
- **D-02:** `allow_transfer` is already defined as `AllowTransfer []string` in `ZoneConfig`. No new config field needed.
- **D-03:** IP ACL failure → return REFUSED (rcode 5).
- **D-04:** TSIG is always required globally. No per-zone `require_tsig` flag. Unsigned requests → NOTAUTH (rcode 9).
- **D-05:** TSIG verification failure (bad key, bad sig, missing TSIG) → return NOTAUTH (rcode 9), per RFC 2845 §4.
- **D-06:** Reuse existing `tsig.KeyRing` wired to `dns.Server.TsigSecret`. miekg/dns auto-verifies TSIG on incoming messages; handler must additionally check TSIG was present at all.
- **D-07:** AXFR dispatches early in `handleDNS`, before `pool.GetMessage()` — same pattern as NOTIFY (line 480 in server.go).
- **D-08:** AXFR over UDP returns TC=1 (truncation flag set, no answer section). Do not return REFUSED on UDP.
- **D-09:** AXFR response is multi-message, RFC 5936-compliant: opening SOA + batches of RRs + closing SOA. Single-message is not acceptable.
- **D-10:** AXFR handler lives inline in `internal/server/` as a new `axfr.go` file. No separate package.

### Claude's Discretion

- How the handler detects TSIG presence/absence (r.IsTsig() vs checking r.Extra for TSIG RR)
- Message batching strategy for multi-message streaming (RR count per message vs. byte budget)
- How to look up ZoneConfig from zone origin string at dispatch time

### Deferred Ideas (OUT OF SCOPE)

- IXFR server (incremental zone transfers, RFC 1995)
- NOTIFY-on-transfer
- Per-zone TSIG key binding
- Catalog zones (RFC 9432)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| XFER-01 | AXFR request over TCP receives complete zone: opening SOA + all RRs + closing SOA in correct wire format (RFC 5936) | `dns.Transfer.Out()` + `zone.GetAllRecords()` provide the streaming infrastructure; opening/closing SOA must be explicitly sent |
| XFER-02 | TSIG-authenticated transfers accepted; unsigned requests rejected with NOTAUTH | `r.IsTsig()` detects presence; `w.TsigStatus()` reflects auto-verification by miekg/dns; `Transfer.Out()` signs each outgoing message automatically |
| XFER-03 | AXFR from IP not in `allow_transfer` → REFUSED regardless of TSIG | `dsync.SourceACL.Check(net.IP)` directly reusable; build per-zone ACL map at server init |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TCP-only zone transfer streaming | DNS Server (TCP) | — | RFC 5936 §4.2 mandates TCP; UDP returns TC=1 redirect |
| TSIG authentication enforcement | DNS Server handler | tsig package | Handler enforces presence; miekg/dns auto-verifies signature |
| IP ACL enforcement | DNS Server handler | dsync.SourceACL | Reuses Phase 8 CIDR ACL infrastructure |
| Zone content enumeration | zone.Zone | — | `GetAllRecords()` already exists |
| Per-message TSIG signing | dns.Transfer.Out | — | Library handles signing automatically when given TSIG-signed request |

## Standard Stack

### Core (already in go.mod — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/miekg/dns` | v1.1.72 [VERIFIED: go.mod] | AXFR streaming via `dns.Transfer.Out()`, TSIG ops | Already used throughout; `Transfer.Out` is the idiomatic server-side AXFR API |
| `internal/dsync` | project-internal | `SourceACL` for CIDR IP ACL | Identical ACL problem, directly reusable |
| `internal/tsig` | project-internal | `KeyRing` for TSIG key lookup | Already wired to all `dns.Server` instances |
| `internal/zone` | project-internal | `zone.Zone.GetAllRecords()` | Content source for transfer stream |

### No New Dependencies

This phase requires zero new external dependencies. All required infrastructure exists.

**Installation:** None required.

## Architecture Patterns

### System Architecture Diagram

```
TCP client (secondary DNS)
        |
        | AXFR query (TypeAXFR) over TCP
        v
handleDNS() — early dispatch [line ~502 in server.go]
        |
        |-- UDP? --> TC=1 truncated response (D-08)
        |
        v
handleAXFR(w, r, clientIP)
        |
        |-- len(r.Question)==0 --> REFUSED (malformed)
        |
        |-- TSIG absent? (r.IsTsig()==nil) --> NOTAUTH (D-04/D-05)
        |
        |-- TSIG bad? (w.TsigStatus()!=nil) --> NOTAUTH (D-05, auto-verified by miekg)
        |
        |-- Zone lookup: s.cfg.Zones[qname] --> not found? REFUSED
        |
        |-- ACL check: s.zoneTransferACLs[qname].Check(clientIP) --> false? REFUSED (D-01/D-03)
        |
        v
dns.Transfer.Out(w, r, ch)      zone.GetAllRecords()
        |                               |
        |<-- Envelope{[SOA]}            |
        |<-- Envelope{[RR batch...]}    |
        |<-- Envelope{[SOA]}            |
        |                               |
  (channel closed) <-------------------+
        |
   w.Close()
```

### Recommended Project Structure

```
internal/server/
├── server.go        # existing — add zoneTransferACLs field + init + handleAXFR dispatch
└── axfr.go          # NEW — handleAXFR() method + zone ACL init helpers
```

### Pattern 1: Early AXFR Dispatch in handleDNS

**What:** Detect TypeAXFR in question section before pool.GetMessage(), dispatch to handleAXFR.
**When to use:** Always — AXFR must exit before pool acquisition because it streams multiple messages.

```go
// In handleDNS(), after the NOTIFY block (~line 501):
// Source: internal/server/server.go (NOTIFY dispatch pattern, line 480-501)
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

### Pattern 2: UDP Truncation Response (D-08)

**What:** On UDP transport, return TC=1 with no answer section (RFC 5936 §4.2 signal).

```go
// Source: [VERIFIED: RFC 5936 §4.2; server.go transport detection pattern]
func (s *Server) handleAXFR(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
    // Detect UDP via RemoteAddr type — same pattern used elsewhere in server.go
    if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Truncated = true
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    // ... TCP path continues
}
```

### Pattern 3: TSIG Presence + Validity Check (D-04, D-05, D-06)

**What:** miekg/dns auto-verifies TSIG when TsigSecret is populated, but does NOT reject absent TSIG. Handler must enforce presence.

```go
// Source: [VERIFIED: miekg/dns defaults.go:135 IsTsig(), server.go:824 TsigStatus()]
// Check TSIG presence first
if r.IsTsig() == nil {
    // No TSIG record at all — reject per D-04
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m) //nolint:errcheck
    return
}
// TSIG present — miekg/dns has already verified it; check result
if w.TsigStatus() != nil {
    // Bad signature, unknown key, etc. — reject per D-05
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeNotAuth
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

### Pattern 4: Zone Lookup and ACL Check

**What:** Find zone by exact QNAME match, check IP ACL.

```go
// Source: [VERIFIED: internal/server/server.go zone lookup pattern; internal/dsync/source_acl.go]
qname := r.Question[0].Name
z, ok := s.cfg.Zones[qname]
if !ok {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
acl := s.zoneTransferACLs[qname] // nil if zone not in map (no allow_transfer configured)
if acl == nil || !acl.Check(clientIP) {
    // D-01: nil ACL (no allow_transfer) = REFUSED; D-03: unlisted source = REFUSED
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeRefused
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

### Pattern 5: dns.Transfer.Out Streaming (D-09)

**What:** miekg/dns `Transfer.Out` consumes an `Envelope` channel and sends RFC 5936-compliant multi-message AXFR. It handles per-message TSIG signing automatically when the request had TSIG.

```go
// Source: [VERIFIED: miekg/dns xfr.go:206-240 Transfer.Out godoc + implementation]
// Basic use pattern from godoc:
ch := make(chan *dns.Envelope)
tr := new(dns.Transfer)
var wg sync.WaitGroup
wg.Add(1)
go func() {
    tr.Out(w, r, ch)
    wg.Done()
}()

// Send opening SOA, all RRs, closing SOA in one or more envelopes
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}
// Batch remaining RRs (excluding SOA to avoid duplicate at zone apex)
rrs := filterSOA(z.GetAllRecords())
for i := 0; i < len(rrs); i += batchSize {
    end := i + batchSize
    if end > len(rrs) {
        end = len(rrs)
    }
    ch <- &dns.Envelope{RR: rrs[i:end]}
}
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}} // closing SOA
close(ch)
wg.Wait()
w.Close() //nolint:errcheck
```

**TSIG signing in Transfer.Out:** Line 231-233 of xfr.go shows `Transfer.Out` reads `q.IsTsig()` and calls `r.SetTsig(...)` + `w.TsigTimersOnly(true)` on each message. Since TSIG presence and validity were already verified above, `Transfer.Out` handles all outgoing signing automatically. [VERIFIED: miekg/dns xfr.go:231-238]

### Pattern 6: zoneTransferACLs Initialization

**What:** Build a `map[string]*dsync.SourceACL` on the Server struct at startup, indexed by zone FQDN origin. The `config.Config.Zones []ZoneConfig` slice (not `server.Config.Zones`) holds `AllowTransfer` lists.

**The ZoneConfig gap:** `server.Config` only carries `Zones map[string]*zone.Zone` (zone data, no AllowTransfer). `config.Config.Zones []ZoneConfig` carries AllowTransfer but lives in the config package, not passed to server.New(). The AXFR handler needs AllowTransfer at dispatch time.

**Resolution options (Claude's Discretion):**

Option A — Add `ZoneTransferCIDRs map[string][]string` to `server.Config`:
- main.go populates it from `loadedCfg.Zones` at startup
- Server builds ACL map in New() from this field
- No config package import cycle ([]string, not config.ZoneConfig)

Option B — Add `ZoneConfigs []config.ZoneConfig` to `server.Config`:
- Requires importing config package from server package
- Creates import cycle: server → config → server
- NOT viable

Option C — Accept a separate `map[string]*dsync.SourceACL` built by main.go:
- main.go builds the ACL map, passes to server via a setter or New() parameter
- Adds complexity to New() signature

**Recommendation (Option A):** Add `ZoneTransferCIDRs map[string][]string` to `server.Config`, populated by main.go at startup. Server.New() builds `s.zoneTransferACLs map[string]*dsync.SourceACL` from this. D-01 (empty = REFUSED) is enforced by treating absent or nil ACL as deny.

### Anti-Patterns to Avoid

- **Single-message AXFR:** Putting all RRs in one Envelope violates RFC 5936 and fails for non-trivial zones. Always stream.
- **SOA duplication in non-SOA batch:** `GetAllRecords()` returns all records including the SOA. Filter out SOA from the middle batch — opening and closing SOA are added explicitly. Failing to filter causes duplicate SOA in the middle.
- **Checking TSIG validity before presence:** Must check `r.IsTsig() == nil` first. If nil, `w.TsigStatus()` is also nil (no TSIG to fail). Checking `TsigStatus()` first would silently accept unsigned requests.
- **Not calling w.Close() after Transfer.Out:** Transfer.Out drives the write loop but does not close the TCP connection. Handler must call `w.Close()` after `wg.Wait()`.
- **Using pool.GetMessage() for AXFR responses:** AXFR sends multiple messages; the pooled message pattern is for single responses. Transfer.Out creates its own messages.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Multi-message TSIG signing | Custom signing loop | `dns.Transfer.Out()` | Library handles `SetTsig()` + `TsigTimersOnly(true)` per-message per RFC 5936 §2.2 automatically |
| CIDR IP ACL | Custom net.IP comparison | `dsync.NewSourceACL()` + `Check()` | Phase 8 infrastructure; handles IPv4/IPv6, /32, /128, error on invalid CIDRs |
| Message size budgeting | Custom byte-count packer | Fixed RR-count batching (e.g., 100 RRs/message) | `Transfer.Out` sends one Envelope per message; keeping envelopes small prevents oversized messages |

**Key insight:** `dns.Transfer.Out` is the correct server-side AXFR primitive in miekg/dns. It is not widely documented but the godoc + source in `xfr.go` lines 206-240 show the exact channel-driven pattern. Do not implement raw TCP message writing — use Transfer.Out.

## Common Pitfalls

### Pitfall 1: Missing SOA at Zone Apex in GetAllRecords Output

**What goes wrong:** `zone.GetAllRecords()` iterates `z.Records` map which stores records by owner name and type. If the SOA is stored in `z.SOA` field but not in `z.Records`, it will be absent from the middle batch. Conversely if it IS in Records, filtering it from the batch is needed to avoid three SOA appearances.
**Why it happens:** Zone struct has a dedicated `SOA *dns.SOA` field AND records map; the relationship between them depends on how zone loading works.
**How to avoid:** Check whether `GetAllRecords()` includes the SOA. If yes, filter SOA from the non-apex envelopes. Send `z.SOA` explicitly as the opening and closing SOA.
**Warning signs:** Secondary rejects with ErrSoa or sees an unexpected SOA serial in the middle.

### Pitfall 2: TSIG Presence Check Order

**What goes wrong:** Checking `w.TsigStatus() != nil` before `r.IsTsig() == nil` causes silent acceptance of unsigned AXFR requests, because an absent TSIG produces `TsigStatus() == nil`.
**Why it happens:** miekg/dns populates TsigStatus only when a TSIG record is present and verification runs.
**How to avoid:** Always check `r.IsTsig() == nil` first; only then check `w.TsigStatus()`.

### Pitfall 3: ZoneConfig AllowTransfer Not Available in Server at Dispatch

**What goes wrong:** `server.Config.Zones` is `map[string]*zone.Zone` (zone data only, no AllowTransfer). AllowTransfer lives in `config.Config.Zones []ZoneConfig`, which is not passed to the server. The handler has no way to find per-zone ACL at runtime.
**Why it happens:** The server/config architecture separates zone data (in server.Config) from zone configuration (in config.ZoneConfig).
**How to avoid:** Add `ZoneTransferCIDRs map[string][]string` to `server.Config`; populate from `loadedCfg.Zones` in main.go; build `zoneTransferACLs` in `New()`.

### Pitfall 4: AXFR over UDP — Wrong Error Code

**What goes wrong:** Returning REFUSED on UDP AXFR requests. RFC 5936 §4.2 requires TC=1 (truncation), which signals clients to retry over TCP.
**Why it happens:** Easy to return REFUSED for "unsupported transport" without reading the RFC.
**How to avoid:** Detect UDP via `w.RemoteAddr().(*net.UDPAddr)` type assertion; set `m.Truncated = true`; no answer section; return.

### Pitfall 5: Not Calling w.Close() After Transfer.Out

**What goes wrong:** TCP connection stays open; secondary hangs waiting for more data.
**Why it happens:** `Transfer.Out` returns when the channel is closed and drained, but does not close the underlying TCP connection.
**How to avoid:** After `wg.Wait()`, call `w.Close()`.

### Pitfall 6: AXFR Dispatch Placed After pool.GetMessage()

**What goes wrong:** The pooled message is acquired even for AXFR requests. The deferred `pool.PutMessage(m)` runs after the handler returns, potentially resetting a message still in use or causing confusion.
**Why it happens:** Missing the early dispatch pattern (D-07).
**How to avoid:** Insert AXFR dispatch block before `pool.GetMessage()`, same as NOTIFY dispatch at line 482.

## Code Examples

### TSIG Detection — IsTsig() API

```go
// Source: [VERIFIED: miekg/dns defaults.go:133-142]
// IsTsig returns the *TSIG record from r.Extra if the last Extra record is TSIG, else nil.
// Use for presence check:
tsig := r.IsTsig() // nil means no TSIG present
```

### TsigStatus — Auto-Verification Result

```go
// Source: [VERIFIED: miekg/dns server.go:824 TsigStatus()]
// w.TsigStatus() returns nil if TSIG verified OK (or no TSIG on request)
// Returns error if TSIG was present but verification failed
status := w.TsigStatus() // non-nil = bad TSIG
```

### Transfer.Out Full Example

```go
// Source: [VERIFIED: miekg/dns xfr.go:206-240 godoc]
ch := make(chan *dns.Envelope)
tr := new(dns.Transfer)
var wg sync.WaitGroup
wg.Add(1)
go func() {
    if err := tr.Out(w, r, ch); err != nil {
        // log transfer error — connection likely dropped
    }
    wg.Done()
}()
// Feed envelopes: [SOA], [RRs...], [SOA]
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}
// ... batch RRs ...
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}
close(ch)
wg.Wait()
w.Close() //nolint:errcheck
```

### NewSourceACL for allow_transfer (inverted D-01 semantics)

```go
// Source: [VERIFIED: internal/dsync/source_acl.go — NewSourceACL; D-01 inverts D-05]
// For AXFR: empty cidrs list must mean DENY ALL (not allow all as in DSYNC)
// Build ACL only when len(cidrs) > 0:
if len(zoneConfig.AllowTransfer) == 0 {
    // No ACL configured — deny all (D-01); store nil in map
    s.zoneTransferACLs[zoneName] = nil
} else {
    acl, err := dsync.NewSourceACL(zoneConfig.AllowTransfer)
    if err != nil {
        return fmt.Errorf("zone %s allow_transfer: %w", zoneName, err)
    }
    s.zoneTransferACLs[zoneName] = acl
}
```

Note: `dsync.NewSourceACL(nil)` returns `allowAll: true` — do NOT call it with an empty slice for AXFR. Build ACLs only for non-empty AllowTransfer lists.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single-message AXFR (RFC 1034-era) | Multi-message streaming per RFC 5936 | RFC 5936 published 2010 | Mandatory for non-trivial zones; Transfer.Out handles this |
| AXFR without TSIG | TSIG-authenticated AXFR (RFC 2845) | RFC 2845 published 1997 | All secondaries must present valid TSIG |

**No deprecated approaches in scope:** miekg/dns `Transfer.Out` is the current correct API. [VERIFIED: miekg/dns xfr.go v1.1.72]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `zone.GetAllRecords()` may or may not include the `z.SOA` record in its output (iterates `z.Records` map; SOA may be stored there too) | Common Pitfalls #1, Code Examples | Handler would either miss SOA in middle or send triple SOA; needs verification at implementation time |
| A2 | main.go does not currently wire `loadedCfg.TsigKeys` into `server.Config.TsigKeys` | Architecture Patterns #6 | TSIG keys may already be wired; check main.go lines around srv.New() before adding wiring |

## Open Questions

1. **Does GetAllRecords() include the SOA?**
   - What we know: `zone.Zone.SOA *dns.SOA` is a separate field; `GetAllRecords()` iterates `z.Records` map (line 205-215 of zone.go). The SOA may or may not be stored in `z.Records` as well.
   - What's unclear: Whether zone parsers store SOA in both `z.SOA` AND `z.Records`, or only in `z.SOA`.
   - Recommendation: Implementation (Wave 0 or Plan 01) must verify this with a test before building the RR batching logic. Check `zone.GetAllRecords()` return for SOA records, then decide whether to filter.

2. **Is main.go wiring for TsigKeys needed?**
   - What we know: `server.Config.TsigKeys []tsig.KeyConfig` exists with `yaml:"-"` tag (not decoded from YAML directly). STATE.md says "tsig.KeyConfig in server.Config uses yaml:'-' — populated by main.go after config load." But no such code was found in main.go (cmd/dnsscienced/main.go).
   - What's unclear: Whether TSIG keys work with the current main.go or require a wiring step.
   - Recommendation: Phase 12 Plan 01 must add `cfg.TsigKeys` wiring from `loadedCfg.TsigKeys` in main.go if absent, since TSIG is required for all AXFR.

## Environment Availability

Step 2.6: SKIPPED — Phase is purely code additions with no new external tool dependencies. All required packages (`github.com/miekg/dns`, `internal/dsync`, `internal/tsig`, `internal/zone`) are already in go.mod and confirmed building.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go testing (stdlib), testify v1.11.1 |
| Config file | none (go test ./...) |
| Quick run command | `go test ./internal/server/... -run TestAXFR -v` |
| Full suite command | `go test ./internal/server/... ./internal/dsync/... ./internal/tsig/... ./internal/zone/...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| XFER-01 | TCP AXFR returns opening SOA + all RRs + closing SOA | unit (in-process) | `go test ./internal/server/... -run TestHandleAXFR_TCPComplete -v` | No — Wave 0 |
| XFER-02 | TSIG-signed request accepted; unsigned → NOTAUTH | unit (in-process) | `go test ./internal/server/... -run TestHandleAXFR_TSIG -v` | No — Wave 0 |
| XFER-03 | Source not in allow_transfer → REFUSED | unit (in-process) | `go test ./internal/server/... -run TestHandleAXFR_ACL -v` | No — Wave 0 |
| XFER-01 (UDP) | UDP AXFR returns TC=1, no REFUSED | unit | `go test ./internal/server/... -run TestHandleAXFR_UDP -v` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./internal/server/... -count=1`
- **Per wave merge:** `go test ./internal/server/... ./internal/dsync/... ./internal/tsig/... ./internal/zone/... -count=1`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/server/axfr_test.go` — covers XFER-01, XFER-02, XFER-03, UDP truncation
- [ ] A test helper `tcpTestResponseWriter` or similar that captures multi-message writes is needed for AXFR testing (the existing `testResponseWriter` in `notify_test.go` captures only the last `WriteMsg` call)

Note: The existing `notify_test.go` `testResponseWriter` captures `rcode int` only — insufficient for verifying multi-message streaming. AXFR tests need a writer that accumulates all written messages to verify SOA-RRs-SOA sequence.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | TSIG via `tsig.KeyRing` — mandatory, always required |
| V3 Session Management | no | Stateless DNS protocol |
| V4 Access Control | yes | Per-zone CIDR ACL via `dsync.SourceACL` |
| V5 Input Validation | yes | Empty question guard; zone existence check; TSIG presence check before validity |
| V6 Cryptography | yes | HMAC-SHA256/384/512 only; enforced by `tsig.ValidateAlgorithm` (already in place) |

### Known Threat Patterns for AXFR Server Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Zone content exfiltration by unauthorized secondary | Information Disclosure | Per-zone allow_transfer ACL (XFER-03); TSIG authentication (XFER-02) |
| TSIG replay attack | Spoofing | miekg/dns TsigVerify checks timestamp fudge (300s default in tsig.Sign); auto-mitigated |
| Zone enumeration via AXFR | Information Disclosure | REFUSED for all unlisted sources; NOTAUTH for unsigned |
| DoS via AXFR flood | Denial of Service | Existing RRL applies to query counts; AXFR exits early on ACL/TSIG failure before streaming |
| Unsigned transfer accepted | Spoofing | Handler explicitly checks `r.IsTsig() == nil` → NOTAUTH (D-04) |

## Sources

### Primary (HIGH confidence)

- `miekg/dns v1.1.72 xfr.go` — `Transfer.Out()` API, `Transfer.In()`, TSIG signing per-message; lines 206-240 [VERIFIED: source read in this session]
- `miekg/dns v1.1.72 defaults.go:133-142` — `IsTsig()` API [VERIFIED: source read]
- `miekg/dns v1.1.72 server.go:824` — `TsigStatus()` API [VERIFIED: source read]
- `miekg/dns v1.1.72 defaults.go:134,138` — `RcodeRefused=5`, `RcodeNotAuth=9` [VERIFIED: source read]
- `internal/dsync/source_acl.go` — `NewSourceACL()`, `Check()` directly reusable [VERIFIED: source read]
- `internal/tsig/tsig.go` — `KeyRing`, `IsTsig` equivalent (`r.IsTsig()`), all TSIG APIs [VERIFIED: source read]
- `internal/zone/zone.go:204-215` — `GetAllRecords()` implementation [VERIFIED: source read]
- `internal/server/server.go:461-501` — NOTIFY dispatch pattern for AXFR early dispatch model [VERIFIED: source read]
- `internal/config/config.go:75-134` — `ZoneConfig.AllowTransfer []string` at line 103 [VERIFIED: source read]

### Secondary (MEDIUM confidence)

- RFC 5936 (DNS Zone Transfer Protocol) — multi-message requirement §2.2, TCP requirement §4.2, TSIG signing §2.2 [CITED: RFC 5936 via CONTEXT.md canonical refs]
- RFC 2845 (TSIG) — NOTAUTH rcode §4 [CITED: RFC 2845 via CONTEXT.md canonical refs]

### Tertiary (LOW confidence)

None — all claims verified against source code or official RFC references in CONTEXT.md.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries verified in go.mod and source-read
- Architecture: HIGH — dispatch pattern verified from server.go; Transfer.Out verified from xfr.go source
- Pitfalls: HIGH — verified against miekg/dns source and existing codebase patterns
- ZoneConfig lookup gap: HIGH — confirmed no ZoneConfig indexed in server.Config by grep

**Research date:** 2026-05-23
**Valid until:** 2026-06-23 (stable dependencies; miekg/dns API is stable)
