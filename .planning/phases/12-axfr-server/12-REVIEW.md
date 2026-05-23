---
phase: 12-axfr-server
reviewed: 2026-05-23T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - internal/server/axfr.go
  - internal/server/axfr_test.go
  - internal/server/server.go
  - cmd/dnsscienced/main.go
findings:
  critical: 2
  warning: 3
  info: 2
  total: 7
status: issues_found
---

# Phase 12: Code Review Report

**Reviewed:** 2026-05-23
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

This phase implements RFC 5936 AXFR zone transfer on top of the existing DNS server. The guard chain (UDP truncation → TSIG presence → TSIG validity → zone lookup → ACL) is logically sound, and the secure-by-default deny-all ACL posture (D-01) is correctly implemented for zones with no `allow_transfer` entry.

Two blockers were found. The most serious is a SOA duplication bug: for every production zone loaded via the YAML parser, BIND parser, or compiled loader, the SOA record lives in BOTH `z.SOA` and `z.Records`. `GetAllRecords()` iterates `z.Records`, so the SOA appears in the "middle" section of the transfer as well as the mandatory opening and closing positions — violating RFC 5936 §2.2 and producing a malformed zone transfer. The second blocker is a security gap in `handleDNS`: the AXFR dispatcher checks `r.Question[0].Qtype == dns.TypeAXFR` to route zone transfers, but does not handle `dns.TypeIXFR` — an IXFR request for an authoritative zone passes straight into the normal authoritative handler, which can leak zone content without TSIG or ACL checks.

Three warnings cover: missing nil-guard on `z.SOA` before streaming (a nil SOA panics at runtime), the `tr.Out` goroutine leak when the channel send blocks, and a dangerous semantic mismatch between `NewSourceACL([]string{})` returning `allowAll: true` (used by DSYNC) versus the AXFR ACL builder treating an empty list as deny-all.

---

## Critical Issues

### CR-01: SOA duplicated in AXFR middle section for all file-loaded zones

**File:** `internal/server/axfr.go:98-106` (caused by `internal/zone/zone.go:127-131` + all three parsers)

**Issue:** The comment on line 98 asserts "`GetAllRecords` iterates `z.Records` only, does NOT include `z.SOA`". This is false for any zone loaded through the production code paths.

- `zone.ParseDNSZone` calls `zone.AddRecord(soa)` (`parser_dnszone.go:263`)
- `zone.ParseBIND` routes every record through `zone.AddRecord` (`parser_bind.go:43`)
- `zone.LoadCompiledZone` calls `zone.AddRecord(zone.SOA)` (`loader.go:46`)

`AddRecord` stores the SOA in both `z.Records[owner][dns.TypeSOA]` AND `z.SOA` (`zone.go:127-131`). Because `GetAllRecords` iterates `z.Records`, it will include the SOA. The AXFR transfer therefore sends: `[opening SOA] → [SOA again in middle RRs] → [all other records] → [closing SOA]`, which is a malformed transfer violating RFC 5936 §2.2. Secondary nameservers may reject it or import a corrupt zone.

The test zone helper (`axfr_test.go:51-82`) constructs the zone by directly setting `z.SOA` and populating `z.Records` *without* the SOA type key, so tests pass while production is broken.

**Fix:** Filter out SOA records from the `GetAllRecords()` result before streaming, or add a dedicated `GetNonSOARecords()` method. Simplest immediate fix in `axfr.go`:

```go
// Middle: all zone RRs — exclude SOA (it bookends the transfer)
allRRs := z.GetAllRecords()
var rrs []dns.RR
for _, rr := range allRRs {
    if rr.Header().Rrtype != dns.TypeSOA {
        rrs = append(rrs, rr)
    }
}
for i := 0; i < len(rrs); i += axfrBatchSize {
    end := i + axfrBatchSize
    if end > len(rrs) {
        end = len(rrs)
    }
    ch <- &dns.Envelope{RR: rrs[i:end]}
}
```

---

### CR-02: IXFR requests bypass TSIG and ACL guards

**File:** `internal/server/server.go:527`

**Issue:** The AXFR dispatcher in `handleDNS` is keyed on `r.Question[0].Qtype == dns.TypeAXFR`. An inbound IXFR request (`dns.TypeIXFR`) is not intercepted and falls through to `handleAuthoritative`. The authoritative handler (`handleAuthoritative`) serves zone records for any in-zone name without TSIG validation or ACL checking. While a full IXFR response requires server-side incremental state (not implemented), a secondary can also receive a full zone in an IXFR response. More critically, the absence of TSIG/ACL checks on `TypeIXFR` means an unauthenticated, unpermitted client requesting IXFR gets a NOERROR response with zone data rather than NOTAUTH/REFUSED.

At a minimum, IXFR queries should be refused or handled identically to AXFR for the guard chain.

**Fix:**

```go
// internal/server/server.go, near line 527
if len(r.Question) > 0 &&
    (r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR) {
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

`handleAXFR` already gates on the question type name for zone lookup, so routing IXFR through the same guard chain is safe. Alternatively, return NOTIMP for IXFR if incremental transfers are not supported.

---

## Warnings

### WR-01: Nil SOA dereference panic in transfer path

**File:** `internal/server/axfr.go:96` and `axfr.go:109`

**Issue:** Both the opening and closing SOA envelopes send `z.SOA` directly:

```go
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}  // line 96
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}  // line 109
```

`zone.Zone.SOA` is a pointer (`*dns.SOA`). `Validate()` is called by `AddZone` but NOT by `LoadZone` (which calls `ParseDNSZone`/`ParseBIND` directly). A zone file with a missing or unparseable SOA record that ends up in `s.cfg.Zones` with `SOA == nil` will cause a nil-pointer dereference when passed as a `dns.RR` interface value — the interface will be non-nil but the underlying concrete pointer is nil, causing a panic in `dns.Transfer.Out` when it tries to read the RR header.

**Fix:** Add an explicit nil guard before the streaming section:

```go
if z.SOA == nil {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Rcode = dns.RcodeServerFailure
    w.WriteMsg(m) //nolint:errcheck
    return
}
```

---

### WR-02: Goroutine leak when Transfer.Out channel is blocked

**File:** `internal/server/axfr.go:90-93`

**Issue:** The `tr.Out` goroutine is started before any sends on `ch`. If `tr.Out` returns early (e.g., because the underlying TCP connection is closed by the peer or due to a write error), the goroutine exits and nobody is reading `ch`. The subsequent sends at lines 96, 105, and 109:

```go
ch <- &dns.Envelope{RR: []dns.RR{z.SOA}}   // line 96 — blocks forever
```

...will block forever because `ch` is an unbuffered channel and there is no reader. `wg.Wait()` at line 111 will never return, leaking the goroutine servicing this TCP connection.

The `tr.Out` goroutine already suppresses its error return via `//nolint:errcheck`. There is no feedback path from the writer goroutine to the sender loop.

**Fix:** Use a context or select with a done signal to abort the send loop if the writer goroutine exits:

```go
errCh := make(chan error, 1)
go func() {
    errCh <- tr.Out(w, r, ch)
    wg.Done()
}()

send := func(env *dns.Envelope) bool {
    select {
    case ch <- env:
        return true
    case <-errCh:
        // tr.Out exited early; drain errCh and abort
        return false
    }
}

if !send(&dns.Envelope{RR: []dns.RR{z.SOA}}) {
    close(ch)
    wg.Wait()
    return
}
// ... rest of loop ...
```

---

### WR-03: `NewSourceACL([]string{})` returns allow-all — inconsistent with AXFR empty-list semantics

**File:** `internal/dsync/source_acl.go:26-28` / `internal/server/server.go:320-331`

**Issue:** `NewSourceACL` documents that an empty list means "allow all":

```go
// NewSourceACL: Empty/nil = allow all.
if len(cidrs) == 0 {
    return &SourceACL{allowAll: true}, nil
}
```

The AXFR ACL builder in `server.go` works around this by intercepting the empty case and storing `nil`:

```go
if len(cidrs) == 0 {
    s.zoneTransferACLs[zoneName] = nil   // deny-all
    continue
}
acl, err := dsync.NewSourceACL(cidrs)  // only called for non-empty
```

This is fragile. Any future code path that calls `NewSourceACL(emptySlice)` expecting deny-all behavior will silently get allow-all instead. The workaround in `server.go` is correct, but it is only one call site — there is no enforcement at the type level.

**Fix:** Either document this at both call sites with explicit `// NOTE: empty = allow-all for DSYNC, deny-all handled by caller for AXFR` comments, or introduce a distinct `NewTransferACL` that fails closed on empty input and is used exclusively for AXFR.

---

## Info

### IN-01: AXFR test does not verify SOA bookending or record count

**File:** `internal/server/axfr_test.go:260-280`

**Issue:** `TestHandleAXFR_Success_StreamsSOA` only verifies that `w.Close()` was called — it does not assert the structure of the transfer (opening SOA, middle records, closing SOA). The comment acknowledges "Transfer.Out will fail on mock writer (no TCP framing)" which means the test cannot verify correct streaming behavior. This is why the SOA duplication bug (CR-01) is not caught by any test.

**Fix:** Mock `dns.Transfer.Out` behavior or test at a lower level by inspecting the envelopes sent to `ch` directly. Alternatively, verify the count and types of messages if any arrive in `w.msgs`.

---

### IN-02: Misleading comment about SIGHUP performing "full config reload"

**File:** `cmd/dnsscienced/main.go:334`

**Issue:** The comment reads `// D-09: Full config reload (not just API keys)`. The actual SIGHUP implementation only reloads admin API keys and TLS configuration into `configHolder` — it does NOT reload zones, zone transfer ACLs, TSIG keys, RRL config, or any DNS server parameters. The `// D-09` reference and "Full config reload" description set incorrect expectations.

**Fix:** Update the comment to accurately describe the scope of the reload:

```go
// SIGHUP: reload admin gRPC config (API keys + TLS). DNS server config
// (zones, TSIG keys, ACLs) requires a restart. See D-11 (atomic config swap).
```

---

_Reviewed: 2026-05-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
