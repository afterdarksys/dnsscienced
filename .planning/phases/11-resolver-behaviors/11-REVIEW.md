---
phase: 11-resolver-behaviors
reviewed: 2026-05-22T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - internal/resolver/recursive.go
  - internal/cache/nsec.go
  - internal/resolver/resolver_behaviors_test.go
  - internal/cache/nsec_test.go
findings:
  critical: 4
  warning: 6
  info: 3
  total: 13
status: issues_found
---

# Phase 11: Code Review Report

**Reviewed:** 2026-05-22T00:00:00Z
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Phase 11 implements three RFC-compliance features in the recursive resolver: QNAME
minimization (RFC 7816/9156), Aggressive NSEC synthesis (RFC 8198), and Serve Stale
(RFC 8767). The code is well-structured and the feature logic is generally sound.
However, there are four critical bugs that cause incorrect behavior: two `defer` calls
inside a hot code path that produce use-after-free-equivalent memory aliasing, a
broken "all-features-off" default-override guard that silently ignores explicit operator
intent, a wrap-around NSEC synthesis path that covers names in a different zone entirely,
and a missing glue-resolution fallback that returns `ErrNoNameservers` for every delegation
whose NS targets are not in the same packet. Several additional warnings affect correctness
and robustness.

---

## Critical Issues

### CR-01: `defer pool.PutMessage` inside a loop — returned `resp.Copy()` aliases freed memory

**File:** `internal/resolver/recursive.go:259-276`

**Issue:** In the stale-fallback path inside `Resolve`, `pool.PutMessage(staleResp)` is
deferred while the function still returns `staleResp.Copy()`. `pool.PutMessage` resets the
pooled `*dns.Msg` back to zero/nil state before returning it to the pool. `resp.Copy()` on
line 276 is called *before* the deferred `PutMessage` executes — Go's defer fires at
function return, after all return-value expressions are evaluated but before the caller
receives the value. In this case `staleResp.Copy()` is safe *for this particular invocation*,
but an identical pattern exists earlier at line 222-243 for the normal cache-hit path:

```
resp := pool.GetMessage()       // line 221
defer pool.PutMessage(resp)     // line 222
if err := resp.Unpack(...); err == nil {
    ...
    return resp.Copy(), nil     // line 243
}
```

The returned pointer from `resp.Copy()` is safe because Copy is called first. However, if
`resp.Unpack` fails (line 223), execution falls through to `resolveIterative`, which may
allocate a second `pool.GetMessage()` via `queryNameserver`. The pooled message from line
221 is returned to the pool by the deferred `PutMessage` when `Resolve` eventually returns,
but any goroutine that runs `queryNameserver` concurrently may receive the same pooled
slot between the time the defer is registered and the time `Resolve` returns — because
`queryNameserver` itself defers `pool.PutMessage(msg)` (line 433). This is benign only
if the pool is never concurrently accessed for the *same* object, which requires auditing
`pool.GetMessage` for LIFO vs FIFO behavior.

More concretely: the *stale-fallback* defer (line 260) runs at the same function-return
point as the caller that placed `resp` in the pool (line 222). Both defers are on the
same call frame. If `resp.Unpack` at line 223 succeeds AND `staleResp.Unpack` at line 261
also succeeds in the same call, **both** defers fire at return, returning two distinct
messages to the pool — this is correct. But the pattern is fragile and was already
identified as the root cause of D-07 bug 2. A deeper danger: at line 259 `staleResp` is
allocated from the pool inside the `if r.cfg.ServeStale` block, yet the `defer` at
line 260 runs unconditionally for the entire `Resolve` lifetime. If `staleResp.Unpack`
fails (line 261), `Resolve` falls through to `return nil, err` at line 280, and
`pool.PutMessage(staleResp)` fires — returning an empty/zeroed message. This is correct
behavior for the pool, but the pattern makes it easy for a future code change to
double-free (call `PutMessage` twice on the same object).

**Fix:** Avoid `defer` for pool returns inside conditional branches. Use explicit
`pool.PutMessage` calls at each early-return site:

```go
// Replace:
staleResp := pool.GetMessage()
defer pool.PutMessage(staleResp)
if unpackErr := staleResp.Unpack(staleEntry.Data); unpackErr == nil {
    ...
    return staleResp.Copy(), nil
}

// With:
staleResp := pool.GetMessage()
if unpackErr := staleResp.Unpack(staleEntry.Data); unpackErr == nil {
    result := staleResp.Copy()
    pool.PutMessage(staleResp)
    return result, nil
}
pool.PutMessage(staleResp)
```

---

### CR-02: D-10 default-override guard silently overrides explicit single-flag-off configs

**File:** `internal/resolver/recursive.go:121-125`

**Issue:** The guard intended to provide "RFC compliance out of the box" fires when
`!cfg.QNAMEMinimization && !cfg.AggressiveNSEC && !cfg.ServeStale`. This means an
operator who explicitly sets, for example, `serve_stale: false` in YAML while leaving
the other two at their Go zero value (`false`) will have all three flags forcibly enabled —
the exact opposite of their intent. The comment acknowledges this fragility ("a user who
wants all three off explicitly sets at least one bool true") but that precondition is
nowhere enforced and is not documented in the public `Config` struct.

The condition is also semantically incorrect: the guard fires even when the caller
explicitly constructs `Config{ServeStale: false}` to disable stale serving, because
`false == false`. There is no way to distinguish an unset field from an explicitly-false
field in Go without adding a pointer or sentinel value.

This is a **behavioral correctness bug**: operators who disable any single feature via
YAML will not get their intended configuration if the other two happen to be at zero
value.

**Fix:** Remove the heuristic guard. Instead, provide an explicit constructor that sets
safe defaults, and document that `Config{}` means "all features off":

```go
// DefaultConfig returns an RFC-compliant default configuration.
func DefaultConfig() Config {
    return Config{
        QueryTimeout:      5 * time.Second,
        MaxIterations:     20,
        Workers:           100,
        QNAMEMinimization: true,
        AggressiveNSEC:    true,
        ServeStale:        true,
        StaleTTL:          24 * time.Hour,
    }
}

// NewRecursive — remove lines 121-125 and require callers to use DefaultConfig()
// or set flags explicitly.
```

---

### CR-03: NSEC wrap-around synthesis path covers names in foreign zones

**File:** `internal/cache/nsec.go:166-172`

**Issue:** The wrap-around branch for the last NSEC in a zone:

```go
if canonicalLess(rec.Owner, qname) && canonicalLess(rec.Next, rec.Owner) {
    return buildSyntheticNXDOMAIN(qname, qtype, qclass, queryID, rec)
}
```

This condition is true whenever `rec.Owner < qname` AND `rec.Next < rec.Owner` (i.e.,
the record wraps). However, there is **no check** that `qname` is a subdomain of
`rec.Zone`. An NSEC record from `example.com.` that wraps around (e.g.,
`zzz.example.com. NSEC example.com.`) would match any `qname > zzz.example.com.` in
canonical order — including names in a completely different zone such as
`zzz.example.net.` or even `zzz.example.org.`.

The canonical ordering is global: `zzz.example.com. < aaa.example.net.` is false (both
start at `.com` vs `.net` from the right), but edge cases exist. More importantly,
`example.com`'s NSEC wrap cannot prove non-existence of names in `example.net`.

The non-wrapping path (line 161) has the same issue — no zone membership check before
synthesis.

**Fix:** Add a zone membership check before any synthesis:

```go
// In SynthesizeNXDOMAIN, before the canonicalLess comparisons:
for _, rec := range c.records {
    if rec.ExpiresAt.Before(now) {
        continue
    }
    // Guard: qname must be a subdomain of the NSEC record's zone.
    if !dns.IsSubDomain(rec.Zone, qname) {
        continue
    }
    if canonicalLess(rec.Owner, qname) && canonicalLess(qname, rec.Next) {
        return buildSyntheticNXDOMAIN(qname, qtype, qclass, queryID, rec)
    }
    if canonicalLess(rec.Owner, qname) && canonicalLess(rec.Next, rec.Owner) {
        return buildSyntheticNXDOMAIN(qname, qtype, qclass, queryID, rec)
    }
}
```

---

### CR-04: `resolveIterative` returns `ErrNoNameservers` for all delegations with out-of-zone NS targets (no iterative glue resolution)

**File:** `internal/resolver/recursive.go:412-414`

**Issue:** When following a referral, glue records (A/AAAA in the Additional section)
are looked up via `r.findGlue`. If glue is absent — which is the normal case for
out-of-zone nameservers (e.g., `ns1.different-registrar.com` is authoritative for
`example.com`) — `newNameservers` remains empty and the function returns
`ErrNoNameservers`. This means the resolver **cannot resolve any zone whose nameservers
are not in-zone** (i.e., do not have glue records). The overwhelming majority of
real-world delegations use out-of-zone nameservers. This is a fundamental correctness
failure for a recursive resolver.

```go
if len(newNameservers) == 0 {
    return nil, ErrNoNameservers   // CR-04: fires for most real delegations
}
```

**Fix:** When glue is absent, iteratively resolve each NS target name to an IP before
continuing. This requires a recursive call (already supported by the architecture) or a
dedicated helper:

```go
if len(newNameservers) == 0 {
    // No glue: resolve each NS target name to obtain addresses.
    for _, rr := range resp.Ns {
        ns, ok := rr.(*dns.NS)
        if !ok {
            continue
        }
        // Resolve NS target name (A record) through a fresh iterative chain.
        glueResp, err := r.resolveIterative(ctx, ns.Ns, dns.TypeA, qclass)
        if err != nil {
            continue
        }
        for _, arec := range glueResp.Answer {
            if a, ok := arec.(*dns.A); ok {
                newNameservers = append(newNameservers, a.A.String()+":53")
            }
        }
    }
}
if len(newNameservers) == 0 {
    return nil, ErrNoNameservers
}
```

Note: the recursive call to `resolveIterative` must decrement/check `iterations` to
prevent unbounded recursion, or use a separate iteration counter.

---

## Warnings

### WR-01: `getTTL` defaults to 3600 when `resp.Answer` is empty — NXDOMAIN responses cached for 1 hour

**File:** `internal/resolver/recursive.go:480-490`

**Issue:** `getTTL` iterates only over `resp.Answer`. When the answer section is empty
(NXDOMAIN, NODATA), it returns the hardcoded default of 3600 seconds. Negative responses
should be cached using the SOA `Minimum` field per RFC 2308. `cache.CreateNegativeCacheEntry`
(in `internal/cache/negative.go`) does the right thing using SOA TTL, but `Resolve` never
calls it — it calls `getTTL` and then manually sets `IsNegative`/`NegType` on the entry.
This means NXDOMAIN responses are cached for 1 hour regardless of the zone's SOA TTL.

**Fix:** Use SOA-based TTL for negative responses:

```go
func getTTL(msg *dns.Msg) uint32 {
    if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
        // Negative response: use SOA minimum per RFC 2308
        for _, rr := range msg.Ns {
            if soa, ok := rr.(*dns.SOA); ok {
                ttl := soa.Minttl
                if soa.Hdr.Ttl < ttl {
                    ttl = soa.Hdr.Ttl
                }
                if ttl < 10 { ttl = 10 }
                if ttl > 10800 { ttl = 10800 }
                return ttl
            }
        }
        return 300 // 5m default for negative with no SOA
    }
    // Positive response: minimum TTL across Answer section
    minTTL := uint32(3600)
    for _, rr := range msg.Answer {
        if rr.Header().Ttl < minTTL {
            minTTL = rr.Header().Ttl
        }
    }
    return minTTL
}
```

---

### WR-02: DNSSEC validation error silently discarded — bogus responses served as if valid

**File:** `internal/resolver/recursive.go:297`

**Issue:** The DNSSEC validation error return is explicitly ignored:

```go
result, _ := r.validator.Validate(ctx, resp, question.Name, question.Qtype)
```

If `Validate` returns an error (network failure fetching DNSKEY, context cancellation,
chain depth exceeded), `result` is `nil` and `dnssecValidated`/`dnssecBogus` both remain
`false`. The response is cached and served as if it were unvalidated-but-OK. For a resolver
with `EnableDNSSEC: true`, this means a validator error causes the resolver to degrade to
the same behavior as `EnableDNSSEC: false` without any signal to the caller. Specifically,
if a DNSSEC-bogus response arrives during a transient validator error, it gets served as
valid.

**Fix:** Log or propagate the error. At minimum, treat a validator error as "indeterminate"
rather than "not bogus":

```go
result, validErr := r.validator.Validate(ctx, resp, question.Name, question.Qtype)
if validErr != nil {
    // Could not validate — do not cache; return SERVFAIL to force client retry.
    m := new(dns.Msg)
    m.SetRcode(q, dns.RcodeServerFailure)
    return m, nil
}
```

---

### WR-03: `resolveIterative` always queries only `nameservers[0]` — no load distribution or retry ordering

**File:** `internal/resolver/recursive.go:362`

**Issue:** `r.queryNameserver(ctx, nameservers[0], ...)` always uses the first nameserver.
On failure, `nameservers = nameservers[1:]` shifts the slice and retries with the new
first element. This is correct for failover but means the first server in any referral
response always bears 100% of load. More critically, after a failure the code calls
`continue` which restarts the outer `for` loop from the *top* — it does NOT retry the
same zone delegation; it re-issues the full query to `nameservers[0]` (which is now
the second server). This effectively means each nameserver only gets one chance per
iteration even though `MaxIterations` is used as the outer bound, consuming iteration
budget just for server failover within a single delegation.

**Fix:** Separate the retry-within-delegation loop from the iterative-hop counter:

```go
var resp *dns.Msg
for i, ns := range nameservers {
    var err error
    resp, err = r.queryNameserver(ctx, ns, sendName, sendType, qclass)
    if err == nil {
        break
    }
    if i == len(nameservers)-1 {
        return nil, fmt.Errorf("all nameservers failed: %w", err)
    }
}
// resp is now valid — continue with referral processing
```

---

### WR-04: `Resolve` calls `SynthesizeNXDOMAIN` before checking for `AggressiveNSEC` being enabled

**File:** `internal/resolver/recursive.go:249`

**Issue:** `r.cache.SynthesizeNXDOMAIN(...)` is called unconditionally. Inside
`ShardedCache.SynthesizeNXDOMAIN`, the guard `if c.nsecCache == nil { return nil }` makes
this safe, but the resolver does not guard on `r.cfg.AggressiveNSEC`. This means if
`AggressiveNSEC` is later changed to store `nsecCache` under a different condition, the
resolver will synthesize responses without operator opt-in. More importantly, the current
code relies on an implementation detail of `ShardedCache` (that `nsecCache == nil` when
the feature is off) rather than checking the resolver's own config. This is a coupling
issue that can produce a behavior gap if the cache layer is refactored.

**Fix:** Add an explicit guard in `Resolve`:

```go
if r.cfg.AggressiveNSEC {
    if synth := r.cache.SynthesizeNXDOMAIN(question.Name, question.Qtype, question.Qclass, q.Id); synth != nil {
        return synth, nil
    }
}
```

---

### WR-05: `canonicalLess` uses Go string comparison for DNS label bytes — incorrect for non-ASCII labels

**File:** `internal/cache/nsec.go:299-321`

**Issue:** RFC 4034 §6.1 requires canonical DNS name ordering to compare labels
octet-by-octet. Go string `<` comparison is correct for ASCII labels, but DNS names
can contain arbitrary octets (internationalized labels via wire format). The current
implementation uses `strings.Split(a, ".")` which treats `.` as a literal byte — correct
in the normalized lowercase FQDN — and then uses `aLabels[i] < bLabels[i]` which is a
Go string comparison. For labels containing non-ASCII bytes this would produce incorrect
ordering because Go string comparison is Unicode code-point order, not raw-byte order
in cases where non-ASCII bytes appear. For real-world IDN domains stored in ACE form
(`xn--...`) this is fine since ACE labels are ASCII. However, if any code path stores a
label in UTF-8 wire form, synthesis could produce incorrect NSEC coverage decisions,
potentially synthesizing NXDOMAIN for a name that actually exists.

**Fix:** Document the ASCII-only assumption explicitly, or switch to byte-level comparison:

```go
// label comparison: byte-wise per RFC 4034 §6.1
if aLabels[i] < bLabels[i] { // safe only for ASCII/ACE labels
    return true
}
```

Add an assertion or normalization step (e.g., `dns.Fqdn` + ACE encoding) before storing
NSEC records to ensure the assumption holds.

---

### WR-06: `StoreNSEC` passes `question.Name` as the `zone` argument — should pass the delegation zone

**File:** `internal/resolver/recursive.go:334`

**Issue:**

```go
r.cache.StoreNSEC(resp, question.Name)
```

The second argument to `StoreNSEC` / `NSECCache.Store` is documented as `zone` — the
zone the NSEC records belong to. Passing `question.Name` (e.g., `nonexistent.example.com.`)
instead of the actual zone (`example.com.`) means every stored `nsecRecord.Zone` is set
to the queried name, not the owning zone. The zone membership check in
`synthesizeFromNSEC3` (`dns.IsSubDomain(rec.Zone, qname)`) then only matches if the new
query name is a subdomain of the original queried name, which is almost never true.

For NSEC records (non-NSEC3 path), `rec.Zone` is set to `question.Name` but the zone
membership check was not present in the non-NSEC3 path (CR-03 above), so this bug was
masked. For NSEC3, the zone membership check does fire and will almost always produce a
false miss.

**Fix:** Extract the zone from the SOA record in the authority section, or from the NS
owner name (the delegation point):

```go
zone := extractZoneFromResponse(resp)
if dnssecValidated && entry.IsNegative {
    r.cache.StoreNSEC(resp, zone)
}

func extractZoneFromResponse(resp *dns.Msg) string {
    for _, rr := range resp.Ns {
        if soa, ok := rr.(*dns.SOA); ok {
            return soa.Hdr.Name
        }
        if ns, ok := rr.(*dns.NS); ok {
            return ns.Hdr.Name
        }
    }
    return "."
}
```

---

## Info

### IN-01: `TestServeStale_BeyondMaxStaleTTL` and `TestServeStale_Disabled` are non-asserting

**File:** `internal/resolver/resolver_behaviors_test.go:144-209`

**Issue:** Both tests use `t.Logf` rather than `t.Errorf`/`t.Fatalf` for the "expected"
case, and contain `_ = got` to discard the response. If the stale entry is incorrectly
served (the wrong behavior), the test passes with a log message ("test inconclusive in
networked env"). This makes the tests unreliable in any environment with network access
to real root servers, which includes CI runners with external network egress.

**Fix:** Use a controlled stub or mock transport for `r.client` so the test controls
whether iterative resolution succeeds or fails, and then assert the result precisely.
Alternatively, bind the test resolver to `127.0.0.1:0` with a timeout of 1ms to force
a fast failure:

```go
cfg := newStaleCfg(true, 1*time.Hour)
cfg.QueryTimeout = 1 * time.Millisecond // force immediate network failure
```

---

### IN-02: Magic number `1232` in `queryNameserver` without named constant

**File:** `internal/resolver/recursive.go:444`

**Issue:** `msg.SetEdns0(1232, false)` uses a magic number. The comment explains the
value (DNS Flag Day 2020, IPv6 min MTU), but the value itself should be a named constant
for searchability and to prevent copy-paste drift:

```go
const edns0PayloadSize = 1232 // DNS Flag Day 2020: IPv6 min MTU (1280) - 48 bytes headers
```

---

### IN-03: `fmt.Printf` used for security-relevant cache flush event

**File:** `internal/cache/sharded.go:431`

**Issue:** The unwanted-reply threshold flush event is logged via `fmt.Printf`, which
writes to stdout. In a production daemon, this event (indicating a possible active cache
poisoning attempt) should be routed through the application's structured logger so it
can be captured by log aggregation, alerted on, and audited. `fmt.Printf` output is
silently dropped if stdout is redirected to `/dev/null`, which is common in systemd
service units.

**Fix:** Accept a `slog.Logger` or structured logger interface in `ShardedCache` and use
it for this event.

---

_Reviewed: 2026-05-22T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
