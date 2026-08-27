# Phase 11: Resolver Behaviors - Research

**Researched:** 2026-05-22
**Domain:** DNS Recursive Resolver — QNAME Minimization, Aggressive NSEC/NSEC3, Serve-Stale
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Target is `internal/resolver/recursive.go` (`resolver.Recursive`) only. `engine.Resolver` is a stub forwarder — do not change its QNAME minimization behavior.
- **D-02:** Minimization happens per-delegation inside `resolveIterative()`: rewrite the query name to reveal one additional label beyond the current zone level at each hop. Reuse or inline the logic from `engine/security.go:ApplyQNAMEMinimization()`.
- **D-03:** RFC 9156 compliance — use `qtype=A` for intermediate hops (not the original qtype). Original qtype is only sent at the final hop to the authoritative nameserver. Planner must determine how to detect "final hop" (answer received, not a referral).
- **D-04:** NSEC3 is in scope for Phase 11. Both NSEC and NSEC3 records must be synthesized.
- **D-05:** Synthesis is DNSSEC-validation-gated — only `StoreNSEC` when `dnssecValidated=true`. Synthesizing from unvalidated NSEC/NSEC3 is a spoofing vector (RFC 8198 §2.1). This gate stays.
- **D-06:** NSEC3 synthesis requires: (a) storing NSEC3 records with zone salt + iteration count, (b) hashing the candidate qname using the zone's algorithm/salt/iterations before range comparison.
- **D-07:** Fix both bugs: (1) Remove `!entry.IsExpired()` guard at line 171 in `resolver.Resolve()` so the cache's own stale logic is reached. (2) Add upstream-failure fallback: when `resolveIterative()` returns an error, do a stale-permissive cache lookup before returning SERVFAIL.
- **D-08:** Stale responses are served with TTL=0 (RFC 8767 §5 SHOULD). Rewrite TTL on all RRs in the stale response to 0 before sending to client.
- **D-09:** New `resolver:` block in `config.yaml` parallel to existing `cache:` and `dnssec:` blocks.
- **D-10:** All three features ON by default.
- **D-11:** `stale_max_ttl` defaults to 24h; wire into the existing `cache.Config.MaxStaleTTL` field (no duplication).

### Claude's Discretion

- Whether NSEC3 synthesis lives in `internal/cache/nsec.go` (extending `NSECCache`) or a new `nsec3.go` file
- How "final hop" detection works for RFC 9156 qtype rewriting
- Whether `resolveIterative()` takes a `qname_minimization bool` param or reads from `r.cfg`
- Test structure — whether NSEC3 tests require mocked DNSSEC validation or can use pre-built validated response fixtures

### Deferred Ideas (OUT OF SCOPE)

- NSEC3 opt-out zones (RFC 5155 §6)
- Prefetch integration for stale-while-revalidate pattern
- `engine.Resolver` QNAME minimization correctness
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RESOLVE-01 | Recursive resolver sends minimized QNAME in outgoing queries (RFC 7816 / RFC 9156) — only the necessary labels sent to each nameserver level | `ApplyQNAMEMinimization()` exists in engine/security.go; per-delegation wiring inside `resolveIterative()` documented with exact state to track |
| RESOLVE-02 | Resolver synthesizes NXDOMAIN / NOERROR responses from cached NSEC/NSEC3 records without upstream queries (RFC 8198 aggressive caching) | `NSECCache` + `SynthesizeNXDOMAIN()` already wired for NSEC; NSEC3 extension via `dns.NSEC3.Cover()` from miekg/dns v1.1.72 documented below |
| RESOLVE-03 | Resolver serves stale cached records with extended TTL (up to configurable stale-max-ttl) when upstream nameservers are unreachable (RFC 8767 proper serve-stale) | Two exact bug locations identified; `cache.ShardedCache.Get()` already implements stale logic correctly at lines 364-393 of sharded.go |
</phase_requirements>

---

## Summary

Phase 11 makes three targeted fixes and additions to `internal/resolver/recursive.go` and `internal/cache/nsec.go`. None of the three features requires new packages or major architectural changes — all the scaffolding (NSEC cache, stale TTL, QNAME minimization logic) already exists and is partially wired.

**QNAME Minimization** is the largest behavioral change: `resolveIterative()` currently sends the full QNAME to every nameserver. The fix adds a `currentZone` string tracked across iterations, starting at `"."` (root), updated each time a referral reveals the delegation zone. Each hop sends `ApplyQNAMEMinimization(qname, currentZone)` as the QNAME and `qtype=A` unless the minimized name already equals the full QNAME (final hop). No import cycle risk: `engine` does not import `resolver`, and `resolver` does not import `engine` — so adding `import engine` to `recursive.go` is safe.

**Aggressive NSEC3** extends `NSECCache` to also accept and synthesize from `*dns.NSEC3` records. The miekg/dns v1.1.72 library provides `(*dns.NSEC3).Cover(name)`, `(*dns.NSEC3).Match(name)`, and `dns.HashName(label, dns.SHA1, iter, salt)`. No custom hashing or range-comparison code is needed.

**Serve-Stale** has two exact bug locations. The `!entry.IsExpired()` guard at line 171 of `recursive.go` prevents `ShardedCache.Get()` from ever returning a stale entry. The second bug is the missing upstream-failure fallback at line 198 — when `resolveIterative()` errors, the resolver should attempt a stale cache lookup before propagating the error as SERVFAIL.

**Primary recommendation:** Fix bugs in `Resolve()` first (serve-stale — smallest blast radius, hermetic tests), then extend `NSECCache` for NSEC3, then add QNAME minimization to `resolveIterative()`. Each can be tested hermetically without network access.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| QNAME minimization | Resolver (`resolver.Recursive`) | — | Per-delegation query rewriting is iterative resolver state; stub forwarder is out of scope |
| Aggressive NSEC synthesis | Cache (`NSECCache`) | Resolver (`Resolve()`) | NSEC records are stored and synthesized in cache layer; resolver drives the call |
| NSEC3 synthesis | Cache (`NSECCache`) | Resolver (`Resolve()`) | Extends existing NSEC synthesis path; same ownership |
| Serve-stale TTL logic | Cache (`ShardedCache.Get()`) | Resolver (`Resolve()`) | Cache already implements `IsStale()`; resolver guard bug prevents reaching it |
| Serve-stale upstream-failure fallback | Resolver (`Resolve()`) | Cache (`ShardedCache.Get()`) | New error-path logic added in resolver; cache provides the stale entry |
| Feature flag config | Config (`resolver.Config`) | Server (`server.Config.RecursiveConfig`) | Flags are part of resolver.Config; wired through server.Config.RecursiveConfig and config.Config.Resolver |

---

## Standard Stack

### Core — Already In Use, No New Dependencies Required

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/miekg/dns` | v1.1.72 | DNS wire format, NSEC3 hashing, Cover/Match methods | Project-wide standard; `dns.NSEC3.Cover()`, `dns.HashName()` confirmed in this version |

[VERIFIED: go.mod + `go list -m github.com/miekg/dns` → v1.1.72; `nsecx.go` and `types.go` read directly]

### Key miekg/dns Primitives for NSEC3

| Function / Method | Signature | Use |
|-------------------|-----------|-----|
| `dns.HashName` | `func HashName(label string, ha uint8, iter uint16, salt string) string` | Hash a candidate QNAME using RFC 5155 SHA-1 before range comparison |
| `(*dns.NSEC3).Cover` | `func (rr *NSEC3) Cover(name string) bool` | Checks if `name` falls within the NSEC3 hashed interval — handles zone-end wrap-around |
| `(*dns.NSEC3).Match` | `func (rr *NSEC3) Match(name string) bool` | Checks if `name` exactly matches the NSEC3 owner (NODATA synthesis) |
| `dns.SHA1` | `uint8 = 1` | Hash algorithm constant for RFC 5155; only SHA-1 is standardized and supported |

`dns.NSEC3.Cover()` internally calls `HashName()` and handles the zone-end wrap case (ownerHash > nextHash). Use `Cover()` rather than manual base32 string comparison. [VERIFIED: miekg/dns@v1.1.72/nsecx.go lines 44-80]

**No new packages to install.**

---

## Architecture Patterns

### System Architecture Diagram

```
Client query
    |
    v
resolver.Resolve()
    |-- 1. cache.Get(key)                         [BUGGY: !IsExpired() guard at line 171]
    |       |-- serveStale=true + within window --> return stale entry (sharded.go:364-393)
    |       `-- BUG: resolver pre-checks IsExpired, bypasses cache's own stale path
    |
    |-- 2. SynthesizeNXDOMAIN()
    |       |-- NSEC:  canonicalLess range check  [EXISTS]
    |       `-- NSEC3: Cover()/Match() via nsec3records [MISSING -- Phase 11 adds]
    |
    |-- 3. resolveIterative()
    |       |-- QNAME min: sends full QNAME       [BUGGY -- Phase 11 adds currentZone tracking]
    |       |       currentZone = "." initially
    |       |       sendName = ApplyQNAMEMinimization(qname, currentZone)
    |       |       sendType = TypeA if sendName != qname (RFC 9156 intermediate hop)
    |       |       on referral: currentZone = resp.Ns[0].Header().Name
    |       `-- upstream failure -> return error   [BUGGY -- Phase 11 adds stale fallback]
    |
    |-- 4. Rebinding check
    |-- 5. DNSSEC validation
    `-- 6. Cache + StoreNSEC (dnssecValidated gate)
            |-- NSEC:  NSECCache.Store() -> nsecRecord  [EXISTS]
            `-- NSEC3: NSECCache.Store() -> nsec3Record [MISSING -- Phase 11 adds]
```

### Recommended Project Structure

No new packages required. NSEC3 storage can extend `nsec.go` or live in a new `nsec3.go` — both are within discretion scope.

```
internal/
  resolver/
    recursive.go          # Primary change surface (all 3 features wired here)
    recursive_test.go     # Extend with hermetic tests for all 3 features
  cache/
    nsec.go               # Extend for NSEC3 storage + synthesis (or add nsec3.go)
    nsec_test.go          # New: direct tests for NSECCache NSEC and NSEC3 paths
  config/
    config.go             # resolver.Config already maps to top-level "resolver:" YAML key
```

### Pattern 1: QNAME Minimization State in resolveIterative()

**What:** Track `currentZone` across iterations. Start at root `"."`. Update on each referral using the NS authority section owner name (the zone being delegated).

```go
// Source: internal/engine/security.go:100 (ApplyQNAMEMinimization logic)
// Inside resolveIterative():
currentZone := "."
for iterations < r.cfg.MaxIterations {
    iterations++

    // Minimize query name for this hop (D-02, D-03)
    sendName := qname
    sendType := qtype
    if r.cfg.QNAMEMinimization {
        sendName = engine.ApplyQNAMEMinimization(qname, currentZone)
        // RFC 9156: use qtype=A at intermediate hops; full type only at final hop
        if sendName != qname {
            sendType = dns.TypeA
        }
    }

    resp, err := r.queryNameserver(ctx, nameservers[0], sendName, sendType, qclass)
    // ...

    // On referral: extract delegation zone from NS authority owner name (not NS target)
    if len(resp.Ns) > 0 {
        // resp.Ns[0].Header().Name is the zone being delegated (e.g., "example.com.")
        // resp.Ns[0].(*dns.NS).Ns is the nameserver target (e.g., "ns1.example.com.") -- NOT the zone
        currentZone = dns.Fqdn(strings.ToLower(resp.Ns[0].Header().Name))
        // ... extract newNameservers, continue
    }
}
```

**Final hop detection:** `sendName == qname`. `ApplyQNAMEMinimization()` returns the full name unchanged when `currentZone` already covers `qname` (i.e., when we are at the authoritative zone). [VERIFIED: internal/engine/security.go:100-127]

**Import:** `"github.com/afterdarksys/dnsscienced/internal/engine"` — no cycle risk. `engine` does not import `resolver`; `resolver` does not currently import `engine`. [VERIFIED: grep of both packages]

### Pattern 2: Serve-Stale Bug Fix — Remove !IsExpired() Guard

**Current buggy code (recursive.go line 171):**

```go
if entry, ok := r.cache.Get(cacheKey); ok && !entry.IsExpired() {
```

**Fixed code:**

```go
if entry, ok := r.cache.Get(cacheKey); ok {
```

`ShardedCache.Get()` at sharded.go lines 364-393 already returns `(nil, false)` when `serveStale=false` OR the entry is outside the `maxStaleTTL` window. The resolver must not second-guess the cache. [VERIFIED: internal/cache/sharded.go:351-394]

### Pattern 3: Serve-Stale Upstream-Failure Fallback

**Where:** After line 198 of recursive.go (`resp, err := r.resolveIterative(...)`), in the `err != nil` branch.

```go
resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
if err != nil {
    // Upstream failure: attempt stale cache lookup before SERVFAIL (RFC 8767)
    if r.cfg.ServeStale {
        if staleEntry, ok := r.cache.Get(cacheKey); ok {
            staleResp := pool.GetMessage()
            defer pool.PutMessage(staleResp)
            if unpackErr := staleResp.Unpack(staleEntry.Data); unpackErr == nil {
                staleResp.Id = q.Id
                staleResp.RecursionAvailable = true
                // RFC 8767 §5: set TTL=0 on all RRs in stale response
                for _, rr := range staleResp.Answer {
                    rr.Header().Ttl = 0
                }
                for _, rr := range staleResp.Ns {
                    rr.Header().Ttl = 0
                }
                for _, rr := range staleResp.Extra {
                    if rr.Header().Rrtype != dns.TypeOPT {
                        rr.Header().Ttl = 0
                    }
                }
                return staleResp.Copy(), nil
            }
        }
    }
    return nil, err
}
```

`r.cache.Get(cacheKey)` with `serveStale=true` and `maxStaleTTL=24h` already enforces the stale window — no additional `IsStale()` call needed at the resolver level. [VERIFIED: sharded.go Get()]

### Pattern 4: NSEC3 Storage Struct and Synthesis

**New struct (add to nsec.go or nsec3.go):**

```go
// nsec3Record is one validated NSEC3 record stored for aggressive synthesis.
type nsec3Record struct {
    // OwnerHash is the base32-encoded hashed owner name (uppercase, without zone suffix).
    // Extracted from the first label of the NSEC3 RR owner name.
    OwnerHash  string
    // NextHash is the base32-encoded hashed next owner name (uppercase).
    NextHash   string
    // Zone is the lowercase FQDN of the zone this NSEC3 covers.
    Zone       string
    // Hash algorithm: dns.SHA1 (1) is the only standardized value.
    Hash       uint8
    Iterations uint16
    Salt       string    // hex-encoded, as stored in *dns.NSEC3.Salt
    Flags      uint8
    TypeMap    []uint16
    ExpiresAt  time.Time
}
```

**Extraction in NSECCache.Store() (alongside existing NSEC loop):**

```go
// Also loop over NSEC3 records in the authority section
for _, rr := range msg.Ns {
    nsec3, ok := rr.(*dns.NSEC3)
    if !ok {
        continue
    }
    // NSEC3 owner: "<hash>.<zone>" — split at second label
    owner := strings.ToUpper(nsec3.Hdr.Name)
    labelIdx := dns.Split(owner)
    if len(labelIdx) < 2 {
        continue
    }
    ownerHash := owner[:labelIdx[1]-1]
    ownerZone := strings.ToLower(dns.Fqdn(owner[labelIdx[1]:]))

    rec := &nsec3Record{
        OwnerHash:  ownerHash,
        NextHash:   strings.ToUpper(nsec3.NextDomain),
        Zone:       ownerZone,
        Hash:       nsec3.Hash,
        Iterations: nsec3.Iterations,
        Salt:       nsec3.Salt,
        Flags:      nsec3.Flags,
        TypeMap:    nsec3.TypeBitMap,
        ExpiresAt:  now.Add(time.Duration(nsec3.Hdr.Ttl) * time.Second),
    }
    // Append or replace existing record for same ownerHash+zone
    c.nsec3records = append(c.nsec3records, rec)
}
```

**Synthesis using dns.NSEC3.Cover() (add to NSECCache):**

```go
// synthesizeFromNSEC3 attempts NSEC3-based synthesis. Returns nil if not possible.
// Source: miekg/dns@v1.1.72/nsecx.go (Cover method)
func (c *NSECCache) synthesizeFromNSEC3(qname string, qtype, qclass, queryID uint16) *dns.Msg {
    qname = strings.ToLower(dns.Fqdn(qname))
    now := time.Now()

    for _, rec := range c.nsec3records {
        if rec.ExpiresAt.Before(now) {
            continue
        }
        // Pre-filter by zone to avoid false Cover() results
        if !dns.IsSubDomain(rec.Zone, qname) {
            continue
        }
        // Reconstruct a minimal *dns.NSEC3 for the Cover() method
        n3 := &dns.NSEC3{
            Hdr:        dns.RR_Header{Name: rec.OwnerHash + "." + rec.Zone},
            Hash:       rec.Hash,
            Flags:      rec.Flags,
            Iterations: rec.Iterations,
            Salt:       rec.Salt,
            NextDomain: rec.NextHash,
            TypeBitMap: rec.TypeMap,
        }
        if n3.Cover(qname) {
            return buildSyntheticNXDOMAIN_NSEC3(qname, qtype, qclass, queryID, rec, n3)
        }
    }
    return nil
}
```

Call from `SynthesizeNXDOMAIN()` after the NSEC check returns nil:

```go
func (c *NSECCache) SynthesizeNXDOMAIN(...) *dns.Msg {
    // ... existing NSEC check ...
    // Fall through to NSEC3
    return c.synthesizeFromNSEC3(qname, qtype, qclass, queryID)
}
```

[VERIFIED: miekg/dns@v1.1.72/nsecx.go — Cover() and HashName() confirmed; dns.SHA1 constant confirmed at dnssec.go:86]

### Pattern 5: Feature Flags in resolver.Config

**Add to `resolver.Config` struct (internal/resolver/recursive.go:44):**

```go
// QNAME Minimization (RFC 7816 + RFC 9156): rewrite outgoing query names
// to reveal only one more label than the current zone at each iterative hop.
QNAMEMinimization bool `yaml:"qname_minimization"`

// AggressiveNSEC enables RFC 8198 synthesis from cached NSEC/NSEC3 records.
// Requires DNSSEC validation to be active (EnableDNSSEC: true).
AggressiveNSEC bool `yaml:"aggressive_nsec"`

// ServeStale enables RFC 8767 behavior: serve cached records with TTL=0
// when all upstream nameservers are unreachable.
ServeStale bool `yaml:"serve_stale"`

// StaleTTL is the maximum age past expiry that a stale record may be served.
// Defaults to 24h. Wired into CacheConfig.MaxStaleTTL (D-11: no duplication).
StaleTTL time.Duration `yaml:"stale_max_ttl"`
```

**Wiring in NewRecursive() before cache construction:**

```go
// Wire resolver feature flags into cache config (D-11: avoid duplication)
if cfg.ServeStale {
    cfg.CacheConfig.ServeStale = true
    if cfg.StaleTTL > 0 {
        cfg.CacheConfig.MaxStaleTTL = cfg.StaleTTL
    } else {
        cfg.CacheConfig.MaxStaleTTL = 24 * time.Hour
    }
}
if cfg.AggressiveNSEC {
    cfg.CacheConfig.AggressiveNSEC = true
}
```

**Config YAML placement:** The top-level `config.Config.Resolver` field (yaml: `"resolver"`) maps directly to `resolver.Config`. The new flags appear in `config.yaml` as:

```yaml
resolver:
  qname_minimization: true
  aggressive_nsec: true
  serve_stale: true
  stale_max_ttl: 24h
```

[VERIFIED: internal/config/config.go:18 — `Resolver resolver.Config yaml:"resolver"`]

### Anti-Patterns to Avoid

- **Hand-rolling NSEC3 hash range comparison:** Use `dns.NSEC3.Cover()` — it handles the zone-end wrap-around (circular hashed namespace) correctly. Manual ownerHash/nextHash base32 string comparison misses the wrap case.
- **Guarding `cache.Get()` output with `!entry.IsExpired()`:** The cache's own stale logic must be trusted. Adding a second expiry check in the resolver defeats the serve-stale feature.
- **Synthesizing from unvalidated NSEC/NSEC3:** The `dnssecValidated` gate in the `StoreNSEC()` call at line 254 of recursive.go must remain. Unsigned NSEC records can be injected to cause NXDOMAIN for legitimate names (RFC 8198 §2.1).
- **Using NS target name instead of NS owner name for currentZone:** `resp.Ns[0].(*dns.NS).Ns` is the nameserver's hostname; `resp.Ns[0].Header().Name` is the zone being delegated. QNAME minimization requires the zone owner name.
- **Sending original qtype at intermediate hops:** RFC 9156 requires `qtype=A` at hops where the query name is still minimized. Sending AAAA or MX to intermediate resolvers leaks information and may cause unexpected NODATA responses.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| NSEC3 name hashing (RFC 5155) | Custom SHA-1 iteration loop | `dns.HashName(label, dns.SHA1, iter, salt)` | Correctly packs name to wire format before hashing; handles iterations |
| NSEC3 interval coverage | Manual base32 string comparison | `(*dns.NSEC3).Cover(name)` | Handles zone-end wrap (ownerHash > nextHash) correctly |
| NSEC3 owner match | Manual hash equality | `(*dns.NSEC3).Match(name)` | For NODATA synthesis — checks exact name match |
| QNAME label manipulation | Custom label splitter | `dns.SplitDomainName()`, `dns.IsSubDomain()`, `ApplyQNAMEMinimization()` | All already in use; reuse exactly |

**Key insight:** miekg/dns v1.1.72 provides complete NSEC3 synthesis primitives in `nsecx.go`. The Phase 11 work is wiring and storage, not algorithm implementation.

---

## Existing Code — Exact Bug Locations

### Bug 1: Stale Guard in Resolve() — line 171 of recursive.go

```go
// CURRENT (line 171) — BUGGY: !entry.IsExpired() skips stale path
if entry, ok := r.cache.Get(cacheKey); ok && !entry.IsExpired() {

// FIX — remove !entry.IsExpired():
if entry, ok := r.cache.Get(cacheKey); ok {
```

`cache.ShardedCache.Get()` returns `(nil, false)` when the entry is expired and `serveStale=false` — so removing `!entry.IsExpired()` does not change behavior for non-stale configurations. It only enables the stale path when the cache is configured for it.

### Bug 2: Missing Stale Fallback After resolveIterative() — line 198 of recursive.go

```go
// CURRENT — no stale fallback
resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
if err != nil {
    return nil, err   // <-- BUG: should attempt stale cache before SERVFAIL
}
```

The fix inserts the stale cache lookup pattern (Pattern 3 above) in the `err != nil` branch.

### Pre-existing Failures (do not fix in Phase 11)

| Test | Location | Failure |
|------|----------|---------|
| `TestFindGlue` | internal/resolver/recursive_test.go:239 | `findGlue()` returns `"[2001:db8::1]"` (bracketed for net.Dial); test asserts `"2001:db8::1"`. Test assertion bug — code is correct. |
| `TestResolveIterative_MaxIterations` | internal/resolver/recursive_test.go:368 | Makes real network connections; non-hermetic. |
| `TestResolver_Resolve` | internal/engine/resolver_test.go:14 | Makes real DNS query to example.com; non-hermetic. |

---

## Common Pitfalls

### Pitfall 1: ServeStale Config Not Wired Into Cache

**What goes wrong:** Resolver config has `ServeStale=true` but `CacheConfig.ServeStale=false` — stale entries are never returned from `cache.Get()`.
**Why it happens:** The two config structs are separate; `NewRecursive()` must explicitly copy the flag before constructing the cache.
**How to avoid:** In `NewRecursive()`, set `cfg.CacheConfig.ServeStale = cfg.ServeStale` before calling `cache.NewShardedCache(cfg.CacheConfig)`.
**Warning signs:** Serve-stale test passes with cache pre-populated as stale but `resolveIterative()` mock returns error — if stale entry is not returned, `cfg.CacheConfig.ServeStale` is likely false.

### Pitfall 2: QNAME Minimization Returns NODATA for Intermediate Hops

**What goes wrong:** Intermediate nameserver returns NODATA (NOERROR + empty answer section) for `qtype=A` at a minimized name. Resolver interprets it as "no A record" and returns to the client.
**Why it happens:** `resolveIterative()` currently treats non-empty `resp.Answer` as a final answer and `resp.Rcode == NXDOMAIN` as a definitive response. Neither condition triggers for NODATA.
**How to avoid:** When `sendName != qname` (minimized hop) and `len(resp.Answer) == 0` and `resp.Rcode == dns.RcodeSuccess` — this is a NODATA at an intermediate hop, not a final answer. Fall through: re-query with `qtype=TypeA` at the same zone level OR advance to the next label with `sendType = qtype` (original). RFC 9156 §4 says: try the original QTYPE at that nameserver before giving up.
**Warning signs:** `TestQNAMEMin_NODATA_intermediate` fails with premature NODATA return.

### Pitfall 3: NSEC3 Cover() Returns False for Out-of-Zone Names

**What goes wrong:** `Cover()` returns false for names that are not subdomains of the NSEC3's zone, even if the hash happens to fall in range.
**Why it happens:** Cover() calls `dns.IsSubDomain(ownerZone, name)` internally — correct behavior.
**How to avoid:** Pre-filter `c.nsec3records` by zone before calling Cover(): `if !dns.IsSubDomain(rec.Zone, qname) { continue }`.
**Warning signs:** NSEC3 synthesis never fires even though the NSEC3 record's hashed range covers the query name.

### Pitfall 4: HashName Returns "" for Non-SHA1 Algorithms

**What goes wrong:** If a zone uses an NSEC3 hash algorithm other than SHA-1 (algorithm ID != 1), `dns.HashName()` returns `""` and `Cover()` returns false (no match on empty string).
**Why it happens:** miekg/dns only implements SHA-1 for NSEC3 (RFC 5155 §11 registers SHA-1 as algorithm 1; no other algorithm is standardized).
**How to avoid:** When storing NSEC3 records, skip records with `nsec3.Hash != dns.SHA1`. During synthesis, skip `nsec3Record` entries with `rec.Hash != dns.SHA1`.
**Warning signs:** NSEC3 records present in response but never stored; check `nsec3.Hash` value.

### Pitfall 5: Zone Name in currentZone Must Be FQDN

**What goes wrong:** `ApplyQNAMEMinimization(qname, currentZone)` relies on `dns.IsSubDomain(currentZone, qname)` — this requires both names to be FQDNs (trailing dot). If `currentZone` lacks the dot, minimization silently stops working.
**Why it happens:** NS authority record names from the wire may or may not have a trailing dot depending on the parser.
**How to avoid:** Always `currentZone = dns.Fqdn(strings.ToLower(resp.Ns[0].Header().Name))` — `dns.Fqdn()` adds the trailing dot if absent.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go testing (stdlib) + testify/assert v1.x |
| Config file | None — `go test ./...` |
| Quick run command | `go test ./internal/resolver/... ./internal/cache/... -count=1` |
| Full suite command | `go test ./... -count=1 2>&1 \| grep -v TestFindGlue \| grep -v TestResolver_Resolve` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RESOLVE-01 | QNAME minimized in outgoing queries per-delegation | unit | `go test ./internal/resolver/... -run TestQNAMEMinimization -count=1` | No — Wave 0 |
| RESOLVE-01 | RFC 9156: qtype=A at intermediate hops | unit | `go test ./internal/resolver/... -run TestQNAMEMin_RFC9156 -count=1` | No — Wave 0 |
| RESOLVE-02 | NSEC cached record synthesizes NXDOMAIN without upstream | unit | `go test ./internal/cache/... -run TestNSECCache -count=1` | No — Wave 0 |
| RESOLVE-02 | NSEC3 cached record synthesizes NXDOMAIN without upstream | unit | `go test ./internal/cache/... -run TestNSEC3Cache -count=1` | No — Wave 0 |
| RESOLVE-03 | Stale entry returned when expired but within StaleTTL | unit | `go test ./internal/resolver/... -run TestServeStale_Expired -count=1` | No — Wave 0 |
| RESOLVE-03 | Upstream failure returns stale entry with TTL=0 | unit | `go test ./internal/resolver/... -run TestServeStale_UpstreamFail -count=1` | No — Wave 0 |
| RESOLVE-03 | Records older than stale-max-ttl are NOT served stale | unit | `go test ./internal/resolver/... -run TestServeStale_Bounded -count=1` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./internal/resolver/... ./internal/cache/... -count=1`
- **Per wave merge:** `go test ./... -count=1`
- **Phase gate:** Full suite green (ignoring pre-existing failures) before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/resolver/resolver_behaviors_test.go` — covers RESOLVE-01 (QNAME min), RESOLVE-03 (serve-stale)
- [ ] `internal/cache/nsec_test.go` — covers RESOLVE-02 (NSEC + NSEC3 synthesis)
- [ ] No framework install needed — stdlib + testify already present

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | yes | NSEC/NSEC3 synthesis gated on `dnssecValidated=true`; NSEC3 hash algorithm != SHA1 is skipped |
| V6 Cryptography | yes | SHA-1 for NSEC3 (mandated by RFC 5155 — no alternative; never used for confidentiality) |
| V4 Access Control | no | Resolver does not serve externally; this is internal recursive resolution |
| V2 Authentication | no | No auth in resolver path |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| NSEC injection — synthesize NXDOMAIN for valid names | Tampering | Gate synthesis on `dnssecValidated=true` (D-05); never synthesize from unsigned records |
| Stale data poisoning — serve stale record after TTL reflects revocation | Tampering | Bounded stale window (`stale-max-ttl: 24h`); TTL=0 signals to client the response is stale |
| Wildcard NSEC overmatch — NSEC record proves nonexistence of a wildcard match | Spoofing | RFC 8198 §4: wildcard synthesis is more complex; Phase 11 should restrict synthesis to NXDOMAIN, not NOERROR/wildcard |
| NSEC3 opt-out confusion — opt-out flag means unsigned delegations can exist | Information Disclosure | Deferred per CONTEXT.md; synthesize only from non-opt-out NSEC3 (check Flags bit 0) |

---

## Environment Availability

Step 2.6: No external runtime dependencies beyond existing Go toolchain and miekg/dns.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `github.com/miekg/dns` | All three features | Yes | v1.1.72 | — |
| Go toolchain | Build | Yes | (project standard) | — |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `engine` package does not import `resolver` package | Import Cycle Risk | If cycle exists, `ApplyQNAMEMinimization` must be inlined rather than imported |
| A2 | `dns.Split()` is the correct function to split an NSEC3 owner name into hash label and zone | NSEC3 Storage | If wrong function, ownerHash extraction produces incorrect results; test will catch |

**Verification status:** A1 confirmed by grep (no `internal/resolver` import in engine/*.go and no `internal/engine` import in resolver/*.go). A2 — `dns.Split()` is the standard label-index function in miekg/dns, used identically inside `Cover()` itself. [VERIFIED: miekg/dns@v1.1.72/nsecx.go:47]

---

## Open Questions (RESOLVED)

1. **NODATA at intermediate QNAME minimization hops** — RESOLVED
   - What we know: RFC 9156 §4 says re-try with original qtype when intermediate NODATA received
   - Resolution: On NODATA at a minimized hop, set `sendName = qname` (disable minimization for remainder of resolution) rather than implementing the full RFC 9156 §4 retry loop — simpler and correct for the common case. Adopted in Plan 02 Task 1 Part B.

2. **NSEC3 records field in NSECCache — slice vs. map** — RESOLVED
   - What we know: `nsecRecord` uses a slice; NSEC3 follows the same pattern
   - Resolution: Use a slice (`nsec3records []nsec3Record`) matching the NSEC pattern — same mutex, same Flush() pattern. Adopted in Plan 01 Task 2.

---

## Sources

### Primary (HIGH confidence)

- `internal/resolver/recursive.go` — read directly; exact line numbers for both bugs confirmed
- `internal/cache/nsec.go` — read directly; Store() and SynthesizeNXDOMAIN() signatures confirmed
- `internal/cache/sharded.go` — read directly; Get() stale path lines 351-394 confirmed
- `internal/engine/security.go` — read directly; ApplyQNAMEMinimization() signature and behavior confirmed
- `internal/config/config.go` — read directly; `Resolver resolver.Config yaml:"resolver"` confirmed at line 18
- `internal/resolver/recursive_test.go` — read directly; existing test coverage and pre-existing failures confirmed
- `github.com/miekg/dns@v1.1.72/nsecx.go` — read directly; HashName(), Cover(), Match() signatures confirmed
- `github.com/miekg/dns@v1.1.72/types.go` — read directly; NSEC3 and NSEC3PARAM struct fields confirmed
- `github.com/miekg/dns@v1.1.72/nsecx_test.go` — read directly; HashName test vectors confirmed

### Secondary (MEDIUM confidence)

- RFC 7816, RFC 9156, RFC 8198, RFC 8767, RFC 5155 — canonical RFCs for the three features; content consistent with implementation

---

## Metadata

**Confidence breakdown:**

| Area | Level | Reason |
|------|-------|--------|
| Bug locations (both serve-stale bugs) | HIGH | Read exact lines in recursive.go and sharded.go |
| NSEC3 synthesis approach | HIGH | miekg Cover()/HashName() read directly from installed module |
| QNAME minimization wiring | HIGH | ApplyQNAMEMinimization() signature read directly; import cycle verified safe |
| Config wiring | HIGH | config.Config.Resolver field verified in config.go |
| Test patterns | HIGH | recursive_test.go and engine/resolver_test.go both read directly |
| RFC correctness | MEDIUM | Based on training knowledge cross-checked against implementation |

**Research date:** 2026-05-22
**Valid until:** 2026-06-22 (stable library versions, 30-day window)
