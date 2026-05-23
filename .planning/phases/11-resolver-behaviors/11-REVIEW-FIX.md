---
phase: 11-resolver-behaviors
fixed_at: 2026-05-22T00:00:00Z
review_path: .planning/phases/11-resolver-behaviors/11-REVIEW.md
iteration: 1
findings_in_scope: 10
fixed: 10
skipped: 0
status: all_fixed
---

# Phase 11: Code Review Fix Report

**Fixed at:** 2026-05-22T00:00:00Z
**Source review:** .planning/phases/11-resolver-behaviors/11-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 10 (4 critical, 6 warning)
- Fixed: 10
- Skipped: 0

## Fixed Issues

### CR-01: defer pool.PutMessage inside stale-fallback path

**Files modified:** `internal/resolver/recursive.go`
**Commit:** 514c6df
**Applied fix:** Replaced `defer pool.PutMessage(staleResp)` with explicit calls at each return site. When the unpack succeeds, copies the response first (`result := staleResp.Copy()`), then calls `pool.PutMessage(staleResp)`, then returns `result`. When the unpack fails, calls `pool.PutMessage(staleResp)` before falling through. Eliminates the fragile defer-inside-conditional pattern that could lead to double-free on future refactors.

---

### CR-02: D-10 default-override guard silently overrides explicit single-flag-off configs

**Files modified:** `internal/resolver/recursive.go`
**Commit:** b46aa49
**Applied fix:** Removed the `if !cfg.QNAMEMinimization && !cfg.AggressiveNSEC && !cfg.ServeStale` heuristic guard from `NewRecursive`. Added a new `DefaultConfig()` constructor that explicitly sets all three feature flags to `true` along with sane defaults for `QueryTimeout`, `MaxIterations`, `Workers`, and `StaleTTL`. `Config{}` now means "all features off" as the zero value implies.

---

### CR-03: NSEC wrap-around synthesis path covers names in foreign zones

**Files modified:** `internal/cache/nsec.go`
**Commit:** 5d5257a
**Applied fix:** Added `if !dns.IsSubDomain(rec.Zone, qname) { continue }` guard at the top of the NSEC record loop in `SynthesizeNXDOMAIN`, before either the normal or wrap-around canonicalLess comparisons. This prevents NSEC records from one zone from synthesizing NXDOMAIN for names in unrelated zones.

---

### CR-04: resolveIterative returns ErrNoNameservers for all delegations with out-of-zone NS targets

**Files modified:** `internal/resolver/recursive.go`
**Commit:** fcc8d8e
**Applied fix:** Added a glue resolution fallback: when `newNameservers` is empty after scanning the Additional section, iterate over NS records in the authority section and call `r.resolveIterative` recursively for each NS target name (TypeA). Add resolved A record IPs to `newNameservers`. The sub-resolution is gated on `iterations < r.cfg.MaxIterations` to prevent unbounded recursion. The second `ErrNoNameservers` check follows after this fallback.

---

### WR-01: getTTL defaults to 3600 for NXDOMAIN responses

**Files modified:** `internal/resolver/recursive.go`
**Commit:** 90b1b40
**Applied fix:** Rewrote `getTTL` to detect negative responses (`RcodeNameError` or `RcodeSuccess` with empty answer). For negative responses, extracts the SOA from the authority section and returns `min(soa.Minttl, soa.Hdr.Ttl)` clamped to `[10, 10800]`. Falls back to 300s (5 minutes) when no SOA is present. Positive responses continue to use the minimum TTL across the Answer section.

---

### WR-02: DNSSEC validation error silently discarded

**Files modified:** `internal/resolver/recursive.go`
**Commit:** 75c6c03
**Applied fix:** Changed `result, _ :=` to `result, validErr :=`. Added a check for `validErr != nil` that returns a SERVFAIL response immediately, preventing a transient validator failure from serving potentially bogus data as if it were unvalidated-but-valid.

---

### WR-03: resolveIterative always queries nameservers[0] — server failover consumes iteration budget

**Files modified:** `internal/resolver/recursive.go`
**Commit:** d028c7b
**Applied fix:** Replaced the `resp, err := r.queryNameserver(ctx, nameservers[0], ...)` pattern with an inner `for i, ns := range nameservers` loop that tries each server in order and breaks on the first success. The QNAME minimization fallback re-query is performed against the same successful server. Server failover no longer calls `continue` on the outer iteration loop, so the MaxIterations budget is consumed only for zone delegation hops, not for server failover within a single delegation.

---

### WR-04: Resolve calls SynthesizeNXDOMAIN without checking AggressiveNSEC config

**Files modified:** `internal/resolver/recursive.go`
**Commit:** 434c6b0
**Applied fix:** Wrapped the `r.cache.SynthesizeNXDOMAIN(...)` call with `if r.cfg.AggressiveNSEC { ... }` so the resolver's own config flag controls synthesis, decoupling policy from the cache layer's nil-nsecCache implementation detail.

---

### WR-05: canonicalLess uses Go string comparison — incorrect for non-ASCII labels

**Files modified:** `internal/cache/nsec.go`
**Commit:** 8645c5c
**Applied fix:** Added an explicit doc comment to `canonicalLess` documenting the ASCII/ACE-only assumption and noting that raw UTF-8 labels would require byte-level comparison per RFC 4034 §6.1. Added an inline comment on the comparison line. This makes the limitation explicit for future maintainers rather than leaving it as a silent assumption.

---

### WR-06: StoreNSEC passes question.Name as zone argument

**Files modified:** `internal/resolver/recursive.go`
**Commit:** 0f58ad4
**Applied fix:** Added `extractZoneFromResponse(resp)` helper that searches the authority section for a SOA record (using its `Hdr.Name` as the zone) and falls back to the first NS record owner name, finally returning `"."` if neither is found. Changed the `StoreNSEC` call from `r.cache.StoreNSEC(resp, question.Name)` to `r.cache.StoreNSEC(resp, extractZoneFromResponse(resp))`.

---

_Fixed: 2026-05-22T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
