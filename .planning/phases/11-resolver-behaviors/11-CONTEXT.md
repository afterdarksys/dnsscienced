# Phase 11: Resolver Behaviors - Context

**Gathered:** 2026-05-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix and complete three resolver behaviors in `internal/resolver/recursive.go` (the full iterative recursive resolver — `engine.Resolver` is a stub forwarder and is NOT the target):

1. **QNAME Minimization (RFC 7816 + RFC 9156)** — wire per-delegation query name rewriting inside `resolveIterative()`. The existing `ApplyQNAMEMinimization()` in `engine/security.go` fires once at stub level; Phase 11 moves this logic into the iterative loop so each nameserver hop sees only the labels it needs.

2. **Aggressive NSEC/NSEC3 Synthesis (RFC 8198)** — `NSECCache` and `SynthesizeNXDOMAIN()` are already wired in `resolver.Resolve()`. Phase 11 adds NSEC3 synthesis support (NSEC only currently) and ensures the end-to-end path is testable hermetically.

3. **Serve-Stale (RFC 8767)** — fix two bugs in `resolver.Resolve()`: (a) the `!entry.IsExpired()` guard that bypasses the cache's own stale-serving logic, and (b) the missing upstream-failure fallback (when `resolveIterative()` returns an error, attempt stale cache before SERVFAIL).

</domain>

<decisions>
## Implementation Decisions

### QNAME Minimization

- **D-01:** Target is `internal/resolver/recursive.go` (`resolver.Recursive`) only. `engine.Resolver` is a stub forwarder — do not change its QNAME minimization behavior.
- **D-02:** Minimization happens per-delegation inside `resolveIterative()`: rewrite the query name to reveal one additional label beyond the current zone level at each hop. Reuse or inline the logic from `engine/security.go:ApplyQNAMEMinimization()`.
- **D-03:** RFC 9156 compliance — use `qtype=A` for intermediate hops (not the original qtype). Original qtype is only sent at the final hop to the authoritative nameserver. Planner must determine how to detect "final hop" (answer received, not a referral).

### Aggressive NSEC/NSEC3 Synthesis

- **D-04:** NSEC3 is in scope for Phase 11. Both NSEC and NSEC3 records must be synthesized.
- **D-05:** Synthesis is DNSSEC-validation-gated — only `StoreNSEC` when `dnssecValidated=true`. Synthesizing from unvalidated NSEC/NSEC3 is a spoofing vector (RFC 8198 §2.1). This gate stays.
- **D-06:** NSEC3 synthesis requires: (a) storing NSEC3 records with zone salt + iteration count, (b) hashing the candidate qname using the zone's algorithm/salt/iterations before range comparison. This is distinct from NSEC canonical ordering.

### Serve-Stale

- **D-07:** Fix both problems:
  1. Remove the `!entry.IsExpired()` guard in `resolver.Resolve()` (line 171) so the cache's own stale logic (`serveStale` + `IsStale(maxStaleTTL)`) is reached.
  2. Add upstream-failure fallback: when `resolveIterative()` returns an error, do a stale-permissive cache lookup before returning SERVFAIL.
- **D-08:** Stale responses are served with TTL=0 (RFC 8767 §5 SHOULD). Rewrite TTL on all RRs in the stale response to 0 before sending to client.

### Config / Feature Flags

- **D-09:** New features live in a `resolver:` block in `config.yaml`, parallel to existing `cache:` and `dnssec:` blocks:
  ```yaml
  resolver:
    qname_minimization: true      # RFC 7816 + RFC 9156
    aggressive_nsec: true         # RFC 8198 (NSEC + NSEC3)
    serve_stale: true             # RFC 8767
    stale_max_ttl: 24h            # Max age before refusing to serve stale
  ```
- **D-10:** All three features are ON by default for new deployments. Matches Unbound/Knot Resolver defaults and delivers RFC compliance out of the box.
- **D-11:** `stale_max_ttl` defaults to 24h. Serve-stale in cache layer already has `MaxStaleTTL` — the new `resolver:` config should wire into the same cache config field (avoid duplication).

### Claude's Discretion

- Whether NSEC3 synthesis lives in `internal/cache/nsec.go` (extending `NSECCache`) or a new `nsec3.go` file in the same package
- How "final hop" detection works for RFC 9156 qtype rewriting — could be: answer section non-empty, or tracking zone depth vs. delegation depth
- Whether `resolveIterative()` takes a `qname_minimization bool` param or reads from `r.cfg`
- Test structure — whether NSEC3 tests require mocked DNSSEC validation or can use pre-built validated response fixtures

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Primary Implementation Target
- `internal/resolver/recursive.go` — full iterative recursive resolver; all three features are wired here
- `internal/cache/nsec.go` — NSECCache with NSEC synthesis; extend for NSEC3
- `internal/cache/sharded.go` — ShardedCache with ServeStale/MaxStaleTTL/StaleRefresh config; `Get()` already implements stale logic at lines 360–390

### Existing QNAME Minimization (reference, do not change)
- `internal/engine/security.go:100` — `ApplyQNAMEMinimization()` — reuse logic or inline in iterative loop
- `internal/engine/resolver.go:88` — stub-level call site (not the target)

### RFCs (check miekg/dns for NSEC3 primitives)
- RFC 7816 — DNS Query Name Minimisation (original QNAME min)
- RFC 9156 — DNS Query Name Minimisation to Improve Privacy (qtype=A at intermediate hops)
- RFC 8198 — Aggressive Use of DNSSEC-Validated Cache (NSEC + NSEC3 synthesis)
- RFC 8767 — Serving Stale Data to Improve DNS Resiliency (TTL=0, bounded window)
- RFC 5155 — NSEC3 hashed authenticated denial of existence

### Config Wiring
- `internal/config/config.go` — where `resolver:` block config struct goes
- `internal/resolver/recursive.go:44` — `Config` struct in resolver package; extend with feature flags

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `cache.ShardedCache.Get()` — already handles stale serving when `serveStale=true`; the resolver just needs to stop guarding with `!entry.IsExpired()`
- `cache.ShardedCache.SynthesizeNXDOMAIN()` — already called in `resolver.Resolve()` step 2; wiring is there, just needs NSEC3 support underneath
- `engine.ApplyQNAMEMinimization()` — label-stripping logic reusable for iterative per-delegation minimization

### Established Patterns
- Nil-guard pattern from Phase 7: features initialized conditionally in `NewRecursive()`, accessed via `if r.validator != nil` etc.
- Setter pattern from Phase 8: `SetMetrics()`, `SetWebhook()` — avoid constructor changes, inject post-construction
- Config struct extension: add fields to `resolver.Config`, wire defaults in `NewRecursive()`, expose in `internal/config/config.go`

### Integration Points
- `resolver.Resolve()` — primary change surface: fix stale guard (line 171), add upstream-failure fallback (after `resolveIterative()` error at line 198)
- `resolver.resolveIterative()` — add per-delegation QNAME rewriting; track zone level across iterations
- `cache.NSECCache.Store()` — extend to also store NSEC3 records
- `cache.NSECCache.SynthesizeNXDOMAIN()` — extend to attempt NSEC3 synthesis when NSEC synthesis fails

### Pre-existing Test Failures (not our code)
- `internal/engine/TestResolver_Resolve` — makes real DNS query to example.com; non-hermetic, will still fail
- `internal/resolver/TestFindGlue` — assertion compares `"[2001:db8::1]"` (slice String()) to `"2001:db8::1"`; pre-existing bug

</code_context>

<specifics>
## Specific Requirements

- RESOLVE-01: Outgoing queries from the iterative resolver contain only the labels required for each nameserver level — not the full QNAME — when QNAME minimization is enabled
- RESOLVE-02: A cached and DNSSEC-validated NSEC/NSEC3 record that proves nonexistence causes the resolver to return NXDOMAIN without sending any upstream query
- RESOLVE-03: When all upstream nameservers are unreachable, the resolver returns a cached record with its TTL rewritten to 0, up to the configured stale-max-ttl rather than returning SERVFAIL

</specifics>

<deferred>
## Deferred Ideas

- NSEC3 opt-out zones (RFC 5155 §6) — edge case, can be a follow-up
- Prefetch integration for stale-while-revalidate pattern (cache already has StaleRefresh flag; wiring it into the resolver's upstream-failure path could be future work)
- `engine.Resolver` QNAME minimization correctness — it currently minimizes once at stub level; fixing it to be iterative is out of scope (it's not the production resolver path)

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 11-resolver-behaviors*
*Context gathered: 2026-05-22*
