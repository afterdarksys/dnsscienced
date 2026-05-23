# Phase 11: Resolver Behaviors - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-22
**Phase:** 11-resolver-behaviors
**Areas discussed:** QNAME minimization wiring, Serve-stale integration, Aggressive NSEC gaps, Config / feature flags

---

## QNAME Minimization Wiring

### Canonical resolver target

| Option | Description | Selected |
|--------|-------------|----------|
| resolver.Recursive only | Fix resolveIterative() per-delegation. RFC 7816 compliant. | ✓ |
| Both resolvers | Wire iterative minimization in Recursive AND keep engine.Resolver single-shot. More work. | |

**User's choice:** resolver.Recursive only
**Notes:** engine.Resolver is a stub forwarder — changing its QNAME minimization is out of scope.

### RFC 9156 qtype rewriting

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, qtype=A for intermediate hops | RFC 9156 compliant. Intermediate NSes see only A queries. | ✓ |
| No, send original qtype at every hop | Simpler. Still minimizes labels but leaks qtype to intermediate NSes. | |

**User's choice:** Yes, use qtype=A for intermediate hops
**Notes:** Full RFC 9156 compliance. Planner to determine final-hop detection strategy.

---

## Serve-Stale Integration

### Fix scope

| Option | Description | Selected |
|--------|-------------|----------|
| Fix both: stale cache check + upstream failure fallback | Remove !IsExpired() guard + add resolveIterative() error fallback. Full RFC 8767. | ✓ |
| Upstream failure fallback only | Keep IsExpired guard, only add error fallback. Simpler but less correct. | |

**User's choice:** Fix both

### Stale TTL in response

| Option | Description | Selected |
|--------|-------------|----------|
| Serve with TTL=0 | RFC 8767 SHOULD. Clients don't re-cache. | ✓ |
| Serve with original remaining TTL | Simpler. Not RFC 8767 compliant. | |

**User's choice:** TTL=0 for stale responses.

---

## Aggressive NSEC Gaps

### NSEC3 scope

| Option | Description | Selected |
|--------|-------------|----------|
| NSEC only | Ship NSEC now; NSEC3 is substantially harder (requires hashing). | |
| NSEC and NSEC3 both | Full RFC 8198 compliance. Harder — hash candidate names, compare hash ranges. | ✓ |

**User's choice:** Both NSEC and NSEC3 in scope for Phase 11.

### DNSSEC validation gate

| Option | Description | Selected |
|--------|-------------|----------|
| Keep DNSSEC validation required | Safe. RFC 8198 §2.1 requires validated records only. | ✓ |
| Allow unvalidated NSEC | More permissive. Spoofing vector. | |

**User's choice:** Keep DNSSEC-validation-gated synthesis.

---

## Config / Feature Flags

### Config structure

| Option | Description | Selected |
|--------|-------------|----------|
| resolver: block with sub-flags | resolver:\n  qname_minimization: true\n  aggressive_nsec: true\n  serve_stale: true | ✓ |
| Top-level flags | Flat. Harder to namespace later. | |
| Split: stale in cache:, rest in resolver: | Stale already has MaxStaleTTL in cache config. | |

**User's choice:** resolver: block with all three sub-flags.

### Defaults

| Option | Description | Selected |
|--------|-------------|----------|
| All three ON by default | Matches Unbound/Knot defaults. RFC compliance out of the box. | ✓ |
| All three OFF | Conservative. Operators opt in. | |
| QNAME on, NSEC on, stale off | Middle ground. | |

**User's choice:** All three ON by default.

---

## Claude's Discretion

- Whether NSEC3 synthesis lives in `cache/nsec.go` (extending NSECCache) or a new `cache/nsec3.go`
- How "final hop" detection works for RFC 9156 qtype=A rewriting
- Whether `resolveIterative()` reads feature flags from `r.cfg` directly or via param
- Test structure for NSEC3 (mocked DNSSEC vs. pre-built validated fixtures)

## Deferred Ideas

- NSEC3 opt-out zones (RFC 5155 §6 edge case)
- Stale-while-revalidate prefetch integration (StaleRefresh flag exists in cache)
- engine.Resolver QNAME minimization correctness (out of scope — not the production path)
