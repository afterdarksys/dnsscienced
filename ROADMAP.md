# DNSScienced Implementation Roadmap

**Updated:** 2026-08-08

This file describes current product direction. Historical phase plans and
milestone audits live under `.planning/`; they are valuable provenance, but
some describe older commits and must not be treated as the current capability
matrix.

## Current baseline

DNSScienced currently ships an integrated implementation of:

- Authoritative UDP/TCP service, native and BIND zone loading, compiled zones,
  EDNS(0), modern record types, wildcards, referrals, glue, and negative
  answers.
- AXFR/IXFR, transfer-over-TLS, NOTIFY, secondary management, TSIG, RFC 2136
  UPDATE, durable update persistence, and catalog-zone operations.
- Recursive resolution with sharded caching, negative caching, serve-stale,
  QNAME minimization, 0x20 randomization, forwarding modes, hedging, prefetch,
  and request coalescing.
- DNSSEC validation with durable RFC 5011 trust anchors and aggressive negative
  caching.
- RPZ and DNS firewall enforcement with threat feeds and Starlark policy.
- RRL, DNS Cookies, query complexity limits, TCP resource controls, pooled
  buffers, and optional Linux UDP batching.
- DoT, DoH, an authenticated gRPC management plane, metrics, audit logging,
  role profiles, and operational documentation.

The full Go suite passes as of this update. A pinned Docker differential suite
also compares a defined authoritative query corpus with BIND and NSD.

## Priority 1: release evidence and reproducibility

- [ ] Publish versioned releases with reproducible build instructions and
      signed checksums.
- [ ] Run the full suite under Linux and macOS in CI, including `-race` gates
      for critical packages.
- [ ] Run the BIND/NSD differential suite in CI and retain its normalized result
      as a release artifact.
- [ ] Add protocol-focused fuzz corpora and long-duration fuzz budgets for wire
      parsing, UPDATE, TSIG, DNSSEC, and transfer state machines.
- [ ] Add end-to-end benchmark profiles with commit, hardware, kernel, network,
      zone size, traffic mix, latency, loss, allocations, and CPU usage.
- [ ] Archive DNSBlast JSON output as a release artifact and record both the
      DNSScienced and DNSBlast commit IDs for every published comparison.
- [ ] Produce an independently reproducible security and conformance report.

## Priority 2: authoritative completeness

- [ ] Expand differential coverage beyond the initial 14 cases.
- [ ] Add stateful comparison profiles for UPDATE, NOTIFY, AXFR, IXFR, TSIG,
      catalog zones, and DNSSEC denial responses.
- [ ] Add large-zone and high-churn tests for catalog reconciliation and dynamic
      update persistence.
- [ ] Decide whether authoritative online signing belongs in core. Until it is
      implemented, continue rejecting `dnssec_signing.enabled` explicitly.
- [ ] Document pre-signed-zone operating procedures and rollover boundaries.

## Priority 3: recursive-resolver assurance

- [ ] Build a differential recursive suite against Unbound, BIND, and PowerDNS
      Recursor using deterministic local authorities.
- [ ] Expand DNSSEC chain, insecure delegation, bogus-answer, rollover, and
      clock-behavior vectors.
- [ ] Exercise cache poisoning, bailiwick, delegation loops, CNAME/DNAME loops,
      truncation fallback, stale data, and upstream failure under sustained
      concurrency.
- [ ] Run long-lived resolver soak tests with bounded memory and goroutine
      assertions.

## Priority 4: performance engineering

- [ ] Establish portable baseline profiles before enabling DNSASM, recvmmsg, or
      XDP/kernel acceleration.
- [ ] Publish throughput and latency distributions for authoritative hot-zone,
      recursive hot-cache, recursive cold-cache, DNSSEC, TCP, DoT, and DoH
      workloads.
- [ ] Compare like-for-like configurations with BIND, NSD, Knot, Unbound, and
      PowerDNS rather than comparing microbenchmarks with network QPS.
- [ ] Track allocation, GC, lock contention, and memory-per-zone regressions in
      CI.
- [ ] Keep optional accelerated paths fail-closed and semantically equivalent to
      the portable path.

## Priority 5: operations and packaging

- [ ] Publish minimal container images and an operator-focused deployment
      example.
- [ ] Add upgrade, rollback, backup, restore, key rotation, and disaster
      recovery acceptance tests.
- [ ] Add configuration schema validation that rejects unknown or obsolete keys.
- [ ] Define supported platforms and support boundaries for portable, Linux
      batching, DNSASM, and kernel/XDP modes.
- [ ] Version the gRPC API and document compatibility guarantees.

## Experimental boundary

DoQ, draft protocols, Web3 mappings, DNSASM, and kernel/XDP integrations are
research or advanced paths unless explicitly promoted by a release. They should
not block release hardening of the portable authoritative and recursive core.

## Definition of a defensible BIND/NSD comparison

DNSScienced can claim parity only for behavior covered by reproducible tests.
The comparison becomes progressively stronger as the project publishes:

1. A pinned reference implementation and configuration.
2. A shared query or state-transition corpus.
3. Normalization rules that ignore wire trivia but preserve semantics.
4. Identical pass/fail criteria.
5. Release-linked output that an independent operator can reproduce.
6. Explicit exclusions and known differences.

Protocol parity is separate from deployment maturity. BIND and NSD have decades
of operational exposure; DNSScienced must earn confidence through expanding
evidence, independent review, and sustained real deployments.
