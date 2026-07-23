# Carrier-Grade Multi-Role Architecture and Release Gates

DNSScienced's product target is a security-first, Linux-native DNS platform
capable of replacing BIND or NSD in defined deployments. It must support
authoritative, validating recursive, forwarding, policy/security, and root-zone
roles without weakening protocol correctness to gain benchmark throughput.

This is a release-gate document, not a claim that every role is production-ready.
Passing a microbenchmark or successfully loading a root-zone file does not make a
server suitable for public root service.

## Role model

| Role | Required behavior | Isolation rule | Current gate |
|---|---|---|---|
| Authoritative primary | Atomic zone load/reload, correct referrals and negative answers, DNSSEC serving, UPDATE, NOTIFY, AXFR/IXFR, TSIG, ACLs | Recursion disabled by validated profile | Partial: protocol matrix and interoperability remain |
| Authoritative secondary | Authenticated AXFR/IXFR, serial arithmetic, refresh/retry/expire, NOTIFY, last-good atomic snapshots | Expired zones are withdrawn at SOA Expire | Partial: interoperability and durable transfer state remain |
| Validating recursive | Iteration from root hints, DNSSEC validation, negative caching, QNAME minimization, bounded work, cache/prefetch, serve-stale policy | Authoritative data cannot contaminate recursion | Partial: RFC 5011 and forwarding modes are implemented; broad interoperability/conformance remains |
| Forwarder | Explicit public-recursive, private-upstream, and conditional-forwarding modes with health, failover, TLS policy, and loop prevention | Never silently fall back to an ISP/host resolver | Partial: strict profile and modes implemented; health and encrypted upstreams remain |
| Security/policy | RPZ, RRL, cookies, ACLs, threat enrichment, auditable decisions, bounded failure behavior | Security checks are part of every enabled data path, including fast paths | Partial |
| Local root | Complete root-zone acquisition, signed authoritative data, loopback-only authority, refresh/expire behavior | Must not become an unintended public alternate root; stale authority is withdrawn | Software conformance suite implemented; deployment integration with a same-host validating resolver remains |
| Public root authoritative | Unique root-zone service, IPv4/IPv6, UDP/TCP, EDNS, authoritative DNSSEC, exact protocol behavior, anycast operations, published service evidence | Dedicated authoritative-only profile; no recursion, forwarding, or tenant policy | RFC 7720 daemon protocol suite implemented; operationally not release-ready |

NSD is deliberately authoritative-only, while BIND can combine authoritative and
recursive functions. DNSScienced may support multiple roles in one binary, but a
carrier deployment should select an explicit profile. Listener and policy
configuration must reject unsafe combinations rather than infer intent.

The validated profiles and examples are documented in
[ROLE_PROFILES.md](ROLE_PROFILES.md).

## Data-plane tiers

All tiers must produce equivalent DNS behavior for the same role and policy.

1. **Portable audited path** — the complete Go server is the correctness oracle
   for UDP, TCP, DoT, and DoH behavior.
2. **Linux batched path** — `SO_REUSEPORT` listeners with fixed routing and
   `recvmmsg`/`sendmmsg` may reduce syscall overhead. It can graduate only after
   differential tests show response equivalence and load tests improve both
   throughput and p99 latency.
3. **Kernel-adjacent path** — XDP/AF_XDP may answer immutable authoritative or
   cache-hit traffic. Misses, unsupported features, control traffic, and uncertain
   policy decisions must pass to user space. Generation-tagged snapshots must
   prevent stale cache or policy use.

Assembly remains an implementation tool, not a tier. A native routine must own
enough work to repay its Go/cgo transition, have scalar fallbacks, pass fuzz and
differential tests, and improve the Linux end-to-end result.

## Control plane and state

- Publish immutable zone, cache-policy, RPZ, key, and configuration generations
  atomically; readers never observe partially applied state.
- Separate transfer/update ingestion from serving snapshots.
- Persist secondary serial/journal state, trust-anchor rollover state, catalog
  ownership, and last-good configuration where restart correctness depends on it.
- Put hard bounds on packets, names, records, transfer sizes, update rates, worker
  queues, cache growth, concurrent TCP/TLS sessions, and expensive DNSSEC work.
- Expose generation, freshness, serial, queue saturation, rejection, validation,
  RRL, and fast-path fallback metrics.
- Make every dynamic mutation attributable through structured audit events.

## Protocol and correctness gates

Before a role is called a BIND/NSD replacement:

- Pass authoritative and recursive DNS test suites, malformed-packet fuzzing,
  race tests, and differential response testing against at least BIND and NSD
  where their roles overlap.
- Correctly handle IPv4/IPv6, UDP/TCP, truncation and retry, EDNS versions and
  advertised sizes, DNSSEC, unknown RR types, unknown opcodes/options, cookies,
  multiple questions, compression loops, and response-code selection.
- Interoperate for UPDATE, NOTIFY, AXFR, IXFR, TSIG, catalog zones, and encrypted
  transfer where enabled.
- Survive restart, stale/expired secondary data, corrupt journals, unavailable
  primaries, clock changes, partial writes, and rolling upgrades without serving
  an unvalidated partial state.
- Demonstrate overload behavior: bounded memory and goroutines, controlled
  refusal/drop/truncation, TCP backpressure, no amplification-policy bypass, and
  recovery after load subsides.

[RFC 8906](https://www.rfc-editor.org/rfc/rfc8906) is part of the response-behavior
gate because silence or structurally incorrect error responses harm both current
operations and future protocol deployment.

## Root-service gates

Public root-authoritative readiness requires all software gates above plus a
dedicated root profile conforming to
[RFC 7720](https://www.rfc-editor.org/rfc/rfc7720): core DNS, IPv4 and IPv6, UDP
and TCP, authoritative DNSSEC, EDNS(0), the unique root zone, and service to valid
Internet clients. Operational readiness is a separate program covering
[RSSAC001 service expectations](https://www.icann.org/en/rssac/publications),
including accuracy, availability, capability, security, implementation
diversity, monitoring, measurements, and infrastructure transparency.

Anycast routing, capacity diversity, DDoS transit, route security, node
identification, monitoring from outside each site, and root-zone distribution
are deployment-system responsibilities. The daemon must expose the hooks and
evidence they need, but application code alone cannot satisfy them.

A local root is a different role. It follows
[RFC 8806](https://www.rfc-editor.org/rfc/rfc8806), including a current complete
root zone, DNSSEC validation material, and authority restricted to the same host.
DNSScienced's local-root profile enforces loopback listeners, serves the signed
root data required by the same-host validating resolver, refreshes a secondary
root from SOA timers, and withdraws it at SOA Expire after failed refreshes.
Fallback to non-local roots is the responsibility of that same-host validating
resolver, matching the separated-service model described by RFC 8806.

## Performance gates

- Benchmark on the production Linux kernel, NIC class, CPU topology, and container
  or service-manager limits.
- Report sustained QPS plus p50/p95/p99/p99.9 latency, packet loss, TCP fallback,
  SERVFAIL/REFUSED rates, CPU per query, RSS, allocations, GC CPU, queue depth,
  cache hit rate, and fast-path fallback rate.
- Include realistic query-name/type distributions, response sizes, DNSSEC,
  cache hits/misses, NXDOMAIN, attack traffic, zone reloads, transfers, and
  concurrent TCP/TLS work.
- Compare equivalent configurations with current BIND and NSD releases. NSD's
  documented Linux levers—multiple servers, `SO_REUSEPORT`, optional
  `recvmmsg`, processor affinity, and XDP—are individual experiment dimensions,
  not a single bundled benchmark.
- No throughput result is accepted if responses differ, security checks are
  skipped, memory is unbounded, or tail latency fails the declared service-level
  objective.

Official comparison references:

- [BIND 9 Administrator Reference Manual](https://bind9.readthedocs.io/en/stable/)
- [NSD documentation](https://nsd.docs.nlnetlabs.nl/en/latest/)
- [NSD tuning](https://nsd.docs.nlnetlabs.nl/en/latest/running/tuning.html)
- [Large authoritative DNS operator considerations (RFC 9199)](https://www.rfc-editor.org/rfc/rfc9199)
