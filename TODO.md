# DNSScienced TODO

This is the canonical project checklist. It reconciles the older
`TODO_DNSSCIENCED`, `TODO_DNSSCIENCED_2`, and relevant roadmap items against the
implementation available in the feature/bugfix branch stack as of 2026-07-22.

Legend:

- `[x]` is implemented and has concrete source or test coverage in this repository.
- `[ ]` is missing, only partially implemented, configuration-only, or belongs to
  another repository.

## Governing product goal

Build a Linux-native, security-first, ultra-fast, carrier-grade DNS platform
capable of replacing BIND and NSD in defined authoritative, secondary,
validating-recursive, forwarding, policy, local-root, and eventually public
root-authoritative deployments.

- [x] Define explicit role boundaries, data-plane tiers, correctness gates,
  Linux performance gates, and the distinction between loading `.` and operating
  a standards-conformant public root service.
- [x] Add validated role profiles that reject unsafe combinations and default
  authoritative/root listeners to recursion disabled.
- [ ] Build differential protocol suites against current BIND and NSD releases.
- [x] Build a root-authoritative conformance suite for RFC 7720 and a separate
  local-root suite for RFC 8806: signed authoritative answers and denial,
  EDNS(0), IPv4/IPv6 UDP/TCP, unique-root startup validation, loopback role
  isolation, complete root-secondary loading, SOA refresh/retry timing, and
  mandatory withdrawal at SOA Expire are covered. Public-root operational
  qualification remains a separate release gate.
- [ ] Define and continuously test carrier-grade overload SLOs for sustained QPS,
  p99/p99.9 latency, packet loss, TCP fallback, bounded memory, and recovery.

See [Carrier-Grade Multi-Role Architecture and Release
Gates](docs/CARRIER_GRADE_ROLES.md).

## Completed DNS cache and threat-intelligence work

- [x] Add threat score, categories, reputation, first/last seen, and source fields
  to the cache protobuf model.
- [x] Regenerate the Go protobuf and gRPC bindings.
- [x] Implement cache threat enrichment and reputation scoring.
- [x] Enrich entries when the sharded cache stores them.
- [x] Implement the `WatchCache` streaming RPC lifecycle and event-type filtering.
- [x] Publish cache STORE events, including threat metadata.
- [x] Publish HIT, MISS, EVICT, STORE, and DELETE events; enforce event-type and
  domain-pattern filters in the streaming service.
- [x] Aggregate multiple threat-intelligence providers with configurable refresh,
  scoring, provenance, and conflict handling.
- [x] Import operator-supplied threat lists.
- [ ] Add historical, per-client query analysis and durable anomaly history.

## DNS protocol and security work

- [x] Validate DNSSEC positive answers and authenticated denial with NSEC/NSEC3.
- [x] Enforce DNSSEC algorithm policy and NSEC3 iteration limits.
- [x] Load configured static DNSSEC trust anchors.
- [x] Implement RFC 5011 automatic trust-anchor maintenance with authenticated
  DNSKEY refresh, add/remove hold-down state, immediate self-signed revocation,
  permanent removed-key tombstones, RFC-derived refresh/retry timing, and
  atomic durable state required at startup.
- [x] Emit Extended DNS Errors for implemented validation and policy failures.
- [x] Apply QNAME minimization in the recursive resolver.
- [x] Authenticate DNS UPDATE and zone-transfer requests with TSIG, including
  constant-time MAC verification and live key rotation.
- [x] Randomize outbound query IDs and validate response identity.
- [x] Implement aggressive NSEC/NSEC3 caching.
- [x] Provide DGA and DNS-exfiltration heuristic detectors.
- [ ] Wire durable per-client tunneling, subdomain-enumeration, and exfiltration
  correlation into the primary server path with actionable alerts.
- [ ] Add GeoIP-based policy controls.
- [x] Add regex-based RPZ policy matching.
- [ ] Add per-client mTLS identities and authorization for DoT/DoH.
- [ ] Add JWT-based authorization where HTTP APIs require it.
- [ ] Add privacy-preserving, security-context audit logs and retention controls.
- [ ] Implement DNS over QUIC (RFC 9250); the experimental configuration stub is
  not an operational listener.
- [ ] Implement Oblivious DoH (RFC 9230).
- [x] Add authenticated and confidential zone transfer over TLS (RFC 9103):
  strict TLS 1.3 AXFR/IXFR in both directions, ALPN `dot`, primary
  authentication, optional mTLS, TSIG/source-ACL authorization, per-zone
  cleartext refusal, EDE 21, and no client fallback. RFC 9103 does not define
  zone transfer over QUIC; DoQ remains tracked separately.
- [x] Add configurable query-complexity admission scoring before policy,
  authoritative, and recursive processing, with Prometheus rejection counters.
- [x] Add bounded adaptive IP-reputation admission limits with lazy score decay,
  fixed-capacity sharded state, trusted CIDR exemptions, and Prometheus metrics.
- [x] Add explicit TCP/SYN-flood protections: bounded global/per-client
  established connections, handshake admission rate, idle/query limits,
  Prometheus metrics, and Linux SYN-cookie/backlog deployment guidance.
- [ ] Add forensic query replay and SOC 2/ISO 27001 reporting workflows.
- [ ] Add SIEM/SOAR export formats and integrations.

## Response Policy Zones

- [x] Implement the in-memory RPZ rule engine for exact/wildcard query-name rules,
  passthrough, NXDOMAIN, NODATA, drop, and rewrite actions.
- [x] Wire RPZ loading and enforcement into the primary production server and its
  documented configuration path.
- [x] Implement response-IP (`rpz-ip`) policy triggers for answer-section A/AAAA
  data with IPv4/IPv6 prefix validation, RPZ-zone and trigger precedence, and
  production authoritative/recursive response enforcement.
- [x] Implement client-IP (`rpz-client-ip`) triggers with longest-prefix matching,
  IPv4/IPv6 validation, and precedence over QNAME/response-IP within a policy zone.
- [x] Implement NS-name (`rpz-nsdname`) and NS-IP (`rpz-nsip`) triggers with
  recursive answer data-path discovery, wildcard/canonical-name and IP-prefix
  tie-breaking, bounded lookup controls, and full trigger/zone precedence.
- [x] Add safe hot reload, precedence rules, source attribution, hit metrics, and
  end-to-end production-path tests.

## Resolver performance and operator tuning

- [x] Make near-expiry cache prefetch bypass the live entry, suppress duplicate
  refreshes, and expose prefetch through the live admin API.
- [x] Coalesce concurrent cache misses for the same question while preserving
  independent client transaction IDs and cancellation.
- [x] Route recursive cache misses through an operational bounded worker pool and
  expose truthful queue, saturation, and rejection metrics.
- [x] Add safe parallel or hedged nameserver queries with cancellation and bounded
  fan-out.
- [x] Wire the existing byte-buffer pools or an equivalent allocation strategy
  into measured production network paths; retain only changes that benchmarks
  show reduce allocations.
- [x] Retire the unused experimental assembly-parser UDP server and its raw
  resolver bypass instead of duplicating the production security pipeline.
  DNSASM remains a research/benchmark library; production UDP remains on the
  audited `miekg/dns` path with the faster scalar header check.
- [x] Add a fixed-stride, recvmmsg-compatible batch header API with reusable output
  storage and measured zero-allocation steady-state parsing. Benchmarking showed
  scalar Go is faster than cgo even after amortizing the transition, so production
  header rejection stays in Go.
- [x] Make the x86 SIMD header parser read exactly the 12-byte DNS header, use
  baseline SSE2 instead of assuming optional CPU features, and repair the assembly
  response-header builder's corrupted output pointer.
- [x] Add a bounded Linux-only recvmmsg/sendmmsg transport primitive with reusable
  packet slots, IPv4/IPv6 and truncation tests, and syscall-level benchmarks.
- [x] Integrate opt-in Linux recvmmsg receive batching through the production
  `miekg/dns` parser/handler path with SO_REUSEPORT, destination-address
  preservation, TSIG failure parity, bounded batches, and fill/truncation stats.
- [ ] Promote Linux batching from opt-in (`server.udp_batch_size`) only after
  complete receive-parse-route-send NIC/RSS load tests improve throughput and
  p99/p99.9 latency versus the portable listener.
- [x] Define an opt-in XDP/AF_XDP architecture with guarded `XDP_PASS` fallback,
  queue-owned workers, generation-based cache/policy coherence, least privilege,
  observability, hardware qualification, and portable-path differential tests.
- [ ] Implement and qualify guarded XSK-map redirection and the AF_XDP user-space
  engine; keep direct in-kernel cache responses out of scope until separately
  threat-modeled and proven faster.
- [x] Quarantine and harden the legacy Netfilter RPZ module: root-only
  capability-checked control, bounded ingress-only parsing, opt-in rate-limited
  logging, fragment pass-through, and RCU-safe unload.
- [x] Replace linear eviction work under cache-shard locks with a measured
  low-contention policy; do not claim the cache is lock-free while it uses shard
  mutexes.
- [x] Add validated runtime controls and documentation for listener count, resolver
  concurrency, queue size, cache size/shards, and Go memory/GC limits.
- [x] Decide and document CPU-affinity support. Prefer service-manager/container
  affinity unless measurements justify per-worker OS-thread pinning.
- [x] Add explicit forwarding/upstream modes so operators can choose direct
  iterative resolution, public recursive resolvers, or conditional forwarders
  without relying on ignored configuration.

## Catalog Zones (RFC 9432)

Catalog Zones implement the RFC 9432 schema-version-2 consumer core and safe
automatic secondary provisioning. The remaining work below is primarily
fleet-scale policy, operations, interoperability, and producer support.

### Transfer prerequisites

- [x] Serve authoritative zones and support atomic zone add/remove operations.
- [x] Authenticate AXFR and DNS UPDATE with TSIG.
- [x] Serve AXFR and accept IXFR requests with documented AXFR fallback.
- [x] Implement true IXFR delta generation and consumption.
- [x] Implement ordinary SOA NOTIFY-driven secondary refresh; DSYNC NOTIFY support
  does not satisfy this prerequisite.

### Catalog data model and validation

- [x] Add explicit catalog consumer configuration, primary endpoints, TSIG
  credentials, refresh policy, and per-catalog group mappings.
- [ ] Add catalog producer support with explicit query/transfer ACLs and RFC 9103
  TLS transfer credentials.
- [x] Parse and validate `version.<catalog> TXT "2"` exactly as RFC 9432 requires.
- [x] Parse member nodes as one-PTR RRsets beneath
  `<unique>.zones.<catalog>` and reject duplicate member names or malformed sets.
- [x] Parse optional `group.<unique>.zones.<catalog>` TXT properties.
- [x] Parse the `coo.<unique>.zones.<catalog>` change-of-ownership property.
- [x] Ignore unsupported records and properties while rejecting malformed known
  properties.
- [x] Preserve and expose namespaced `*.ext` custom properties without assigning
  them unsafe default behavior.
- [x] Validate SOA/NS presence, IN class, supported schema version, unique member
  labels, and unique member zones before applying a catalog.
- [x] Enforce RFC 1982 catalog serial progression and reject stale/equal snapshots
  while retaining the last-valid fleet state.

### Consumer reconciliation

- [x] Fetch catalog zones through authenticated AXFR/IXFR and refresh them after
  SOA NOTIFY or timer expiry.
- [x] Compute a deterministic add/update/remove plan from the last valid catalog.
- [x] Prepare all catalog member transfers before atomically swapping the
  authoritative fleet; failures retain the previous catalog, workers, and
  durable ownership state.
- [x] Automatically provision newly listed member zones using the catalog's group
  mapping and transfer policy.
- [x] Remove a member and its associated state only when that same catalog created
  it; optionally archive state for recovery.
- [x] Treat a changed member-node label as remove-and-recreate, including the
  RFC-required associated-state reset.
- [x] Detect member-zone name clashes with static zones or other catalogs, retain
  the existing zone, and report the conflict.
- [x] Implement controlled cross-catalog migration through `coo`, including the
  required confirmation in the destination catalog.
- [x] Retain the last valid applied state when a catalog becomes malformed, stale,
  expired, or temporarily unreachable.
- [x] Persist last-valid catalog/member records, ownership, labels, and serials so
  the reconciliation plan is deterministically recomputed after restart.

### Catalog safety and operations

- [x] Require authenticated catalog transfers and authenticated DNS UPDATE by
  default.
- [x] Support confidential catalog and catalog-member transfer using strict
  RFC 9103 TLS 1.3 with optional mTLS and no cleartext fallback.
- [x] Keep consumer catalog contents outside the authoritative query/transfer
  store (deny-all by architecture); any future producer surface is gated above
  on explicit query/transfer ACLs.
- [x] Scope admissible member names with per-catalog allow/deny suffixes; deny
  rules take precedence and reject the complete snapshot.
- [x] Bound configured catalogs, members per catalog, reconciliation action
  counts, AXFR/IXFR records, transfer bytes, and member provisioning concurrency
  (currently serialized).
- [x] Add an operator-configurable per-catalog reconciliation token budget with
  lazy refill and failure refunds.
- [x] Reject configured catalogs as member zones, self-referential `coo`, and
  deterministic cross-catalog ownership cycles before persistence or side effects.
- [x] Provide dry-run and serial-bound approval modes for mass deletion or replacement.
- [x] Add structured audit events for catalog receipt, validation, reconciliation,
  conflicts, migrations, and state resets.
- [x] Add Prometheus metrics and admin status APIs for catalog freshness, serial,
  members, reconcile outcomes, and transfer failures.
- [x] Add CLI/admin operations to list catalogs, members, effective group config,
  ownership, errors, and pending reconciliation.
- [x] Add unit, race, restart, malformed-catalog, and failure-injection tests.
- [x] Add catalog parser and reconciliation fuzz tests.
- [ ] Add interoperability tests with at least BIND, Knot DNS, and PowerDNS catalog
  producers/consumers.
- [x] Document configuration, migration, rollback, disaster recovery, and a complete
  RFC 9432 schema-v2 example.

## ads-httpproxy integration (external repository)

These cannot be marked complete from this repository alone.

- [ ] Add dnsscienced protobuf definitions or a versioned generated client.
- [ ] Add a pooled, retrying, TLS-capable dnsscienced gRPC client.
- [ ] Query cache threat metadata in the proxy request path and enforce a configured
  score threshold.
- [ ] Subscribe to `WatchCache` and update the proxy threat manager in real time.
- [ ] Add a local TTL decision cache, enriched audit logs, and Prometheus metrics.
- [ ] Add integration and load tests covering both repositories.

## Deployment, performance, and monitoring

- [ ] Add an integrated Docker Compose deployment for dnsscienced and
  ads-httpproxy.
- [ ] Add Kubernetes Services, ConfigMaps/Secrets, and persistent storage manifests.
- [ ] Benchmark gRPC cache-hit latency and compare it with the HTTP API path.
- [ ] Load test realistic DNS and integration traffic at the documented concurrency
  targets.
- [x] Expose baseline Prometheus DNS, cache, RRL, transfer, and system metrics.
- [ ] Add integration-specific threat-score and proxy decision metrics.
- [ ] Add maintained Grafana dashboards and actionable alert rules.

## Longer-term research

- [ ] ML-assisted threat scoring with an explainable, versioned model and evaluation
  corpus.
- [ ] Privacy-preserving collaborative threat sharing.
- [ ] Browser extension for domain-reputation visualization.
- [ ] Evaluate standardized post-quantum DNSSEC algorithms if and when assigned and
  supported by the DNS ecosystem.
- [ ] Keep blockchain trust anchors and immutable-ledger designs out of production
  scope unless a concrete threat model demonstrates an advantage over DNSSEC and
  append-only audit storage.

## Historical source lists

- `TODO_DNSSCIENCED` contains the original ads-httpproxy integration plan.
- `TODO_DNSSCIENCED_2` contains the original security-feature brainstorm.
- `ROADMAP.md` contains the broader milestone roadmap.

New work and status changes should be recorded in this file so implementation and
planning do not drift again.
