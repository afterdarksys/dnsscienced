# DNSScienced TODO

This is the canonical project checklist. It reconciles the older
`TODO_DNSSCIENCED`, `TODO_DNSSCIENCED_2`, and relevant roadmap items against the
implementation on `fixes/dns-audit-hardening` as of 2026-07-22.

Legend:

- `[x]` is implemented and has concrete source or test coverage in this repository.
- `[ ]` is missing, only partially implemented, configuration-only, or belongs to
  another repository.

## Completed DNS cache and threat-intelligence work

- [x] Add threat score, categories, reputation, first/last seen, and source fields
  to the cache protobuf model.
- [x] Regenerate the Go protobuf and gRPC bindings.
- [x] Implement cache threat enrichment and reputation scoring.
- [x] Enrich entries when the sharded cache stores them.
- [x] Implement the `WatchCache` streaming RPC lifecycle and event-type filtering.
- [x] Publish cache STORE events, including threat metadata.
- [ ] Publish HIT, MISS, and EVICT events and implement the requested domain-pattern
  filter; the protobuf fields exist but the service does not yet enforce all of them.
- [ ] Aggregate multiple threat-intelligence providers with configurable refresh,
  scoring, provenance, and conflict handling.
- [ ] Import operator-supplied threat lists.
- [ ] Add historical, per-client query analysis and durable anomaly history.

## DNS protocol and security work

- [x] Validate DNSSEC positive answers and authenticated denial with NSEC/NSEC3.
- [x] Enforce DNSSEC algorithm policy and NSEC3 iteration limits.
- [x] Load configured static DNSSEC trust anchors.
- [ ] Implement RFC 5011 automatic trust-anchor maintenance and durable key-rollover
  state; configuration fields alone do not count as support.
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
- [ ] Add regex-based RPZ policy matching.
- [ ] Add per-client mTLS identities and authorization for DoT/DoH.
- [ ] Add JWT-based authorization where HTTP APIs require it.
- [ ] Add privacy-preserving, security-context audit logs and retention controls.
- [ ] Implement DNS over QUIC (RFC 9250); the experimental configuration stub is
  not an operational listener.
- [ ] Implement Oblivious DoH (RFC 9230).
- [ ] Add authenticated and confidential zone transfer over TLS/QUIC (RFC 9103).
- [ ] Add query-complexity controls, adaptive IP-reputation limits, and explicit
  TCP/SYN-flood deployment protections.
- [ ] Add forensic query replay and SOC 2/ISO 27001 reporting workflows.
- [ ] Add SIEM/SOAR export formats and integrations.

## Response Policy Zones

- [x] Implement the in-memory RPZ rule engine for exact/wildcard query-name rules,
  passthrough, NXDOMAIN, NODATA, drop, and rewrite actions.
- [ ] Wire RPZ loading and enforcement into the primary production server and its
  documented configuration path.
- [ ] Implement response-IP and other RFC-defined RPZ triggers.
- [ ] Add safe hot reload, precedence rules, source attribution, hit metrics, and
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
- [ ] Bring the experimental assembly-parser UDP server to feature and security
  parity before considering it for production; the primary UDP path remains the
  audited `miekg/dns` server.
- [ ] Replace linear eviction work under cache-shard locks with a measured
  low-contention policy; do not claim the cache is lock-free while it uses shard
  mutexes.
- [x] Add validated runtime controls and documentation for listener count, resolver
  concurrency, queue size, cache size/shards, and Go memory/GC limits.
- [x] Decide and document CPU-affinity support. Prefer service-manager/container
  affinity unless measurements justify per-worker OS-thread pinning.
- [ ] Add explicit forwarding/upstream modes so operators can choose direct
  iterative resolution, public recursive resolvers, or conditional forwarders
  without relying on ignored configuration.

## Catalog Zones (RFC 9432)

Catalog Zones are not currently implemented. The target is schema version 2 and
safe automatic provisioning for authoritative server fleets.

### Transfer prerequisites

- [x] Serve authoritative zones and support atomic zone add/remove operations.
- [x] Authenticate AXFR and DNS UPDATE with TSIG.
- [x] Serve AXFR and accept IXFR requests with documented AXFR fallback.
- [ ] Implement true IXFR delta generation and consumption.
- [ ] Implement ordinary SOA NOTIFY-driven secondary refresh; DSYNC NOTIFY support
  does not satisfy this prerequisite.

### Catalog data model and validation

- [ ] Add explicit catalog producer/consumer configuration, primary endpoints,
  TSIG/TLS credentials, refresh policy, and per-catalog group mappings.
- [ ] Parse and validate `version.<catalog> TXT "2"` exactly as RFC 9432 requires.
- [ ] Parse member nodes as one-PTR RRsets beneath
  `<unique>.zones.<catalog>` and reject duplicate member names or malformed sets.
- [ ] Parse optional `group.<unique>.zones.<catalog>` TXT properties.
- [ ] Parse the `coo.<unique>.zones.<catalog>` change-of-ownership property.
- [ ] Ignore unsupported records and properties while rejecting malformed known
  properties.
- [ ] Preserve and expose namespaced `*.ext` custom properties without assigning
  them unsafe default behavior.
- [ ] Validate SOA/NS presence, IN class, supported schema version, unique member
  labels, unique member zones, and serial arithmetic before applying a catalog.

### Consumer reconciliation

- [ ] Fetch catalog zones through authenticated AXFR/IXFR and refresh them after
  SOA NOTIFY or timer expiry.
- [ ] Compute a deterministic add/update/remove plan from the last valid catalog.
- [ ] Apply a valid catalog atomically so readers never observe a partial fleet.
- [ ] Automatically provision newly listed member zones using the catalog's group
  mapping and transfer policy.
- [ ] Remove a member and its associated state only when that same catalog created
  it; optionally archive state for recovery.
- [ ] Treat a changed member-node label as remove-and-recreate, including the
  RFC-required associated-state reset.
- [ ] Detect member-zone name clashes with static zones or other catalogs, retain
  the existing zone, and report the conflict.
- [ ] Implement controlled cross-catalog migration through `coo`, including the
  required confirmation in the destination catalog.
- [ ] Retain the last valid applied state when a catalog becomes malformed, stale,
  expired, or temporarily unreachable.
- [ ] Persist catalog ownership, member labels, serials, and the last valid plan so
  restart behavior is deterministic.

### Catalog safety and operations

- [ ] Require authenticated catalog transfers and authenticated DNS UPDATE by
  default; support confidential transfer using RFC 9103 when available.
- [ ] Restrict catalog queries and transfers with explicit ACLs.
- [ ] Scope admissible member names with allow/deny suffixes or regular expressions.
- [ ] Add limits for catalogs, members per catalog, reconciliation rate, transfer
  size, and simultaneous member provisioning.
- [ ] Reject recursive/self-referential ownership and provisioning cycles.
- [ ] Provide dry-run and approval modes for mass deletion or replacement.
- [ ] Add structured audit events for catalog receipt, validation, reconciliation,
  conflicts, migrations, and state resets.
- [ ] Add Prometheus metrics and admin status APIs for catalog freshness, serial,
  members, reconcile outcomes, and transfer failures.
- [ ] Add CLI/admin operations to list catalogs, members, effective group config,
  ownership, errors, and pending reconciliation.
- [ ] Add unit, race, fuzz, restart, malformed-catalog, and failure-injection tests.
- [ ] Add interoperability tests with at least BIND, Knot DNS, and PowerDNS catalog
  producers/consumers.
- [ ] Document configuration, migration, rollback, disaster recovery, and a complete
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
