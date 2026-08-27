# DNSScienced

**A security-oriented authoritative DNS server and recursive resolver written in Go.**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DNSScienced combines authoritative service, recursive resolution, DNSSEC
validation, policy enforcement, protected zone operations, and an authenticated
management plane in one codebase. It is designed for operators who need to
understand and control DNS behavior under failure, attack, and change—not only
answer ordinary queries.

The project is under active development. Its implemented surface is substantial
and its automated suite is green, but feature claims in this README distinguish
implemented behavior, measured results, and experimental work.

## What is implemented

### Authoritative DNS

- Authoritative UDP and TCP service with EDNS(0).
- Native `.dnszone` YAML and BIND-style zone-file loading.
- Compiled `.dzc` zones and bidirectional format conversion.
- Wildcards, delegations, referrals, in-bailiwick glue, negative answers, and
  modern record types.
- AXFR and IXFR, including strict TLS transport for zone transfers.
- Primary NOTIFY and secondary-zone management.
- RFC 2136 dynamic updates with TSIG, per-zone ACLs, replay handling, atomic
  mutation, and optional durable persistence.
- Catalog-zone reconciliation with limits, approvals, audit events, and admin
  inspection.
- Serving of pre-signed DNSSEC records and authoritative DNSSEC response logic.

Authoritative online zone signing is **not** implemented. Configuration that
requests it is rejected instead of silently running without signing.

### Recursive DNS

- Iterative resolution from root hints.
- Sharded caching, negative caching, request coalescing, prefetch, and
  serve-stale behavior.
- QNAME minimization, 0x20 case randomization, UDP-to-TCP retry, bounded worker
  routing, hedged authority queries, and conditional forwarding modes.
- DNSSEC chain validation, bogus-result caching, aggressive NSEC/NSEC3 use, and
  durable RFC 5011 trust-anchor state.
- RPZ enforcement on query names, client IPs, response IPs, and nameserver
  names.

### Security and policy

- Response Rate Limiting and query-complexity limits.
- RFC 7873/9018 DNS Cookies using SipHash-2-4.
- Cryptographic transaction-ID and source-port randomization.
- Compression-loop/bomb defenses and malformed-query validation.
- Bounded TCP resources, UDP receive batching on Linux, and pooled buffers.
- TSIG request and response authentication with truncation and replay defenses.
- DNS firewall policy with static rules, threat feeds, customer context, and
  sandboxed Starlark hooks.
- Optional kernel/XDP work for high-rate filtering; this path is advanced and
  platform-specific rather than part of the portable baseline.

### Operations

- Authenticated gRPC administration using API key **and** mTLS identity.
- Runtime zone and record management, cache operations, rate-limit controls,
  connection inspection, audit logging, and metrics.
- Prometheus instrumentation, structured logging, health endpoints, role
  profiles, SIGHUP reload, and deployment/runbook documentation.
- DoT and DoH listeners. DoQ and other draft-oriented work remain experimental.

## Evidence

The primary verification command is:

```sh
go test ./...
```

As of 2026-08-08, the full repository suite passes on macOS with Go 1.26.5. The
repository currently contains more than 100 Go test files spanning unit,
protocol, integration, race-sensitive, fuzz, and benchmark coverage.

The authoritative differential suite builds pinned versions of DNSScienced,
BIND, and NSD, sends an identical query corpus to all three, normalizes only
wire-irrelevant differences, and compares DNS semantics:

```sh
tests/differential/run.sh
```

It currently covers 14 cases across UDP, TCP, EDNS(0), apex data, A/AAAA,
CNAME, MX, TXT, CAA, wildcards, NODATA, NXDOMAIN, delegation referrals, and
glue. See [Differential Conformance](docs/DIFFERENTIAL_CONFORMANCE.md) for its
scope and exclusions.

### What “compares with BIND and NSD” means

DNSScienced is directly comparable to BIND and NSD for the authoritative
semantics exercised by the differential suite. It also implements operational
features—including recursive service, programmable policy, RPZ, authenticated
administration, catalog operations, and protected dynamic updates—that extend
beyond NSD's intentionally narrow role.

That does **not** imply equivalent protocol breadth, platform coverage,
independent review, deployment population, or decades of production history.
BIND and NSD remain the references. DNSScienced treats compatibility as an
executable claim that should expand case by case.

## Quick start

Requires Go 1.25 or newer.

```sh
git clone https://github.com/afterdarksys/dnsscienced.git
cd dnsscienced
go build -o dnsscienced ./cmd/dnsscienced
```

Run a recursive resolver on the default development port:

```sh
./dnsscienced -recursive
dig @127.0.0.1 -p 5353 example.com A
```

Run an authoritative zone:

```sh
./dnsscienced \
  -recursive=false \
  -authoritative \
  -zone internal/zone/testdata/example.com.dnszone
```

Run from a production-style configuration:

```sh
./dnsscienced -config config.production.yaml
```

The command-line default is port `5353`, which avoids requiring privileged bind
access during development. Review the example configuration, access controls,
TSIG material, TLS identities, and deployment guide before exposing a server.

## Zone formats

The native format is intended to be readable and mechanically validated:

```yaml
zone:
  name: example.com
  ttl: 1h
  class: IN

soa:
  primary_ns: ns1.example.com
  contact: hostmaster@example.com
  serial: auto
  refresh: 2h
  retry: 1h
  expire: 2w
  negative_ttl: 1h

records:
  "@":
    NS:
      - ns1.example.com
      - ns2.example.com
    A: 192.0.2.1
  www:
    A:
      - 192.0.2.10
      - 192.0.2.11
```

Standard BIND zone files are also accepted. A zone may be compiled to `.dzc`
for faster and deterministic loading:

```sh
go build -o dnsscienced-compile ./cmd/dnsscienced-compile
./dnsscienced-compile -input example.com.dnszone
```

See [Compiled Zones](docs/COMPILED_ZONES.md) and the zone-related sections of
the [API Specifications](docs/API_SPECIFICATIONS.md).

## Performance

The repository includes microbenchmarks for packet handling, cookies, buffers,
workers, cache hits, zone parsing/compilation, DNSASM, and response writes.
End-to-end and comparative network testing is performed with
[DNSBlast](https://github.com/afterdarksys/dnsblast), a purpose-built Rust load
generator maintained alongside DNSScienced. DNSBlast gives every target an
independent concurrency pool, releases measured traffic through a shared start
barrier, supports UDP and persistent TCP workers, excludes warmup traffic, and
reports parsed-response QPS plus bounded HDR latency distributions.

Historical measurements on an Intel i9-9880H include a 1,761 ns/op recursive
cache-hit microbenchmark (approximately 568k operations/second) and a 2.2x load
improvement for the tested compiled-zone fixture. Separately, DNSScienced has
been exercised at high end-to-end QPS using the specialized DNSBlast tooling.
The earlier raw result artifact, exact hardware profile, and command line are
not currently committed, so this README does not manufacture an exact release
number from memory. Future published results should retain DNSBlast's JSON
output with the DNSScienced and DNSBlast commits, configuration, traffic
profile, hardware, kernel, latency distribution, loss rate, and CPU/NIC data.

```sh
go test -run '^$' -bench=. -benchmem ./internal/...
go run ./tools/bench_throughput.go \
  -target 127.0.0.1:5353 \
  -workers 32 \
  -domain example.com. \
  -duration 30s
```

For controlled multi-server comparison, build DNSBlast in release mode and run
the same deterministic workload against equivalent DNSScienced, BIND, and NSD
targets:

```sh
git clone https://github.com/afterdarksys/dnsblast.git
cd dnsblast
cargo build --release

./target/release/dnsblast \
  --server dnsscienced=192.0.2.10 \
  --server bind=192.0.2.11 \
  --server nsd=192.0.2.12 \
  --names-file names.txt \
  --type A,AAAA,MX,NS,SOA \
  --duration 60s \
  --warmup 10000 \
  --concurrency 512 \
  --workers 8 \
  --output json \
  --output-file dns-comparison.json
```

See [Benchmarks](docs/BENCHMARKS.md) and
[Performance Tuning](docs/PERFORMANCE_TUNING.md).

## Architecture

```text
                         +----------------------+
UDP / TCP / DoT / DoH -->| network + protection |
                         +----------+-----------+
                                    |
                     +--------------+--------------+
                     |                             |
             +-------v--------+            +-------v--------+
             | authoritative  |            | recursive      |
             | zones/transfers|            | resolver/cache |
             +-------+--------+            +-------+--------+
                     |                             |
                     +--------------+--------------+
                                    |
                         +----------v-----------+
                         | policy / RPZ / DNSSEC|
                         +----------+-----------+
                                    |
                         +----------v-----------+
                         | gRPC admin / metrics |
                         +----------------------+
```

The server uses `miekg/dns` for standards-oriented DNS message and transport
primitives while implementing its own resolver, zone lifecycle, security,
policy, administrative, and operational layers. Optional DNSASM and Linux
receive-batching paths target hot-path performance without replacing the
portable implementation.

See [Design](DESIGN.md), [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md),
[Security](SECURITY.md), and [Implementation Roadmap](ROADMAP.md).

## Documentation map

- [Quick Start](docs/QUICKSTART.md)
- [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)
- [Deployment Operations](docs/DEPLOYMENT_OPERATIONS.md)
- [Carrier-Grade Roles](docs/CARRIER_GRADE_ROLES.md)
- [Views](docs/VIEWS.md)
- [Secondary Zones](docs/SECONDARY_ZONES.md)
- [Catalog Zones](docs/CATALOG_ZONES.md)
- [Dynamic Updates](docs/DYNAMIC_UPDATES.md)
- [Resolver and Forwarding](docs/RESOLVER_FORWARDING.md)
- [RPZ](docs/RPZ.md)
- [RFC 5011 Trust Anchors](docs/RFC5011_TRUST_ANCHORS.md)
- [Observability](docs/OBSERVABILITY.md)
- [Admin CLI](docs/ADMIN_CLI.md)
- [Testing Strategy](docs/TESTING_STRATEGY.md)
- [Differential Conformance](docs/DIFFERENTIAL_CONFORMANCE.md)
- [Experimental Features](docs/EXPERIMENTAL_FEATURES.md)

## Development

```sh
# Full suite
go test ./...

# Race detector
go test -race ./...

# Benchmarks
go test -run '^$' -bench=. -benchmem ./internal/...

# One fuzz target example
go test -fuzz=FuzzParser ./internal/packet

# BIND/NSD authoritative comparison
tests/differential/run.sh
```

## Project status

The implemented code is materially ahead of several historical planning files
retained in Git history. The root [Roadmap](ROADMAP.md) describes current work;
`.planning/` contains milestone records and audits, including findings that may
describe the repository at an earlier commit.

Before calling a capability absent or complete, verify current source, tests,
and the latest commit rather than relying on a superseded milestone audit.

## License

MIT License. Copyright (c) 2026 After Dark Systems. See [LICENSE](LICENSE).
