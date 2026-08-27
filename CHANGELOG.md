# Changelog

> **Maintenance note:** The original `Unreleased` section below documents the
> early Phase 1–3 baseline and historical microbenchmarks. It is not a complete
> list of capabilities at the current `main` branch. Tagged v1.1/v1.2 history,
> `.planning/MILESTONES.md`, the Git log, and the current [README](README.md)
> provide the later implementation record. A future release should consolidate
> those sources into versioned release notes.

All notable changes to DNSScienced will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Core Infrastructure (Phase 1):**
- DNS packet parser with CVE-2024-8508 protection (compression bomb mitigation)
- 256-shard concurrent cache with lock-free atomic counters
- DNS Cookies implementation (RFC 7873/9018) with SipHash-2-4
- Worker pool with bounded goroutines (prevents exhaustion attacks)
- Crypto-secure source port and transaction ID randomization (30.8 bits entropy)
- Zero-allocation buffer pooling using sync.Pool
- Response Rate Limiting (RRL) with token bucket algorithm

**Recursive Resolver (Phase 2):**
- Full iterative DNS resolution starting from 13 root servers
- Cache integration with serve-stale support
- Follows NS referrals with glue record support
- Handles NXDOMAIN, NODATA, and error responses
- Automatic TTL extraction and caching
- Performance: 568k queries/second (cache hit), 1,761 ns/op

**Zone Management (Phase 3):**
- Modern .dnszone YAML format parser
- BIND zone file compatibility (RFC 1035)
- Bidirectional format conversion (BIND ↔ .dnszone)
- Comprehensive zone validation (SOA, NS, glue, CNAME conflicts)
- Wildcard record support (*.example.com)
- Auto-generated serials (YYYYMMDD00 format)
- Zone parsing: 4,000 zones/sec (.dnszone), 4,900 zones/sec (BIND)

**Production Server (Phase 3):**
- SO_REUSEPORT multi-listener architecture (16 UDP listeners)
- Dual-mode operation (recursive + authoritative)
- Real-time statistics (queries, cache hits, RRL)
- Graceful shutdown with signal handling
- UDP buffer tuning (8MB default)
- Configurable listeners per CPU core

### Performance Benchmarks

All benchmarks on Intel i9-9880H @ 2.30GHz:

| Component | Performance | Notes |
|-----------|-------------|-------|
| DNS Packet Parse | 303 ns/op | 224 B/op, 6 allocs/op |
| DNS Cookie Gen | 214 ns/op | Zero allocations |
| DNS Cookie Validate | 424 ns/op | Constant-time |
| Buffer Pool Get/Put | 38 ns/op | 26M ops/sec |
| Worker Submit | 193 ns/op | 5.2M jobs/sec |
| Recursive Resolve (cache hit) | 1,761 ns/op | 568k qps |
| Zone Parse (.dnszone) | 254 μs/op | 59 KB/op |
| Zone Parse (BIND) | 206 μs/op | 14 KB/op |
| BIND Export | 26 μs/op | 7 KB/op |

### Security

- **CVE-2024-8508**: Compression bomb protection with 20-hop limit
- **Cache Poisoning**: 30.8 bits entropy (txid + source port randomization)
- **DDoS Protection**: RRL token bucket, DNS cookies, bounded workers
- **Query Validation**: RFC compliance checks, malformed packet rejection

### RFC Compliance

Implemented RFCs:
- RFC 1034/1035 - DNS core protocol
- RFC 7873 - DNS Cookies (client)
- RFC 9018 - DNS Cookies (server)
- RFC 8767 - Serve stale (partial)
- RFC 2181 - DNS clarifications

### Tests

- 85+ comprehensive tests across all packages
- Fuzzing for packet parser
- Benchmark suite for performance regression tracking
- Edge case coverage for security scenarios

## [0.1.0] - Initial Development

### Project Structure

- Established Go module structure
- Created internal package organization
- Set up build system
- Documented architecture in DESIGN.md
- Created 12-phase roadmap to v1.0

---

## Release Notes Format

Future releases will follow this structure:

### [X.Y.Z] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes to existing functionality

#### Deprecated
- Soon-to-be removed features

#### Removed
- Now removed features

#### Fixed
- Bug fixes

#### Security
- Security fixes and improvements

---

[Unreleased]: https://github.com/afterdarksys/dnsscienced/compare/HEAD
