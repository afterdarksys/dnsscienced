# DNSScienced

**High-Performance DNS Server with Modern Security**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

DNSScienced is a production-ready DNS server written in Go, providing both **recursive** and **authoritative** DNS services with state-of-the-art security features.

## Status

🚀 **Phase 3 Complete** - Production-ready DNS server with recursive resolver, authoritative server, and zone management.

**What Works Now:**
- ✅ Recursive DNS resolver with caching (568k+ qps)
- ✅ Authoritative DNS server with zone loading
- ✅ Response Rate Limiting (RRL) for DDoS protection
- ✅ DNS Cookies (RFC 7873/9018) with SipHash-2-4
- ✅ Modern .dnszone YAML format + BIND compatibility
- ✅ Compiled zones (.dzc) for 2-5x faster loading
- ✅ SO_REUSEPORT multi-listener architecture
- ✅ Zero-allocation buffer pooling
- ✅ Crypto-secure randomization
- ⚡ **Experimental**: IETF draft protocols (DNS-SD, DoQ, DSO, DELEG, DID, IoT DNS)

## Quick Start

### Build from Source

```bash
# Clone repository
git clone https://github.com/dnsscience/dnsscienced.git
cd dnsscienced

# Build
go build -o dnsscienced ./cmd/dnsscienced/

# Run recursive resolver
sudo ./dnsscienced -recursive
```

### Basic Usage

```bash
# Recursive resolver only
./dnsscienced -recursive

# Authoritative server with zone
./dnsscienced -zone example.com.dnszone -authoritative

# Both modes
./dnsscienced -zone example.com.dnszone -recursive -authoritative

# Custom listeners
./dnsscienced -udp :5353 -tcp :5353 -listeners 8
```

### Test it

```bash
# Query recursive resolver
dig @127.0.0.1 google.com

# Query authoritative zone
dig @127.0.0.1 www.example.com
```

### Compile Zones for Performance

Compile zone files to binary format for 2-5x faster loading:

```bash
# Build compiler tool
go build -o dnsscienced-compile ./cmd/dnsscienced-compile/

# Compile a zone file
./dnsscienced-compile -input example.com.dnszone

# Server automatically uses .dzc if available
./dnsscienced -zone example.com.dnszone -authoritative
```

See [Compiled Zones Documentation](docs/COMPILED_ZONES.md) for details.

## Features

### Core DNS

- **Recursive Resolver** - Full iterative resolution from root servers
- **Authoritative Server** - Zone hosting with comprehensive validation
- **Caching** - 256-shard concurrent cache with serve-stale support
- **SO_REUSEPORT** - Multi-listener architecture for linear CPU scaling
- **Buffer Pooling** - Zero-allocation design with sync.Pool

### Security

- **Response Rate Limiting (RRL)** - Token bucket algorithm per client/query/response
- **DNS Cookies** - RFC 7873/9018 with SipHash-2-4 HMAC
- **Source Port Randomization** - Crypto-secure (30.8 bits entropy)
- **Compression Bomb Protection** - CVE-2024-8508 mitigation
- **Query Validation** - RFC compliance checks

### Zone Management

- **Modern .dnszone Format** - Human-readable YAML syntax
- **BIND Compatibility** - Full RFC 1035 zone file support
- **Compiled Zones (.dzc)** - Binary format with 2-5x faster loading
- **Bidirectional Conversion** - Convert between formats
- **Comprehensive Validation** - SOA, NS, glue, CNAME conflict checks
- **Wildcard Support** - *.example.com matching
- **Auto-serial** - Automatic YYYYMMDD00 serial generation

### Experimental Features (IETF Drafts)

- **DNS-SD SRP (RFC 9665)** - Service registration for IoT devices
- **DNS over QUIC (RFC 9250)** - Modern encrypted transport with 0-RTT
- **DSO (RFC 8490)** - Stateful operations with push notifications
- **DELEG (draft)** - Extensible delegation records
- **DNS DID (draft)** - Decentralized identifiers
- **IoT DNS (draft)** - Optimizations for constrained devices

See [Experimental Features Documentation](docs/EXPERIMENTAL_FEATURES.md) for details.

## Performance

**Benchmarks** (Intel i9-9880H @ 2.30GHz):

| Component | Performance | Notes |
|-----------|-------------|-------|
| DNS Packet Parse | 303 ns/op | CVE-2024-8508 protected |
| DNS Cookie Gen | 214 ns/op | SipHash-2-4 |
| Zone Load (text) | 229 µs | .dnszone YAML format |
| Zone Load (compiled) | 104 µs | .dzc binary format (2.2x faster) |
| Buffer Pool | 38 ns/op | 26M ops/sec |
| Worker Submit | 193 ns/op | 5.2M jobs/sec |
| Recursive Resolve | 1,761 ns/op | 568k qps (cache hit) |
| Zone Parse (.dnszone) | 254 μs/op | 4,000 zones/sec |
| Zone Parse (BIND) | 206 μs/op | 4,900 zones/sec |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    DNSScienced Server                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐           ┌──────────────┐           │
│  │   Recursive  │           │ Authoritative│           │
│  │   Resolver   │           │    Server    │           │
│  │              │           │              │           │
│  │  • Cache     │           │  • Zones     │           │
│  │  • Workers   │           │  • Wildcard  │           │
│  │  • Iterative │           │  • DNSSEC    │           │
│  └──────┬───────┘           └──────┬───────┘           │
│         │                          │                    │
│         └──────────┬───────────────┘                    │
│                    │                                     │
│         ┌──────────▼──────────┐                         │
│         │  Security Layer     │                         │
│         │  • RRL              │                         │
│         │  • DNS Cookies      │                         │
│         │  • Validation       │                         │
│         └──────────┬──────────┘                         │
│                    │                                     │
│         ┌──────────▼──────────┐                         │
│         │  Network Layer      │                         │
│         │  • SO_REUSEPORT     │                         │
│         │  • 16 UDP listeners │                         │
│         │  • Buffer pooling   │                         │
│         └─────────────────────┘                         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Zone File Format

### Modern .dnszone Format

```yaml
zone:
  name: example.com
  ttl: 1h
  class: IN

soa:
  primary_ns: ns1.example.com
  contact: admin@example.com
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
    AAAA: 2001:db8::1
    MX:
      - priority: 10
        target: mail.example.com

  www:
    A:
      - 192.0.2.10
      - 192.0.2.11
    AAAA: 2001:db8::10

  "*":
    A: 192.0.2.100
```

### BIND Format (Compatible)

Standard RFC 1035 zone files work directly:

```
$ORIGIN example.com.
$TTL 3600

@  IN  SOA  ns1.example.com. admin.example.com. (
           2024010100  ; Serial
           7200        ; Refresh
           3600        ; Retry
           1209600     ; Expire
           3600 )      ; Negative TTL

   IN  NS   ns1.example.com.
   IN  NS   ns2.example.com.

@  IN  A    192.0.2.1
www IN A    192.0.2.10
```

## Configuration

### Command Line Flags

```
-udp string
    UDP listen address (default ":53")

-tcp string
    TCP listen address (default ":53")

-listeners int
    Number of UDP listeners with SO_REUSEPORT (default: NumCPU)

-recursive
    Enable recursive resolver (default: true)

-authoritative
    Enable authoritative server (default: false)

-zone string
    Zone file to load

-format string
    Zone file format: dnszone or bind (default: "dnszone")

-stats
    Print statistics periodically (default: true)
```

## Implementation Details

### SO_REUSEPORT Multi-Listener

The server creates multiple UDP listeners (default: one per CPU core) all bound to the same port. The kernel distributes incoming packets evenly across listeners for near-linear scaling.

```go
// Each listener runs in separate goroutine
for i := 0; i < numCPU; i++ {
    server := &dns.Server{
        Addr: ":53",
        Net: "udp",
        ReusePort: true,  // SO_REUSEPORT
    }
    go server.ListenAndServe()
}
```

### Security Components

**Response Rate Limiting:**
- Token bucket per (client-IP, query-type, response-category)
- Configurable limits per category (response, error, NXDOMAIN)
- Slip algorithm: 1 in N get TC bit, rest dropped
- Exempt prefixes for trusted clients

**DNS Cookies:**
- Client cookie: 8 bytes random
- Server cookie: SipHash-2-4(client-cookie || client-IP || timestamp)
- Validates client identity and prevents forgery
- BIND 9 compatible implementation

**Source Port Randomization:**
- Crypto-secure random txid (16 bits)
- Random source port from high ephemeral range (14.8 bits)
- Combined: 30.8 bits entropy (requires ~37k queries for 50% collision)

## Development Status

### Completed (Phase 1-3)

- ✅ DNS packet parser with security hardening
- ✅ 256-shard concurrent cache
- ✅ DNS cookies (RFC 7873/9018)
- ✅ Worker pool for bounded concurrency
- ✅ Crypto-secure randomization
- ✅ Zero-allocation buffer pooling
- ✅ Response Rate Limiting
- ✅ Recursive resolver with iterative resolution
- ✅ Zone file parser (.dnszone + BIND)
- ✅ Authoritative server with validation
- ✅ SO_REUSEPORT multi-listener architecture

### Roadmap

**Phase 4 - Performance & Scale:**
- [ ] Benchmark suite
- [ ] Profile-guided optimization
- [ ] Reduce allocations (<5 per query)
- [ ] Target: 1M+ queries/second

**Phase 5 - Modern Transports:**
- [ ] DNS over TLS (DoT) - RFC 7858
- [ ] DNS over HTTPS (DoH) - RFC 8484
- [ ] DNS over QUIC (DoQ) - RFC 9250

**Phase 6 - Management:**
- [ ] gRPC management API
- [ ] Runtime configuration reload
- [ ] Metrics export (Prometheus)
- [ ] Health checks

**Phase 7 - DNSSEC:**
- [ ] Zone signing
- [ ] Validation chain
- [ ] Key management
- [ ] Algorithm support (ECDSAP256SHA256, ED25519)

## Testing

```bash
# Run all tests
go test ./internal/...

# Run with benchmarks
go test -bench=. -benchmem ./internal/...

# Run specific package
go test -v ./internal/resolver/...

# Fuzzing
go test -fuzz=FuzzParser ./internal/packet/
```

**Test Coverage:**
- 85+ tests across all packages
- Comprehensive edge case coverage
- Fuzzing for packet parser
- Benchmark suite for performance tracking

## Contributing

This is an active development project. Contributions welcome!

## License

Apache License 2.0

---

**Built with Go** • Designed for performance and security
