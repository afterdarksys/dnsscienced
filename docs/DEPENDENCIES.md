# DNSScienced Dependencies & Library Choices

## Core Dependencies

### DNS Protocol

| Library | Purpose | Rationale |
|---------|---------|-----------|
| **Custom Implementation** | Wire protocol | Full control, optimized for our needs, no external dependency |
| `golang.org/x/net/dns/dnsmessage` | Reference | Use for validation/testing against Go standard |

**Decision**: Build custom DNS message handling for:
- Zero-allocation parsing where possible
- Custom compression handling
- Direct integration with our cache
- Support for obscure RFCs

### Cryptography

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `golang.org/x/crypto` | DNSSEC algorithms | Official Go crypto extensions |
| `golang.org/x/crypto/ed25519` | ED25519 signing | Modern DNSSEC algorithm |
| `golang.org/x/crypto/sha3` | SHA-3 for NSEC3 | Standard library |
| `crypto/ecdsa` | ECDSA P-256/P-384 | Go standard library |

**DNSSEC Algorithm Support Matrix**:

```
Algorithm         Library                      Status
─────────────────────────────────────────────────────────────
RSASHA256 (8)     crypto/rsa + crypto/sha256   Supported
RSASHA512 (10)    crypto/rsa + crypto/sha512   Supported
ECDSAP256 (13)    crypto/ecdsa + crypto/sha256 Supported (Recommended)
ECDSAP384 (14)    crypto/ecdsa + crypto/sha384 Supported
ED25519 (15)      golang.org/x/crypto/ed25519  Supported (Recommended)
ED448 (16)        golang.org/x/crypto/ed448    Supported
```

### Networking

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `net` | UDP/TCP | Go standard library |
| `crypto/tls` | TLS 1.3 | Go standard library (DoT) |
| `golang.org/x/net/http2` | HTTP/2 | DoH support |
| `github.com/quic-go/quic-go` | QUIC | DoQ support |

**QUIC Library Choice**:

```
Library               Pros                           Cons
─────────────────────────────────────────────────────────────────────────
quic-go               Most mature, widely used       Larger dependency
                      Active development
                      Good performance

lucas-clemente/quic   Original, well-tested          Deprecated, use quic-go

Custom                Full control                   Significant effort
                                                     Time to market
```

**Decision**: Use `quic-go` - it's the de-facto Go QUIC implementation with active maintenance.

### Configuration

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `github.com/spf13/viper` | Config loading | Multi-format, env vars, hot reload |
| `github.com/spf13/cobra` | CLI framework | Industry standard |
| `gopkg.in/yaml.v3` | YAML parsing | Viper dependency, zone files |

**Configuration Format Support**:

```yaml
# Native support via Viper
formats:
  - yaml      # Primary (dnsscienced.conf)
  - json      # API/programmatic
  - toml      # Alternative
  - env       # Environment variables
  - etcd      # Remote config (optional)
  - consul    # Remote config (optional)
```

### Caching

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `github.com/hashicorp/golang-lru/v2` | In-memory LRU | Battle-tested, generic |
| `github.com/redis/go-redis/v9` | Redis client | Official, full-featured |
| `github.com/dgraph-io/ristretto` | Alternative cache | Higher performance, more complex |

**Cache Backend Comparison**:

```
Backend           Throughput      Latency     Memory      Distribution
─────────────────────────────────────────────────────────────────────────
golang-lru        ~10M ops/s      <1μs        In-process  No
ristretto         ~20M ops/s      <1μs        In-process  No
Redis             ~100K ops/s     <1ms        External    Yes
Redis Cluster     ~500K ops/s     <1ms        External    Yes (sharded)
```

**Decision**:
- Default: `golang-lru` for simplicity
- High-volume: `ristretto` option
- Distributed: Redis for multi-instance deployments

### Metrics & Observability

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `github.com/prometheus/client_golang` | Prometheus metrics | Industry standard |
| `go.uber.org/zap` | Structured logging | High performance, structured |
| `go.opentelemetry.io/otel` | Tracing | OpenTelemetry standard |

**Metrics Exported**:

```prometheus
# Query metrics
dns_queries_total{type, class, rcode, transport}
dns_query_duration_seconds{type, quantile}
dns_response_size_bytes{type, quantile}

# Cache metrics
dns_cache_hits_total
dns_cache_misses_total
dns_cache_size_bytes
dns_cache_evictions_total

# DNSSEC metrics
dns_dnssec_validations_total{result}
dns_dnssec_signatures_total{algorithm}

# Security metrics
dns_rate_limit_drops_total{reason}
dns_blocked_queries_total{category}
```

### Web3 / Blockchain

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `github.com/ethereum/go-ethereum` | Ethereum RPC | Official Go-Ethereum |
| `github.com/wealdtech/go-ens/v3` | ENS resolution | Purpose-built for ENS |
| `github.com/gagliardetto/solana-go` | Solana RPC | Most complete Solana Go lib |

**Blockchain Library Evaluation**:

```
Ethereum Libraries:
─────────────────────────────────────────────────────────────────────────
go-ethereum           Official, comprehensive         Large dependency
ethclient             Subset of go-ethereum          Smaller footprint
go-ens                ENS-specific                   Depends on go-ethereum

Decision: go-ethereum + go-ens (comprehensive ENS support)

Solana Libraries:
─────────────────────────────────────────────────────────────────────────
solana-go             Most complete, active          Learning curve
portto/solana-go-sdk  Simpler API                    Less features

Decision: gagliardetto/solana-go (better maintained, more complete)

Polygon/EVM Libraries:
─────────────────────────────────────────────────────────────────────────
Use go-ethereum with different RPC endpoint - same API
```

### AI/ML Inference

| Library | Purpose | Rationale |
|---------|---------|-----------|
| `github.com/yalue/onnxruntime_go` | ONNX inference | Cross-platform, Go bindings |
| Custom gRPC client | Remote inference | For GPU/cloud inference |

**ML Inference Options**:

```
Option              Latency     Accuracy    Complexity    GPU
─────────────────────────────────────────────────────────────────────────
ONNX Runtime        <1ms        Full        Medium        Optional
TensorFlow Lite     <1ms        Limited     High          No
gRPC to Python      5-50ms      Full        Low           Yes
Cloud API           50-200ms    Full        Low           N/A
```

**Decision**:
- Embedded: ONNX Runtime for real-time inference
- Sidecar: gRPC to Python service for complex models
- Cloud: API fallback for deep analysis

---

## Dependency Tree

```
github.com/afterdarksys/dnsscienced
├── golang.org/x/crypto             (DNSSEC, TLS)
├── golang.org/x/net                (HTTP/2, DNS utils)
├── golang.org/x/sync               (Concurrency)
│
├── github.com/quic-go/quic-go      (DoQ)
│   └── golang.org/x/crypto
│   └── golang.org/x/net
│
├── github.com/spf13/viper          (Config)
│   └── github.com/spf13/pflag
│   └── gopkg.in/yaml.v3
│   └── github.com/pelletier/go-toml
│
├── github.com/spf13/cobra          (CLI)
│   └── github.com/spf13/pflag
│
├── github.com/hashicorp/golang-lru (Cache)
│
├── github.com/redis/go-redis/v9    (Redis)
│   └── github.com/cespare/xxhash
│
├── github.com/prometheus/client_golang (Metrics)
│   └── github.com/prometheus/common
│   └── github.com/prometheus/procfs
│
├── go.uber.org/zap                 (Logging)
│   └── go.uber.org/multierr
│   └── go.uber.org/atomic
│
├── github.com/ethereum/go-ethereum (Ethereum)
│   └── (many transitive deps)
│
├── github.com/wealdtech/go-ens/v3  (ENS)
│   └── github.com/ethereum/go-ethereum
│
├── github.com/gagliardetto/solana-go (Solana)
│   └── github.com/gagliardetto/binary
│   └── github.com/mr-tron/base58
│
└── github.com/yalue/onnxruntime_go (ML inference)
```

---

## Build Constraints

### Minimum Go Version

```go
// go.mod
go 1.22
```

**Rationale**: Go 1.22+ required for:
- Improved generics
- Enhanced crypto support
- Better HTTP/2 performance
- Range-over-func (for iterators)

### Build Tags

```go
// +build linux darwin freebsd
// +build amd64 arm64

// Optional features via build tags:
// +build dpdk      - DPDK support for ultra-low latency
// +build cgo       - Required for some crypto backends
// +build !nocgo    - Can build without cgo for portability
```

### CGO Dependencies

```
Feature                CGO Required    Notes
─────────────────────────────────────────────────────────────────────────
Basic DNS              No              Pure Go
DNSSEC (most algs)     No              Pure Go
ED448                  Optional        Faster with CGO
ONNX Runtime           Yes             C++ library
DPDK                   Yes             C library
```

**Decision**: Support both CGO and pure-Go builds:
- Default: Pure Go (maximum portability)
- Optional: CGO for performance-critical deployments

---

## Version Pinning Strategy

### Semantic Versioning

```
Dependency Type         Version Strategy
─────────────────────────────────────────────────────────────────────────
Standard library        Go version pin (go 1.22)
golang.org/x/*          Latest compatible
Critical (crypto)       Exact pin, audit updates
Networking (quic-go)    Minor version pin (v0.41.x)
Web3 (go-ethereum)      Minor version pin (v1.13.x)
Utilities               Floating (latest minor)
```

### Security Updates

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
    groups:
      security:
        patterns:
          - "golang.org/x/crypto*"
          - "crypto/*"
        update-types:
          - "patch"
          - "minor"
    reviewers:
      - security-team
```

---

## Alternatives Considered

### DNS Libraries

| Library | Considered | Decision |
|---------|------------|----------|
| `miekg/dns` | Yes | Too opinionated, different architecture |
| `coredns` | Yes | Full server, not library-focused |
| Custom | Yes | **Selected** - full control |

### Web Framework (REST API)

| Library | Considered | Decision |
|---------|------------|----------|
| `net/http` | Yes | **Selected** - standard library |
| `gin` | Yes | Overkill for simple API |
| `echo` | Yes | Unnecessary dependency |
| `fiber` | No | Different paradigm |

### Database (Zone Storage)

| Library | Considered | Decision |
|---------|------------|----------|
| Files | Yes | **Selected** - primary |
| SQLite | Yes | Optional backend |
| PostgreSQL | Yes | Optional backend |
| etcd | Yes | Cluster coordination |

---

## License Compliance

```
Dependency                      License         Compatible
─────────────────────────────────────────────────────────────────────────
golang.org/x/*                  BSD-3           Yes
github.com/quic-go/quic-go      MIT             Yes
github.com/spf13/viper          MIT             Yes
github.com/spf13/cobra          Apache-2.0      Yes
github.com/hashicorp/golang-lru MPL-2.0         Yes
github.com/redis/go-redis       BSD-2           Yes
github.com/prometheus/*         Apache-2.0      Yes
go.uber.org/zap                 MIT             Yes
github.com/ethereum/go-ethereum LGPL-3.0        Caution (linking)
github.com/wealdtech/go-ens     Apache-2.0      Yes
github.com/gagliardetto/solana  Apache-2.0      Yes
github.com/yalue/onnxruntime_go MIT             Yes
```

**Note on go-ethereum**: LGPL-3.0 requires careful handling:
- Dynamic linking preferred
- Modifications must be open-sourced
- Our code can remain proprietary if properly separated

---

*Document Version: 1.0*
*Dependency Specification*
