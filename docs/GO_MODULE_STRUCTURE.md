# DNSScienced Go Module Structure

## Repository Layout

```
github.com/afterdarksys/dnsscienced/
├── cmd/                              # Command-line applications
│   ├── dnsscience-authd/            # Authoritative DNS server
│   │   └── main.go
│   ├── dnsscience-cached/           # Recursive resolver
│   │   └── main.go
│   ├── dnsscience-ctl/              # Control utility
│   │   └── main.go
│   ├── dnsscience-checkzone/        # Zone file validator
│   │   └── main.go
│   ├── dnsscience-convert/          # Zone file converter
│   │   └── main.go
│   ├── dnsscience-keygen/           # DNSSEC key generator
│   │   └── main.go
│   ├── dnsscience-signzone/         # Zone signer
│   │   └── main.go
│   └── dnsscience-dig/              # Enhanced dig
│       └── main.go
│
├── pkg/                              # Public packages (importable)
│   ├── dns/                         # Core DNS library
│   │   ├── message.go              # DNS message handling
│   │   ├── parser.go               # Wire format parser
│   │   ├── builder.go              # Message builder
│   │   ├── compression.go          # Name compression
│   │   ├── types.go                # Record types
│   │   ├── edns.go                 # EDNS(0) support
│   │   ├── tsig.go                 # TSIG authentication
│   │   └── cookie.go               # DNS cookies
│   │
│   ├── zone/                        # Zone file handling
│   │   ├── parser.go               # Multi-format parser
│   │   ├── bind.go                 # BIND format
│   │   ├── djbdns.go               # djbdns format
│   │   ├── dnszone.go              # Native format
│   │   ├── validator.go            # Zone validation
│   │   └── converter.go            # Format conversion
│   │
│   ├── dnssec/                      # DNSSEC implementation
│   │   ├── signer.go               # Zone signing
│   │   ├── validator.go            # Signature validation
│   │   ├── keygen.go               # Key generation
│   │   ├── nsec.go                 # NSEC/NSEC3
│   │   └── algorithms.go           # Crypto algorithms
│   │
│   ├── resolver/                    # Recursive resolution
│   │   ├── resolver.go             # Main resolver
│   │   ├── cache.go                # Caching layer
│   │   ├── priming.go              # Root priming
│   │   ├── qmin.go                 # Query minimization
│   │   └── validator.go            # DNSSEC validation
│   │
│   ├── server/                      # Server components
│   │   ├── udp.go                  # UDP listener
│   │   ├── tcp.go                  # TCP listener
│   │   ├── dot.go                  # DNS over TLS
│   │   ├── doh.go                  # DNS over HTTPS
│   │   ├── doq.go                  # DNS over QUIC
│   │   └── handler.go              # Request handler
│   │
│   └── config/                      # Configuration parsing
│       ├── parser.go               # Config file parser
│       ├── types.go                # Config types
│       └── defaults.go             # Default values
│
├── internal/                         # Private packages
│   ├── auth/                        # Authoritative server internals
│   │   ├── engine.go               # Query engine
│   │   ├── zonedb.go               # Zone database
│   │   ├── transfer.go             # Zone transfers
│   │   ├── notify.go               # NOTIFY handling
│   │   ├── update.go               # Dynamic updates
│   │   └── catalog.go              # Catalog zones
│   │
│   ├── cache/                       # Recursive cache internals
│   │   ├── memory.go               # In-memory cache
│   │   ├── redis.go                # Redis backend
│   │   ├── stale.go                # Serve stale
│   │   └── prefetch.go             # Prefetching
│   │
│   ├── security/                    # Security internals
│   │   ├── rrl.go                  # Response rate limiting
│   │   ├── ddos.go                 # DDoS detection
│   │   ├── acl.go                  # Access control
│   │   └── rpz.go                  # Response Policy Zones
│   │
│   ├── metrics/                     # Metrics collection
│   │   ├── prometheus.go           # Prometheus exporter
│   │   ├── statsd.go               # StatsD exporter
│   │   └── counters.go             # Internal counters
│   │
│   ├── logging/                     # Logging internals
│   │   ├── logger.go               # Structured logging
│   │   ├── query.go                # Query logging
│   │   └── formats.go              # Log formats
│   │
│   └── control/                     # Control interface
│       ├── socket.go               # Unix socket
│       ├── commands.go             # Control commands
│       └── reload.go               # Hot reload
│
├── plugins/                          # Plugin implementations
│   ├── interface.go                 # Plugin interface
│   ├── manager.go                   # Plugin manager
│   │
│   ├── dip/                         # DNS Intelligence Platform
│   │   ├── plugin.go               # Main plugin
│   │   ├── sampling.go             # Traffic sampling
│   │   ├── ai.go                   # AI/ML engine
│   │   ├── feeds.go                # Threat feeds
│   │   ├── routing.go              # Intelligent routing
│   │   └── provider.go             # Service provider features
│   │
│   ├── web3/                        # Web3 DNS modules
│   │   ├── router.go               # TLD router
│   │   ├── ens/                    # ENS module
│   │   │   ├── module.go
│   │   │   ├── namehash.go
│   │   │   └── resolver.go
│   │   ├── sns/                    # SNS module
│   │   │   ├── module.go
│   │   │   └── resolver.go
│   │   ├── unstoppable/            # Unstoppable Domains
│   │   │   ├── module.go
│   │   │   └── resolver.go
│   │   ├── freename/               # Freename module
│   │   │   ├── module.go
│   │   │   └── resolver.go
│   │   └── itz/                    # ITZ module
│   │       ├── module.go
│   │       └── resolver.go
│   │
│   ├── geoip/                       # GeoIP routing
│   │   └── plugin.go
│   │
│   └── blocklist/                   # Blocklist plugin
│       └── plugin.go
│
├── api/                              # REST/gRPC APIs
│   ├── rest/                        # REST API
│   │   ├── server.go
│   │   ├── handlers.go
│   │   └── middleware.go
│   ├── grpc/                        # gRPC API
│   │   ├── server.go
│   │   └── proto/
│   │       └── dnsscienced.proto
│   └── openapi/                     # OpenAPI spec
│       └── spec.yaml
│
├── scripts/                          # Build and deploy scripts
│   ├── build.sh
│   ├── test.sh
│   └── release.sh
│
├── configs/                          # Example configurations
│   ├── dnsscienced.conf.example
│   ├── authd.conf.example
│   ├── cached.conf.example
│   └── zones/
│       └── example.com.dnszone
│
├── docs/                             # Documentation
│   ├── DESIGN.md
│   ├── WIRE_PROTOCOL.md
│   ├── DNS_INTELLIGENCE_PLATFORM.md
│   └── WEB3_DNS_MODULES.md
│
├── test/                             # Integration tests
│   ├── integration/
│   ├── conformance/
│   └── benchmark/
│
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Package Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PACKAGE DEPENDENCY GRAPH                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                            ┌─────────────────┐                              │
│                            │   cmd/*         │                              │
│                            │   (binaries)    │                              │
│                            └────────┬────────┘                              │
│                                     │                                       │
│          ┌──────────────────────────┼──────────────────────────┐           │
│          ▼                          ▼                          ▼           │
│  ┌───────────────┐        ┌───────────────┐        ┌───────────────┐      │
│  │ internal/auth │        │internal/cache │        │   plugins/*   │      │
│  └───────┬───────┘        └───────┬───────┘        └───────┬───────┘      │
│          │                        │                        │               │
│          │                        │                        │               │
│          └────────────────────────┼────────────────────────┘               │
│                                   │                                        │
│                                   ▼                                        │
│                         ┌─────────────────┐                                │
│                         │   pkg/server    │                                │
│                         │  (UDP/TCP/DoT)  │                                │
│                         └────────┬────────┘                                │
│                                  │                                         │
│          ┌───────────────────────┼───────────────────────┐                │
│          ▼                       ▼                       ▼                │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐           │
│  │   pkg/dns     │     │  pkg/dnssec   │     │   pkg/zone    │           │
│  │   (core)      │     │  (signing)    │     │  (parsing)    │           │
│  └───────┬───────┘     └───────┬───────┘     └───────┬───────┘           │
│          │                     │                     │                    │
│          └─────────────────────┴─────────────────────┘                    │
│                                │                                          │
│                                ▼                                          │
│                      ┌─────────────────┐                                  │
│                      │   pkg/config    │                                  │
│                      │  (shared types) │                                  │
│                      └─────────────────┘                                  │
│                                                                           │
│  External Dependencies:                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  golang.org/x/crypto    - Cryptographic primitives                  │ │
│  │  golang.org/x/net       - Networking extensions                     │ │
│  │  github.com/quic-go    - QUIC implementation                       │ │
│  │  github.com/redis/go-redis - Redis client                          │ │
│  │  github.com/prometheus/client_golang - Metrics                     │ │
│  │  github.com/ethereum/go-ethereum - Ethereum client                 │ │
│  │  github.com/gagliardetto/solana-go - Solana client                 │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Package APIs

### pkg/dns - Core DNS Library

```go
package dns

// Message represents a DNS message
type Message struct {
    Header     Header
    Questions  []Question
    Answers    []RR
    Authority  []RR
    Additional []RR
}

// Header represents the DNS message header
type Header struct {
    ID                 uint16
    Response           bool
    Opcode             Opcode
    Authoritative      bool
    Truncated          bool
    RecursionDesired   bool
    RecursionAvailable bool
    Zero               bool
    AuthenticData      bool
    CheckingDisabled   bool
    ResponseCode       RCode
}

// Question represents a DNS question
type Question struct {
    Name  Name
    Type  Type
    Class Class
}

// RR represents a resource record
type RR interface {
    Header() *RRHeader
    Pack(buf []byte, off int, compression map[string]int) (int, error)
    Unpack(buf []byte, off int) (int, error)
    String() string
}

// Name represents a domain name
type Name string

// NameHash computes the namehash (for ENS compatibility)
func (n Name) NameHash() [32]byte

// Pack encodes a message to wire format
func (m *Message) Pack() ([]byte, error)

// Unpack decodes a message from wire format
func (m *Message) Unpack(data []byte) error

// NewResponse creates a response for a query
func (m *Message) NewResponse() *Message
```

### pkg/zone - Zone File Handling

```go
package zone

// Zone represents a DNS zone
type Zone struct {
    Origin     string
    TTL        uint32
    SOA        *SOARecord
    Records    map[string][]RRSet
    Serial     uint32
    DNSSEC     *DNSSECConfig
}

// RRSet represents a set of records with the same name and type
type RRSet struct {
    Name    string
    Type    uint16
    TTL     uint32
    Records []dns.RR
}

// Parser parses zone files
type Parser interface {
    Parse(reader io.Reader) (*Zone, error)
    Format() string
}

// NewParser creates a parser for the given format
func NewParser(format string) (Parser, error)

// Formats
const (
    FormatBIND      = "bind"
    FormatDjbdns    = "djbdns"
    FormatDNSZone   = "dnszone"
    FormatJSON      = "json"
)

// Validator validates a zone
type Validator struct {
    CheckNS       bool
    CheckMX       bool
    CheckDNSSEC   bool
    CheckGlue     bool
}

func (v *Validator) Validate(z *Zone) (*ValidationResult, error)
```

### pkg/dnssec - DNSSEC Implementation

```go
package dnssec

// Signer signs DNS zones
type Signer struct {
    KSK       *Key
    ZSK       *Key
    Algorithm Algorithm
    NSEC3     *NSEC3Config
}

// Key represents a DNSSEC key
type Key struct {
    PublicKey  []byte
    PrivateKey []byte
    KeyTag     uint16
    Algorithm  Algorithm
    Flags      uint16  // 256=ZSK, 257=KSK
}

// Algorithm represents a DNSSEC algorithm
type Algorithm uint8

const (
    RSASHA256       Algorithm = 8
    RSASHA512       Algorithm = 10
    ECDSAP256SHA256 Algorithm = 13
    ECDSAP384SHA384 Algorithm = 14
    ED25519         Algorithm = 15
    ED448           Algorithm = 16
)

// GenerateKey generates a new DNSSEC key
func GenerateKey(algorithm Algorithm, keyType KeyType) (*Key, error)

// Sign signs a zone
func (s *Signer) Sign(zone *zone.Zone) error

// Validator validates DNSSEC signatures
type Validator struct {
    TrustAnchors []*DS
    Cache        *ValidationCache
}

// Validate validates a DNS response
func (v *Validator) Validate(msg *dns.Message) (*ValidationResult, error)
```

### pkg/resolver - Recursive Resolver

```go
package resolver

// Resolver performs recursive DNS resolution
type Resolver struct {
    Cache        Cache
    Validator    *dnssec.Validator
    Forwarders   []string
    RootHints    []*dns.NS
    Config       *Config
}

// Config holds resolver configuration
type Config struct {
    // Query settings
    QNameMinimization QMinMode
    Use0x20Encoding   bool
    MaxRecursionDepth int
    Timeout           time.Duration

    // DNSSEC
    ValidateDNSSEC    bool
    TrustAnchorsFile  string

    // Cache
    MaxCacheSize      int
    ServeStale        bool
    StaleAnswerTTL    uint32
    PrefetchThreshold float64
}

// Resolve performs a recursive query
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*dns.Message, error)

// Cache interface for resolver cache
type Cache interface {
    Get(key string) (*CacheEntry, bool)
    Set(key string, entry *CacheEntry)
    Delete(key string)
    Prefetch(key string)
}
```

### pkg/server - Server Components

```go
package server

// Server is the main DNS server
type Server struct {
    UDP      *UDPServer
    TCP      *TCPServer
    DoT      *DoTServer
    DoH      *DoHServer
    DoQ      *DoQServer
    Handler  Handler
    Config   *Config
}

// Handler handles DNS queries
type Handler interface {
    ServeDNS(ctx context.Context, w ResponseWriter, r *dns.Message)
}

// ResponseWriter writes DNS responses
type ResponseWriter interface {
    WriteMsg(msg *dns.Message) error
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Close() error
}

// Config holds server configuration
type Config struct {
    // Listeners
    ListenAddrs    []string
    ListenAddrsTLS []string
    ListenAddrsDoH []string
    ListenAddrsDoQ []string

    // TLS
    TLSCert        string
    TLSKey         string
    TLSMinVersion  uint16

    // Limits
    MaxUDPSize     int
    MaxTCPConns    int
    TCPTimeout     time.Duration

    // Rate limiting
    RateLimit      *RateLimitConfig
}

// Start starts the server
func (s *Server) Start() error

// Stop stops the server gracefully
func (s *Server) Stop(ctx context.Context) error
```

---

## Plugin Interface

```go
package plugins

// Plugin is the interface all plugins must implement
type Plugin interface {
    // Metadata
    Name() string
    Version() string
    Description() string

    // Lifecycle
    Init(config map[string]interface{}) error
    Start() error
    Stop() error
    Reload(config map[string]interface{}) error

    // Health
    HealthCheck() error
}

// QueryPlugin hooks into query processing
type QueryPlugin interface {
    Plugin

    // Priority determines hook order (lower = earlier)
    Priority() int

    // PreQuery is called before query processing
    PreQuery(ctx *QueryContext) (*dns.Message, error)

    // PostResponse is called after response generation
    PostResponse(ctx *QueryContext, response *dns.Message) (*dns.Message, error)
}

// QueryContext provides query metadata
type QueryContext struct {
    Query       *dns.Message
    Response    *dns.Message
    Client      net.Addr
    Transport   Transport
    Timestamp   time.Time
    ProcessTime time.Duration
    CacheHit    bool
    Validated   bool
    Metadata    map[string]interface{}
}

// Manager manages plugin lifecycle
type Manager struct {
    plugins  map[string]Plugin
    hooks    *HookRegistry
}

func (m *Manager) Load(path string) error
func (m *Manager) Unload(name string) error
func (m *Manager) Get(name string) (Plugin, bool)
func (m *Manager) CallPreQuery(ctx *QueryContext) (*dns.Message, error)
func (m *Manager) CallPostResponse(ctx *QueryContext, resp *dns.Message) (*dns.Message, error)
```

---

## Build Configuration

### Makefile

```makefile
# Makefile for DNSScienced

VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

.PHONY: all build test clean

all: build

build:
	@echo "Building DNSScienced $(VERSION)..."
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-authd ./cmd/dnsscience-authd
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-cached ./cmd/dnsscience-cached
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-ctl ./cmd/dnsscience-ctl
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-checkzone ./cmd/dnsscience-checkzone
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-convert ./cmd/dnsscience-convert
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-keygen ./cmd/dnsscience-keygen
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-signzone ./cmd/dnsscience-signzone
	go build -ldflags "$(LDFLAGS)" -o bin/dnsscience-dig ./cmd/dnsscience-dig

test:
	go test -race -cover ./...

test-integration:
	go test -tags=integration ./test/integration/...

benchmark:
	go test -bench=. -benchmem ./test/benchmark/...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	go clean

docker:
	docker build -t dnsscience/dnsscienced:$(VERSION) .

release: clean test lint build
	@echo "Creating release $(VERSION)..."
```

### go.mod

```go
module github.com/afterdarksys/dnsscienced

go 1.22

require (
    // Core
    golang.org/x/crypto v0.18.0
    golang.org/x/net v0.20.0
    golang.org/x/sync v0.6.0

    // QUIC
    github.com/quic-go/quic-go v0.41.0

    // Configuration
    github.com/spf13/viper v1.18.2
    github.com/spf13/cobra v1.8.0
    gopkg.in/yaml.v3 v3.0.1

    // Caching
    github.com/redis/go-redis/v9 v9.4.0
    github.com/hashicorp/golang-lru/v2 v2.0.7

    // Metrics & Logging
    github.com/prometheus/client_golang v1.18.0
    go.uber.org/zap v1.26.0

    // Web3
    github.com/ethereum/go-ethereum v1.13.10
    github.com/gagliardetto/solana-go v1.8.4
    github.com/wealdtech/go-ens/v3 v3.6.0

    // Testing
    github.com/stretchr/testify v1.8.4
    github.com/golang/mock v1.6.0
)
```

---

## Configuration Example

### Default Configuration

```go
// internal/config/defaults.go

package config

var DefaultConfig = &Config{
    Global: GlobalConfig{
        User:  "dnsscienced",
        Group: "dnsscienced",
        Directory: "/var/lib/dnsscienced",
        PidFile:   "/run/dnsscienced/dnsscienced.pid",
    },

    Logging: LoggingConfig{
        Level:  "info",
        Format: "json",
        Output: "syslog",
    },

    Cached: CachedConfig{
        Listen: []string{"127.0.0.1:53", "[::1]:53"},
        Cache: CacheConfig{
            MaxSize:     512 * 1024 * 1024, // 512MB
            MaxTTL:      86400,
            MinTTL:      0,
            NegativeTTL: 3600,
            ServeStale:  true,
        },
        DNSSEC: DNSSECConfig{
            Validation:      "auto",
            TrustAnchors:    "/etc/dnsscienced/root.keys",
            AggressiveNSEC:  true,
        },
        QNameMinimization: "strict",
    },

    Authd: AuthdConfig{
        Listen: []string{"0.0.0.0:53", "[::]:53"},
        ZoneDefaults: ZoneDefaultConfig{
            Notify:      true,
            NotifyDelay: 5 * time.Second,
        },
    },

    Security: SecurityConfig{
        RateLimit: RateLimitConfig{
            Enabled:            true,
            ResponsesPerSecond: 10,
            ErrorsPerSecond:    5,
            Window:             15 * time.Second,
            Slip:               2,
        },
        DNSCookies: true,
        MaxUDPSize: 1232,
    },
}
```

---

*Document Version: 1.0*
*Go Module Specification*
