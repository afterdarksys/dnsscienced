# DNSScienced Project Roadmap

> **Historical strategy document:** This roadmap preserves the original product
> vision and version sequence. Much of its status data has been overtaken by the
> implementation. Use the root [implementation roadmap](../ROADMAP.md) and
> [README](../README.md) for current shipped/planned boundaries.

## Vision

**DNS Science: DNS Data, Management, Analytics, and Security Experts**

Build the next-generation DNS platform that combines enterprise-grade DNS services with AI-powered security intelligence and Web3 name resolution.

---

## Phase Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROJECT PHASES                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: FOUNDATION                                                        │
│  ══════════════════════════════════════════════════════════════════════════ │
│  Core DNS engine, wire protocol, basic auth/cached servers                  │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  PHASE 2: ENTERPRISE DNS                                                    │
│  ══════════════════════════════════════════════════════════════════════════ │
│  DNSSEC, zone transfers, modern transports (DoT/DoH/DoQ)                   │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  PHASE 3: SECURITY & INTELLIGENCE                                           │
│  ══════════════════════════════════════════════════════════════════════════ │
│  DDoS mitigation, threat detection, DNSScience.io integration              │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  PHASE 4: WEB3 INTEGRATION                                                  │
│  ══════════════════════════════════════════════════════════════════════════ │
│  ENS, SNS, Unstoppable Domains, Freename, ITZ modules                      │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  PHASE 5: AI/ML PLATFORM                                                    │
│  ══════════════════════════════════════════════════════════════════════════ │
│  Predictive DNS firewall, DGA detection, behavior analysis                 │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  PHASE 6: SERVICE PROVIDER                                                  │
│  ══════════════════════════════════════════════════════════════════════════ │
│  Multi-tenant, CDN edition, Financial Services edition                     │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation

### Objective
Build a solid, RFC-compliant DNS foundation that can serve as the base for all future features.

### Deliverables

```
CORE DNS ENGINE
├── pkg/dns/
│   ├── Wire format parser/builder
│   ├── Name compression
│   ├── All basic record types (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV)
│   ├── EDNS(0) support
│   └── DNS message validation
│
├── pkg/zone/
│   ├── Native zone format parser (.dnszone)
│   ├── BIND zone format parser (compatibility)
│   ├── Zone validation
│   └── SOA serial management
│
├── pkg/server/
│   ├── UDP listener
│   ├── TCP listener
│   └── Basic request handler
│
├── cmd/dnsscience-authd/
│   └── Basic authoritative server
│
├── cmd/dnsscience-cached/
│   └── Basic recursive resolver
│
└── cmd/dnsscience-checkzone/
    └── Zone file validator
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M1.1 | Wire protocol | Parse/build all RFC 1035 messages |
| M1.2 | Zone parser | Parse native + BIND formats |
| M1.3 | UDP server | Respond to basic queries |
| M1.4 | TCP server | Handle large responses, pipelining |
| M1.5 | Authoritative | Serve zones from file |
| M1.6 | Recursive | Full iterative resolution |
| M1.7 | Caching | In-memory cache with TTL |

### Success Metrics

- [ ] Pass RFC 1035 conformance tests
- [ ] Serve 100K QPS on single core (UDP)
- [ ] Sub-millisecond latency for cached responses
- [ ] Zero memory leaks under load

---

## Phase 2: Enterprise DNS

### Objective
Add enterprise features required for production deployment: DNSSEC, encrypted transports, zone transfers.

### Deliverables

```
ENTERPRISE FEATURES
├── pkg/dnssec/
│   ├── Signature generation (all RFC 8624 algorithms)
│   ├── Signature validation
│   ├── NSEC/NSEC3 support
│   ├── Key generation
│   └── Key rollover automation
│
├── pkg/server/
│   ├── DNS over TLS (DoT)
│   ├── DNS over HTTPS (DoH)
│   └── DNS over QUIC (DoQ)
│
├── internal/auth/
│   ├── AXFR (full zone transfer)
│   ├── IXFR (incremental transfer)
│   ├── NOTIFY
│   ├── TSIG authentication
│   └── Dynamic updates (RFC 2136)
│
├── internal/cache/
│   ├── Redis backend
│   ├── Serve stale (RFC 8767)
│   └── Prefetching
│
├── cmd/dnsscience-keygen/
├── cmd/dnsscience-signzone/
└── cmd/dnsscience-convert/
    └── BIND/djbdns → native conversion
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M2.1 | DNSSEC signing | Sign zones with ECDSA P-256 |
| M2.2 | DNSSEC validation | Validate responses, build chain of trust |
| M2.3 | DoT | Full RFC 7858 compliance |
| M2.4 | DoH | Full RFC 8484 compliance |
| M2.5 | DoQ | Full RFC 9250 compliance |
| M2.6 | Zone transfers | AXFR/IXFR with TSIG |
| M2.7 | Dynamic updates | RFC 2136 + RFC 3007 |

### Success Metrics

- [ ] Pass DNSSEC conformance tests
- [ ] 100% encrypted transport support
- [ ] Zone transfer to/from BIND
- [ ] Sub-second key rollover

---

## Phase 3: Security & Intelligence

### Objective
Build DDoS mitigation and integrate with DNSScience.io for threat intelligence.

### Deliverables

```
SECURITY FEATURES
├── internal/security/
│   ├── Response Rate Limiting (RRL)
│   ├── DNS Cookies (RFC 7873)
│   ├── Access Control Lists
│   ├── Response Policy Zones (RPZ)
│   └── Query pattern analysis
│
├── internal/ddos/
│   ├── Amplification detection
│   ├── Random subdomain detection
│   ├── TC bit forcing
│   └── Automatic mitigation
│
├── internal/metrics/
│   ├── Prometheus exporter
│   ├── Query logging (JSON, CLF)
│   └── Security event logging
│
├── plugins/dnsscience-cloud/
│   ├── Threat feed integration
│   ├── Reputation lookups
│   └── Telemetry submission
│
└── api/rest/
    ├── Statistics API
    ├── Control API
    └── Health API
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M3.1 | RRL | Configurable rate limiting |
| M3.2 | DNS Cookies | Full RFC 7873 support |
| M3.3 | RPZ | Load and apply RPZ zones |
| M3.4 | Attack detection | Detect common attack patterns |
| M3.5 | DNSScience.io | Feed sync, telemetry |
| M3.6 | REST API | Full management API |
| M3.7 | Prometheus | Comprehensive metrics |

### Success Metrics

- [ ] Mitigate 1M QPS attack
- [ ] <5% false positive rate on blocking
- [ ] Real-time DNSScience.io sync
- [ ] Complete audit trail

---

## Phase 4: Web3 Integration

### Objective
Native resolution of blockchain-based naming systems alongside traditional DNS.

### Deliverables

```
WEB3 MODULES
├── plugins/web3/
│   ├── router.go           (TLD routing)
│   │
│   ├── ens/
│   │   ├── module.go
│   │   ├── namehash.go
│   │   ├── resolver.go
│   │   └── ccip.go         (L2 support)
│   │
│   ├── sns/
│   │   ├── module.go
│   │   └── resolver.go
│   │
│   ├── unstoppable/
│   │   ├── module.go
│   │   └── resolver.go
│   │
│   ├── freename/
│   │   ├── module.go
│   │   └── resolver.go
│   │
│   └── itz/
│       ├── module.go
│       └── resolver.go
│
└── configs/
    └── web3.yaml           (Module configuration)
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M4.1 | ENS basic | Resolve .eth domains |
| M4.2 | ENS L2 | CCIP-Read for L2 resolution |
| M4.3 | SNS | Resolve .sol domains |
| M4.4 | Unstoppable | All UD TLDs |
| M4.5 | Freename | .fn and custom TLDs |
| M4.6 | ITZ | Full itz.agency integration |
| M4.7 | Caching | Multi-layer Web3 cache |

### Success Metrics

- [ ] <100ms Web3 resolution (cached)
- [ ] <2s Web3 resolution (cold)
- [ ] 99.9% resolution accuracy
- [ ] Blockchain verification option

---

## Phase 5: AI/ML Platform

### Objective
Deploy AI-powered threat detection and predictive security features.

### Deliverables

```
DNS INTELLIGENCE PLATFORM
├── plugins/dip/
│   ├── plugin.go           (Main DIP plugin)
│   │
│   ├── sampling/
│   │   ├── sampler.go
│   │   ├── reservoir.go
│   │   └── adaptive.go
│   │
│   ├── ai/
│   │   ├── engine.go
│   │   ├── dga.go          (DGA detector)
│   │   ├── anomaly.go      (Anomaly detection)
│   │   ├── classifier.go   (Threat classifier)
│   │   └── models/         (ONNX models)
│   │
│   ├── feeds/
│   │   ├── manager.go
│   │   ├── dnsscience.go
│   │   └── sync.go
│   │
│   ├── routing/
│   │   ├── geo.go
│   │   ├── latency.go
│   │   ├── health.go
│   │   └── weighted.go
│   │
│   └── policy/
│       ├── engine.go
│       ├── scorer.go
│       └── actions.go
│
└── models/
    ├── dga_lstm_v3.onnx
    └── anomaly_iforest_v2.onnx
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M5.1 | Traffic sampling | Configurable sampling engine |
| M5.2 | DGA detection | 95%+ accuracy on known DGAs |
| M5.3 | Anomaly detection | Behavioral baselines |
| M5.4 | Policy engine | Configurable policies |
| M5.5 | Intelligent routing | Geo, latency, health-based |
| M5.6 | Feed integration | Real-time threat feeds |
| M5.7 | ML pipeline | Model updates, feedback loop |

### Success Metrics

- [ ] 95%+ DGA detection accuracy
- [ ] <1% false positive rate
- [ ] <1ms inline inference
- [ ] Real-time model updates

---

## Phase 6: Service Provider

### Objective
Build multi-tenant platform for service providers, CDNs, and financial institutions.

### Deliverables

```
SERVICE PROVIDER FEATURES
├── plugins/dip/provider/
│   ├── tenant.go           (Multi-tenant)
│   ├── metering.go         (Usage metering)
│   ├── billing.go          (Billing integration)
│   └── portal.go           (Self-service API)
│
├── plugins/dip/cdn/
│   ├── edge.go             (Edge selection)
│   ├── origin.go           (Origin management)
│   ├── cache.go            (Cache control)
│   └── purge.go            (Purge API)
│
├── plugins/dip/finserv/
│   ├── lowlatency.go       (Ultra-low latency)
│   ├── compliance.go       (Audit logging)
│   ├── ha.go               (High availability)
│   └── threats.go          (Financial threats)
│
└── deploy/
    ├── kubernetes/
    │   ├── helm/
    │   └── operators/
    └── terraform/
```

### Milestones

| Milestone | Description | Acceptance Criteria |
|-----------|-------------|---------------------|
| M6.1 | Multi-tenant | Tenant isolation, per-tenant policies |
| M6.2 | Usage metering | Accurate query counting |
| M6.3 | CDN edition | Edge routing, origin management |
| M6.4 | Cache control | Purge, warm, invalidate via DNS |
| M6.5 | FinServ edition | <100μs latency, full audit |
| M6.6 | High availability | 5-nines architecture |
| M6.7 | Kubernetes | Helm charts, operators |

### Success Metrics

- [ ] 10,000+ tenants
- [ ] 1M+ QPS per cluster
- [ ] 99.999% availability
- [ ] PCI-DSS compliant

---

## Technical Debt & Quality

### Continuous Throughout All Phases

```
QUALITY INITIATIVES
├── Testing
│   ├── Unit tests (80%+ coverage)
│   ├── Integration tests
│   ├── Conformance tests (RFC compliance)
│   ├── Fuzz testing (security)
│   └── Benchmark tests
│
├── Documentation
│   ├── API documentation
│   ├── Configuration reference
│   ├── Deployment guides
│   └── Troubleshooting guides
│
├── Security
│   ├── Regular security audits
│   ├── Dependency scanning
│   ├── Penetration testing
│   └── Bug bounty program
│
└── Performance
    ├── Profiling and optimization
    ├── Memory leak detection
    ├── Latency optimization
    └── Throughput testing
```

---

## Release Strategy

### Versioning

```
Version Format: MAJOR.MINOR.PATCH

MAJOR: Breaking changes, major features
MINOR: New features, backward compatible
PATCH: Bug fixes, security updates

Examples:
0.x.x  - Development/Alpha
1.0.0  - First stable release (Phase 1 complete)
1.1.0  - DNSSEC support (Phase 2)
1.2.0  - DoT/DoH/DoQ (Phase 2)
2.0.0  - Security features (Phase 3)
3.0.0  - Web3 integration (Phase 4)
4.0.0  - AI/ML platform (Phase 5)
5.0.0  - Service provider (Phase 6)
```

### Release Cadence

```
Release Type        Frequency       Content
─────────────────────────────────────────────────────────────────────────
Nightly             Daily           Latest development
Alpha               Weekly          Feature-complete milestones
Beta                Monthly         Release candidates
Stable              Quarterly       Production releases
LTS                 Yearly          Long-term support (3 years)
```

---

## Community & Ecosystem

### Open Source Strategy

```
COMPONENT                   LICENSE         OPEN SOURCE
─────────────────────────────────────────────────────────────────────────
Core DNS engine             MIT             Yes
Zone parsers                MIT             Yes
DNSSEC implementation       MIT             Yes
Web3 modules                MIT             Yes
DIP (basic features)        MIT             Yes
DIP (enterprise)            Commercial      No
Service provider            Commercial      No
DNSScience.io integration   Commercial      No
```

### Plugin Ecosystem

```
Encourage third-party plugins:
- Plugin marketplace
- Developer documentation
- Example plugins
- Plugin certification program
```

---

## Success Criteria

### Technical Goals

| Metric | Target |
|--------|--------|
| Query throughput | 1M+ QPS per server |
| Latency (cached) | <100μs p99 |
| Latency (recursive) | <50ms p99 |
| Memory efficiency | <1KB per cached entry |
| Availability | 99.999% (5 nines) |
| DNSSEC validation | 100% coverage |

### Business Goals

| Metric | Target |
|--------|--------|
| Open source adoption | 10,000+ GitHub stars |
| Enterprise customers | 100+ paying customers |
| Service provider customers | 20+ ISP/hosting |
| DNS queries processed | 1T+ queries/month |

---

*Document Version: 1.0*
*Project Roadmap*
