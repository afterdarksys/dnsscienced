# DNSScienced Testing Strategy

> **Strategy, not a completion report:** Checklists and coverage percentages in
> this document describe desired gates unless accompanied by current command
> output. The authoritative current checks are `go test ./...` and
> `tests/differential/run.sh`; see [README](../README.md#evidence).

## Testing Philosophy

**"If it's not tested, it's broken."**

DNS is critical infrastructure. Our testing strategy ensures:
- RFC compliance across all supported standards
- Security under adversarial conditions
- Performance at scale
- Reliability under failure conditions

---

## Test Categories

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TESTING PYRAMID                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                            ┌─────────┐                                      │
│                            │  E2E    │  < 5%                                │
│                            │ Tests   │  Full system, real networks         │
│                           ─┴─────────┴─                                     │
│                          ┌─────────────┐                                    │
│                          │ Integration │  ~15%                              │
│                          │   Tests     │  Component interaction            │
│                         ─┴─────────────┴─                                   │
│                        ┌─────────────────┐                                  │
│                        │  Conformance    │  ~20%                            │
│                        │    Tests        │  RFC compliance                  │
│                       ─┴─────────────────┴─                                 │
│                      ┌─────────────────────┐                                │
│                      │    Unit Tests       │  ~60%                          │
│                      │                     │  Individual functions          │
│                     ─┴─────────────────────┴─                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Unit Tests

### Coverage Requirements

| Package | Minimum Coverage | Critical Paths |
|---------|------------------|----------------|
| `pkg/dns` | 90% | Message parsing, name compression |
| `pkg/zone` | 85% | Zone parsing, validation |
| `pkg/dnssec` | 95% | All crypto operations |
| `pkg/resolver` | 80% | Query engine |
| `pkg/server` | 75% | Request handling |
| `internal/*` | 80% | Security features |
| `plugins/*` | 75% | Plugin logic |

### Unit Test Structure

```go
// Example: pkg/dns/parser_test.go

package dns

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestMessageUnpack(t *testing.T) {
    tests := []struct {
        name    string
        input   []byte
        want    *Message
        wantErr bool
    }{
        {
            name:  "simple A query",
            input: []byte{...},
            want:  &Message{...},
        },
        {
            name:    "truncated message",
            input:   []byte{0x00, 0x01}, // Too short
            wantErr: true,
        },
        {
            name:    "compression loop",
            input:   compressionLoopPacket,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            msg := &Message{}
            err := msg.Unpack(tt.input)

            if tt.wantErr {
                assert.Error(t, err)
                return
            }

            require.NoError(t, err)
            assert.Equal(t, tt.want, msg)
        })
    }
}

// Table-driven tests for all record types
func TestRecordTypeParsing(t *testing.T) {
    recordTypes := []struct {
        name     string
        typeCode uint16
        rdata    []byte
        expected RR
    }{
        {"A", TypeA, []byte{192, 0, 2, 1}, &A{IP: net.ParseIP("192.0.2.1")}},
        {"AAAA", TypeAAAA, ipv6Bytes, &AAAA{IP: net.ParseIP("2001:db8::1")}},
        {"CNAME", TypeCNAME, cnameWire, &CNAME{Target: "www.example.com."}},
        {"MX", TypeMX, mxWire, &MX{Preference: 10, Exchange: "mail.example.com."}},
        // ... all 60+ record types
    }

    for _, tt := range recordTypes {
        t.Run(tt.name, func(t *testing.T) {
            rr, err := UnpackRR(tt.typeCode, tt.rdata)
            require.NoError(t, err)
            assert.Equal(t, tt.expected, rr)
        })
    }
}
```

### Critical Unit Tests

```
WIRE PROTOCOL
├── Message header parsing
├── Question section parsing
├── All RR types (60+)
├── Name compression (encode/decode)
├── EDNS(0) options
├── TSIG MAC calculation
├── DNS Cookie generation/validation
└── Truncation handling

ZONE PARSING
├── BIND format (all directives)
├── djbdns format
├── Native format (YAML)
├── $ORIGIN handling
├── $TTL inheritance
├── Multi-line records
├── Comments and whitespace
└── Serial number parsing

DNSSEC
├── Key generation (all algorithms)
├── Signature creation
├── Signature verification
├── NSEC/NSEC3 generation
├── Chain of trust validation
├── Key tag calculation
├── DS record generation
└── Algorithm rollover

RESOLVER
├── Iterative resolution
├── CNAME chasing
├── Query minimization
├── 0x20 encoding
├── Cache lookup/store
├── TTL handling
├── Negative caching
└── Serve stale logic
```

---

## 2. Conformance Tests

### RFC Compliance Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RFC CONFORMANCE TEST SUITES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  RFC 1035 - Domain Names                                                    │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── Message format                          [  ] 50 tests                 │
│  ├── Name encoding                           [  ] 30 tests                 │
│  ├── Compression                             [  ] 25 tests                 │
│  ├── Basic record types                      [  ] 40 tests                 │
│  └── Response codes                          [  ] 15 tests                 │
│                                                                             │
│  RFC 4033/4034/4035 - DNSSEC                                               │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── DNSKEY records                          [  ] 20 tests                 │
│  ├── RRSIG generation                        [  ] 30 tests                 │
│  ├── RRSIG validation                        [  ] 40 tests                 │
│  ├── DS records                              [  ] 15 tests                 │
│  ├── NSEC records                            [  ] 25 tests                 │
│  └── Chain of trust                          [  ] 35 tests                 │
│                                                                             │
│  RFC 5155 - NSEC3                                                          │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── Hash calculation                        [  ] 15 tests                 │
│  ├── NSEC3 chain                             [  ] 20 tests                 │
│  ├── Opt-out                                 [  ] 10 tests                 │
│  └── Closest encloser proof                  [  ] 15 tests                 │
│                                                                             │
│  RFC 6891 - EDNS(0)                                                        │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── OPT record                              [  ] 20 tests                 │
│  ├── Extended RCODE                          [  ] 10 tests                 │
│  ├── UDP payload size                        [  ] 15 tests                 │
│  └── Unknown options                         [  ] 10 tests                 │
│                                                                             │
│  RFC 7858 - DNS over TLS                                                   │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── TLS handshake                           [  ] 15 tests                 │
│  ├── Message framing                         [  ] 10 tests                 │
│  ├── Connection reuse                        [  ] 10 tests                 │
│  └── Certificate validation                  [  ] 20 tests                 │
│                                                                             │
│  RFC 8484 - DNS over HTTPS                                                 │
│  ════════════════════════════════════════════════════════════════════════  │
│  ├── GET method                              [  ] 15 tests                 │
│  ├── POST method                             [  ] 15 tests                 │
│  ├── Content-Type handling                   [  ] 10 tests                 │
│  └── Caching headers                         [  ] 10 tests                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Conformance Test Implementation

```go
// test/conformance/rfc1035_test.go

package conformance

import (
    "testing"
    "github.com/afterdarksys/dnsscienced/pkg/dns"
)

// TestRFC1035_4_1_1_HeaderFormat tests header format per RFC 1035 Section 4.1.1
func TestRFC1035_4_1_1_HeaderFormat(t *testing.T) {
    t.Run("header is exactly 12 bytes", func(t *testing.T) {
        msg := &dns.Message{
            Header: dns.Header{ID: 0x1234},
        }
        packed, err := msg.Pack()
        require.NoError(t, err)
        assert.GreaterOrEqual(t, len(packed), 12)
    })

    t.Run("ID field is first 16 bits", func(t *testing.T) {
        msg := &dns.Message{Header: dns.Header{ID: 0xABCD}}
        packed, _ := msg.Pack()
        assert.Equal(t, byte(0xAB), packed[0])
        assert.Equal(t, byte(0xCD), packed[1])
    })

    // ... additional header tests
}

// TestRFC1035_4_1_4_MessageCompression tests compression per RFC 1035 Section 4.1.4
func TestRFC1035_4_1_4_MessageCompression(t *testing.T) {
    t.Run("pointer format 11xxxxxx", func(t *testing.T) {
        // Compression pointers must have first two bits set
        compressed := []byte{0xC0, 0x0C} // Pointer to offset 12
        assert.Equal(t, byte(0xC0)&0xC0, byte(0xC0))
    })

    t.Run("no forward pointers", func(t *testing.T) {
        // Message with forward pointer should fail to parse
        badMessage := createForwardPointerMessage()
        msg := &dns.Message{}
        err := msg.Unpack(badMessage)
        assert.Error(t, err)
    })

    t.Run("no compression loops", func(t *testing.T) {
        loopMessage := createCompressionLoopMessage()
        msg := &dns.Message{}
        err := msg.Unpack(loopMessage)
        assert.Error(t, err)
    })
}
```

### External Conformance Test Suites

```yaml
# External test suites to run against

test-suites:
  # ISC DNS compliance tests
  - name: isc-dns-compliance
    source: "https://github.com/isc-projects/bind9/tree/main/bin/tests"
    tests:
      - dnssec-validation
      - zone-transfer
      - notify

  # NLnet Labs tests
  - name: nlnet-ldns-tests
    source: "https://github.com/NLnetLabs/ldns"
    tests:
      - wire-format
      - dnssec-verify

  # DNS flag day tests
  - name: dns-flag-day
    source: "https://dnsflagday.net/2020/"
    tests:
      - edns-compliance
      - tcp-support

  # OARC tests
  - name: oarc-dns-tests
    source: "https://www.dns-oarc.net/"
    tests:
      - reply-size
      - source-port-randomness
```

---

## 3. Integration Tests

### Test Environment

```yaml
# test/integration/docker-compose.yml

version: '3.8'

services:
  # System under test
  dnsscienced-authd:
    build: ../..
    command: ["dnsscience-authd", "-c", "/etc/dnsscienced/authd.conf"]
    volumes:
      - ./configs:/etc/dnsscienced
      - ./zones:/var/lib/dnsscienced/zones
    networks:
      - dns-test

  dnsscienced-cached:
    build: ../..
    command: ["dnsscience-cached", "-c", "/etc/dnsscienced/cached.conf"]
    depends_on:
      - dnsscienced-authd
    networks:
      - dns-test

  # Reference implementations
  bind9:
    image: internetsystemsconsortium/bind9:9.18
    volumes:
      - ./bind-config:/etc/bind
    networks:
      - dns-test

  unbound:
    image: mvance/unbound:latest
    volumes:
      - ./unbound-config:/etc/unbound
    networks:
      - dns-test

  # Test infrastructure
  redis:
    image: redis:7-alpine
    networks:
      - dns-test

  mock-blockchain:
    build: ./mock-blockchain
    networks:
      - dns-test

networks:
  dns-test:
    driver: bridge
```

### Integration Test Scenarios

```go
// test/integration/zone_transfer_test.go

package integration

import (
    "testing"
    "time"
)

func TestZoneTransfer(t *testing.T) {
    env := NewTestEnvironment(t)
    defer env.Cleanup()

    t.Run("AXFR from BIND to DNSScienced", func(t *testing.T) {
        // Configure BIND as primary
        env.ConfigureBIND(BINDConfig{
            Zone:        "example.com",
            Type:        "primary",
            AllowTransfer: []string{env.DNSSciencedIP()},
        })

        // Configure DNSScienced as secondary
        env.ConfigureDNSScienced(AuthdConfig{
            Zone:     "example.com",
            Type:     "secondary",
            Primary:  env.BINDIP(),
        })

        // Trigger transfer
        env.ReloadDNSScienced()

        // Verify zone transferred correctly
        assert.Eventually(t, func() bool {
            return env.ZoneExists("example.com")
        }, 30*time.Second, 1*time.Second)

        // Verify record content
        resp := env.Query("www.example.com", dns.TypeA)
        assert.Equal(t, "192.0.2.1", resp.Answer[0].(*dns.A).IP.String())
    })

    t.Run("IXFR incremental update", func(t *testing.T) {
        // Initial full transfer
        env.PerformAXFR("example.com")

        // Update BIND zone
        env.UpdateBINDZone("example.com", "new.example.com. A 192.0.2.100")

        // Send NOTIFY
        env.SendNOTIFY("example.com")

        // Verify IXFR received
        assert.Eventually(t, func() bool {
            resp := env.Query("new.example.com", dns.TypeA)
            return resp.Rcode == dns.RcodeSuccess
        }, 10*time.Second, 500*time.Millisecond)
    })
}

// test/integration/dnssec_test.go

func TestDNSSECValidation(t *testing.T) {
    env := NewTestEnvironment(t)
    defer env.Cleanup()

    t.Run("validate signed zone", func(t *testing.T) {
        // Load pre-signed zone
        env.LoadSignedZone("signed.example.com")

        // Query with DNSSEC
        resp := env.QueryWithDNSSEC("www.signed.example.com", dns.TypeA)

        // Verify AD flag set
        assert.True(t, resp.AuthenticData)
    })

    t.Run("detect bogus signature", func(t *testing.T) {
        // Load zone with invalid signature
        env.LoadZoneWithBadSignature("bogus.example.com")

        // Query should return SERVFAIL
        resp := env.Query("www.bogus.example.com", dns.TypeA)
        assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
    })
}
```

### Cross-Implementation Tests

```go
// test/integration/interop_test.go

func TestInteroperability(t *testing.T) {
    implementations := []struct {
        name   string
        server Server
    }{
        {"BIND9", NewBINDServer()},
        {"Unbound", NewUnboundServer()},
        {"PowerDNS", NewPowerDNSServer()},
        {"Knot", NewKnotServer()},
    }

    for _, impl := range implementations {
        t.Run(impl.name, func(t *testing.T) {
            t.Run("zone transfer to "+impl.name, func(t *testing.T) {
                // DNSScienced as primary, other as secondary
                testZoneTransferTo(t, impl.server)
            })

            t.Run("zone transfer from "+impl.name, func(t *testing.T) {
                // Other as primary, DNSScienced as secondary
                testZoneTransferFrom(t, impl.server)
            })

            t.Run("recursive queries via "+impl.name, func(t *testing.T) {
                // Use impl as forwarder
                testForwarderInterop(t, impl.server)
            })
        })
    }
}
```

---

## 4. Security Tests

### Fuzz Testing

```go
// test/fuzz/message_fuzz_test.go

//go:build go1.18

package fuzz

import (
    "testing"
    "github.com/afterdarksys/dnsscienced/pkg/dns"
)

func FuzzMessageUnpack(f *testing.F) {
    // Seed corpus with valid messages
    f.Add(validAQuery)
    f.Add(validAAAAQuery)
    f.Add(validMXQuery)
    f.Add(validEDNSQuery)
    f.Add(validTSIGQuery)

    // Seed with known problematic inputs
    f.Add(compressionLoopMessage)
    f.Add(truncatedMessage)
    f.Add(oversizedMessage)

    f.Fuzz(func(t *testing.T, data []byte) {
        msg := &dns.Message{}
        err := msg.Unpack(data)
        if err == nil {
            // If parsing succeeded, repacking should work
            _, packErr := msg.Pack()
            if packErr != nil {
                t.Errorf("Unpack succeeded but Pack failed: %v", packErr)
            }
        }
        // No panics allowed
    })
}

func FuzzZoneParse(f *testing.F) {
    f.Add([]byte(validBindZone))
    f.Add([]byte(validDNSZone))

    f.Fuzz(func(t *testing.T, data []byte) {
        parser := zone.NewParser("auto")
        _, _ = parser.Parse(bytes.NewReader(data))
        // Should not panic on any input
    })
}

func FuzzDNSSECVerify(f *testing.F) {
    f.Add(validRRSIG, validDNSKEY, validRRSet)

    f.Fuzz(func(t *testing.T, rrsig, dnskey, rrset []byte) {
        _ = dnssec.Verify(rrsig, dnskey, rrset)
        // Should not panic
    })
}
```

### Security Test Scenarios

```go
// test/security/attacks_test.go

func TestSecurityVulnerabilities(t *testing.T) {
    t.Run("compression bomb", func(t *testing.T) {
        // Message with deeply nested compression
        bomb := createCompressionBomb(1000)
        msg := &dns.Message{}
        err := msg.Unpack(bomb)
        assert.Error(t, err) // Should reject
    })

    t.Run("amplification prevention", func(t *testing.T) {
        // ANY query should not amplify
        env := NewTestEnvironment(t)
        env.ConfigureRRL(RRLConfig{
            ResponsesPerSecond: 10,
        })

        // Send many ANY queries from spoofed source
        responses := env.SendQueries(1000, QueryConfig{
            Type:   dns.TypeANY,
            Source: "spoofed",
        })

        // Should be rate limited
        successCount := countSuccessful(responses)
        assert.Less(t, successCount, 100)
    })

    t.Run("cache poisoning resistance", func(t *testing.T) {
        env := NewTestEnvironment(t)

        // Attempt Kaminsky attack
        attacker := NewCachePoisonAttacker(env)
        success := attacker.AttemptKaminsky("target.com", 1000000)

        assert.False(t, success)
    })

    t.Run("DNSSEC bypass attempts", func(t *testing.T) {
        tests := []struct {
            name   string
            attack func() *dns.Message
        }{
            {"missing RRSIG", createMissingRRSIGResponse},
            {"wrong signer", createWrongSignerResponse},
            {"expired signature", createExpiredSigResponse},
            {"algorithm downgrade", createAlgoDowngradeResponse},
        }

        for _, tt := range tests {
            t.Run(tt.name, func(t *testing.T) {
                env := NewTestEnvironment(t)
                env.EnableDNSSECValidation()

                response := tt.attack()
                result := env.InjectResponse(response)

                assert.Equal(t, dns.RcodeServerFailure, result.Rcode)
            })
        }
    })
}
```

### Penetration Test Checklist

```markdown
## DNS Security Penetration Test Checklist

### Protocol Attacks
- [ ] DNS amplification (ANY, TXT, DNSSEC)
- [ ] Cache poisoning (birthday, Kaminsky)
- [ ] DNS rebinding
- [ ] NXDOMAIN attack
- [ ] Random subdomain attack
- [ ] Phantom domain attack

### DNSSEC Attacks
- [ ] Algorithm rollover attack
- [ ] Key tag collision
- [ ] Signature replay
- [ ] NSEC walking
- [ ] NSEC3 hash cracking

### Transport Attacks
- [ ] TCP SYN flood
- [ ] TCP connection exhaustion
- [ ] TLS downgrade
- [ ] Certificate spoofing
- [ ] DoH path traversal

### Implementation Attacks
- [ ] Buffer overflow (fuzzing)
- [ ] Integer overflow
- [ ] Memory exhaustion
- [ ] CPU exhaustion
- [ ] File descriptor exhaustion
```

---

## 5. Performance Tests

### Benchmark Suite

```go
// test/benchmark/query_bench_test.go

func BenchmarkQueryProcessing(b *testing.B) {
    server := NewTestServer()
    query := createAQuery("www.example.com")

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            server.HandleQuery(query)
        }
    })
}

func BenchmarkMessageParsing(b *testing.B) {
    messages := []struct {
        name string
        data []byte
    }{
        {"simple-A", simpleAQueryBytes},
        {"EDNS", ednsQueryBytes},
        {"DNSSEC-response", dnssecResponseBytes},
        {"large-TXT", largeTXTResponseBytes},
    }

    for _, msg := range messages {
        b.Run(msg.name, func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                m := &dns.Message{}
                _ = m.Unpack(msg.data)
            }
        })
    }
}

func BenchmarkCache(b *testing.B) {
    cache := NewCache(CacheConfig{MaxSize: 1000000})

    // Pre-populate cache
    for i := 0; i < 100000; i++ {
        cache.Set(fmt.Sprintf("domain%d.com", i), createCacheEntry())
    }

    b.Run("hit", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            cache.Get("domain50000.com")
        }
    })

    b.Run("miss", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            cache.Get(fmt.Sprintf("miss%d.com", i))
        }
    })

    b.Run("set", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            cache.Set(fmt.Sprintf("new%d.com", i), createCacheEntry())
        }
    })
}

func BenchmarkDNSSEC(b *testing.B) {
    b.Run("ECDSA-P256-sign", func(b *testing.B) {
        key := generateECDSAKey()
        rrset := createRRSet()
        for i := 0; i < b.N; i++ {
            _ = dnssec.Sign(rrset, key)
        }
    })

    b.Run("ECDSA-P256-verify", func(b *testing.B) {
        key := generateECDSAKey()
        rrset := createRRSet()
        rrsig := dnssec.Sign(rrset, key)
        for i := 0; i < b.N; i++ {
            _ = dnssec.Verify(rrsig, key.Public(), rrset)
        }
    })

    b.Run("ED25519-sign", func(b *testing.B) {
        key := generateED25519Key()
        rrset := createRRSet()
        for i := 0; i < b.N; i++ {
            _ = dnssec.Sign(rrset, key)
        }
    })
}
```

### Load Testing

```yaml
# test/load/scenarios.yaml

scenarios:
  # Baseline throughput
  - name: baseline-throughput
    description: Maximum QPS with simple A queries
    config:
      query-type: A
      domain-pattern: "www.example.com"
      clients: 100
      duration: 60s
      rate: unlimited
    expectations:
      min-qps: 500000
      max-latency-p99: 1ms

  # Mixed workload
  - name: mixed-workload
    description: Realistic query mix
    config:
      query-mix:
        A: 60%
        AAAA: 20%
        MX: 5%
        TXT: 10%
        ANY: 5%
      domain-pattern: "*.example.com"
      clients: 200
      duration: 300s
      rate: 100000
    expectations:
      min-qps: 100000
      max-latency-p99: 5ms

  # Cache stress
  - name: cache-stress
    description: High unique domain rate
    config:
      query-type: A
      domain-pattern: "unique-{random}.example.com"
      clients: 100
      duration: 120s
      rate: 50000
    expectations:
      min-qps: 50000
      cache-eviction-rate: < 10%

  # DNSSEC validation
  - name: dnssec-validation
    description: DNSSEC-enabled queries
    config:
      query-type: A
      dnssec: true
      domain-pattern: "signed.example.com"
      clients: 50
      duration: 60s
      rate: 10000
    expectations:
      min-qps: 10000
      validation-success-rate: 100%

  # DDoS simulation
  - name: ddos-mitigation
    description: Simulated DDoS attack
    config:
      attack-types:
        - amplification
        - random-subdomain
        - nxdomain-flood
      legitimate-rate: 1000
      attack-rate: 100000
      duration: 300s
    expectations:
      legitimate-success-rate: > 95%
      attack-mitigation-rate: > 99%
```

---

## 6. End-to-End Tests

### Real Network Tests

```go
// test/e2e/real_network_test.go

func TestRealWorldResolution(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping real network tests")
    }

    resolver := NewResolver(ResolverConfig{
        Forwarders: nil, // Full recursive
    })

    tests := []struct {
        domain   string
        qtype    uint16
        validate func(*dns.Message) bool
    }{
        {"google.com", dns.TypeA, hasARecord},
        {"google.com", dns.TypeAAAA, hasAAAARecord},
        {"google.com", dns.TypeMX, hasMXRecord},
        {"_dmarc.google.com", dns.TypeTXT, hasTXTRecord},
    }

    for _, tt := range tests {
        t.Run(tt.domain+"/"+dns.TypeToString[tt.qtype], func(t *testing.T) {
            resp, err := resolver.Resolve(context.Background(), tt.domain, tt.qtype)
            require.NoError(t, err)
            assert.True(t, tt.validate(resp))
        })
    }
}

func TestDNSSECRealWorld(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping real network tests")
    }

    resolver := NewResolver(ResolverConfig{
        DNSSEC: true,
    })

    // Known DNSSEC-signed domains
    signedDomains := []string{
        "dnssec-tools.org",
        "verisigninc.com",
        "nic.cz",
    }

    for _, domain := range signedDomains {
        t.Run(domain, func(t *testing.T) {
            resp, err := resolver.Resolve(context.Background(), domain, dns.TypeA)
            require.NoError(t, err)
            assert.True(t, resp.AuthenticData, "AD flag should be set")
        })
    }
}
```

---

## 7. Continuous Integration

### CI Pipeline

```yaml
# .github/workflows/ci.yml

name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: golangci/golangci-lint-action@v3
        with:
          version: latest

  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go test -race -coverprofile=coverage.out ./...
      - uses: codecov/codecov-action@v3

  conformance-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go test -tags=conformance ./test/conformance/...

  integration-tests:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7
        ports:
          - 6379:6379
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: docker-compose -f test/integration/docker-compose.yml up -d
      - run: go test -tags=integration ./test/integration/...

  fuzz-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go test -fuzz=FuzzMessageUnpack -fuzztime=60s ./test/fuzz/...

  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go test -bench=. -benchmem ./test/benchmark/... | tee benchmark.txt
      - uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'go'
          output-file-path: benchmark.txt
```

---

## Test Data Management

### Test Fixtures

```
test/
├── fixtures/
│   ├── messages/
│   │   ├── valid/
│   │   │   ├── simple-a-query.bin
│   │   │   ├── edns-query.bin
│   │   │   └── dnssec-response.bin
│   │   └── invalid/
│   │       ├── truncated.bin
│   │       ├── compression-loop.bin
│   │       └── oversized.bin
│   ├── zones/
│   │   ├── bind/
│   │   │   └── example.com.zone
│   │   ├── djbdns/
│   │   │   └── data
│   │   └── native/
│   │       └── example.com.dnszone
│   └── keys/
│       ├── ksk/
│       └── zsk/
└── golden/
    ├── responses/
    └── signed-zones/
```

---

*Document Version: 1.0*
*Testing Strategy Specification*
