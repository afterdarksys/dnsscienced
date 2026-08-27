# DNSScienced Security Architecture

> **Status note:** This document contains both implemented controls and older
> roadmap material. The current capability boundary is maintained in the
> [README](README.md); DoT and DoH are implemented, while DoQ remains
> experimental.

This document outlines the security features and protections built into DNSScienced.

## Critical Security Features Implemented

### 1. DNS Packet Parser Security

**Location:** `internal/packet/parser.go`

#### Compression Bomb Protection (CVE-2024-8508 Mitigation)
- **Maximum compression depth:** 20 pointer hops (Unbound standard)
- **Loop detection:** Tracks visited offsets to detect circular pointers
- **Pointer validation:** Ensures pointers are within message bounds and point backwards
- **Operation counting:** Tracks decompression operations for monitoring

#### Resource Exhaustion Protection
- **Maximum RRs per name:** 100 records (prevents memory exhaustion)
- **Maximum RRset size:** 32KB per section (prevents amplification attacks)
- **Label length validation:** Max 63 bytes per label (RFC 1035 compliance)
- **Domain length validation:** Max 255 bytes total (RFC 1035 compliance)

#### Memory Safety
- **Copy-on-parse:** Small slices are copied to prevent holding large backing arrays
- **Bounds checking:** All buffer accesses are bounds-checked before use
- **No pointer arithmetic:** Pure Go without unsafe operations

#### Performance
```
BenchmarkParseSimpleQuery-16           	 3939844	       303.1 ns/op	     224 B/op	       7 allocs/op
BenchmarkParseCompressedResponse-16    	  796473	      1488 ns/op	     776 B/op	      38 allocs/op
```

### 2. Sharded Cache Architecture

**Location:** `internal/cache/sharded.go`

#### Lock Contention Reduction
- **256 shards by default:** Distributes load across independent locks
- **Bitmasking for shard selection:** Fast `hash & mask` instead of modulo
- **Per-shard locking:** RWMutex per shard, not global lock

#### DOS Resistance
- **FNV-1a hashing:** Fast, good distribution, DOS-resistant
- **Atomic statistics:** Lock-free hit/miss counters using atomic operations
- **LRU eviction:** Oldest entries evicted when shard is full

#### Serve Stale Support (RFC 8767)
- **Configurable stale window:** Serve expired entries within time limit
- **Background refresh:** Optional prefetch of stale entries
- **Graceful degradation:** Continue serving during upstream failures

#### Memory Management
- **Background cleanup:** Periodic removal of expired entries
- **Configurable limits:** Per-shard size limits prevent unbounded growth
- **Graceful shutdown:** Cleanup goroutine management with WaitGroup

## Security Features from Design Review

### Critical Additions Needed

#### 1. Source Port Randomization
```go
// TODO: Implement in query sender
// MUST randomize UDP source ports (16 bits entropy)
// Combined with txid (16 bits) = 32 bits total
```

#### 2. Query ID Randomization
```go
// TODO: crypto/rand for transaction IDs
// Never use math/rand for security-critical randomness
import "crypto/rand"

func randomTxID() uint16 {
    var buf [2]byte
    rand.Read(buf[:])
    return binary.BigEndian.Uint16(buf[:])
}
```

#### 3. TSIG Constant-Time Comparison
```go
// TODO: Implement in TSIG validator
import "crypto/subtle"

func validateTSIG(computed, received []byte) bool {
    return subtle.ConstantTimeCompare(computed, received) == 1
}
```

#### 4. Goroutine Worker Pool
```go
// TODO: Replace unbounded goroutine spawning
type QueryWorkerPool struct {
    queue   chan *queryJob
    workers int
}

// Fixed number of workers (e.g., runtime.NumCPU() * 4)
// Prevents goroutine exhaustion under attack
```

#### 5. Buffer Pooling
```go
// TODO: Implement sync.Pool for messages and buffers
var msgPool = sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}
```

## Attack Vectors Mitigated

### 1. Cache Poisoning
- ✅ Compression bomb protection (loop detection, depth limits)
- ✅ Hash-based cache keys (DOS-resistant FNV-1a)
- ⏳ Source port randomization (TODO)
- ⏳ Transaction ID randomization (TODO)
- ⏳ 0x20 encoding (TODO)

### 2. Resource Exhaustion
- ✅ RRset size limits (32KB max)
- ✅ RR count limits (100 per name)
- ✅ Sharded cache (prevents lock contention)
- ✅ Background cleanup (prevents memory leaks)
- ⏳ Worker pools (TODO - prevent goroutine explosion)
- ⏳ TCP connection limits (TODO)

### 3. Amplification Attacks
- ✅ Message size validation
- ⏳ Response rate limiting (RRL) (TODO)
- ⏳ DNS Cookies (RFC 7873) (TODO)
- ⏳ Minimal responses (TODO)
- ⏳ TC bit forcing for large responses (TODO)

### 4. DNSSEC Attacks
- ⏳ Algorithm downgrade protection (TODO)
- ⏳ Key rollover validation (TODO)
- ⏳ NSEC3 iteration limits (TODO)
- ⏳ Trust anchor management (TODO)

### 5. Memory Safety
- ✅ No unsafe pointer operations
- ✅ Bounds checking on all buffer access
- ✅ Copy small slices to prevent backing array retention
- ✅ Atomic operations for shared counters

## Testing & Validation

### Test Coverage
- ✅ Unit tests for all packet parsing edge cases
- ✅ Compression bomb detection tests
- ✅ RRset size limit tests
- ✅ Fuzzing infrastructure (`go test -fuzz`)
- ⏳ Integration tests (TODO)
- ⏳ Load testing (TODO)

### Fuzzing
```bash
# Run continuous fuzzing
go test -fuzz=FuzzParser -fuzztime=1h ./internal/packet
```

### Security Auditing
- ⏳ External security audit (TODO)
- ⏳ Penetration testing (TODO)
- ⏳ Formal verification of critical paths (TODO)

## Unique Security Innovations

### Planned Features

#### 1. AI-Powered Threat Detection
- **On-device ML inference:** TensorFlow Lite models for DGA detection
- **Real-time classification:** <1ms latency per query
- **Pattern learning:** Adaptive threat detection

#### 2. Quantum-Resistant DNSSEC
- **Hybrid signing:** ECDSA + post-quantum (SPHINCS+)
- **Gradual rollout:** Support both during transition
- **Auto-upgrade:** When parent zone supports PQ

#### 3. Zero-Knowledge Queries
- **Oblivious DoH (ODoH):** RFC 9230 implementation
- **Homomorphic encryption:** Process encrypted queries (experimental)
- **Private Information Retrieval:** Server doesn't know which record was fetched

#### 4. Blockchain Trust Anchors
- **Multi-chain verification:** Ethereum, Solana, custom chain
- **Consensus-based trust:** Require 2/3 chains agree
- **Tamper-proof history:** Impossible to retroactively modify

#### 5. Self-Healing Infrastructure
- **Automatic failover:** ML-based remediation selection
- **Synthetic monitoring:** Health checks with canary queries
- **Adaptive responses:** Automatically adjust to load/attacks

## Compliance & Auditing

### Audit Mode Features
- **Immutable logs:** Blockchain or write-once storage
- **Cryptographic proofs:** SNARK proofs of correct operation
- **GDPR compliance:** IP hashing, configurable retention
- **HIPAA compliance:** Encrypted storage, access controls

## RFC Compliance

### Implemented
- RFC 1035: DNS wire format
- RFC 2181: DNS clarifications
- RFC 8767: Serve stale data (cache only)

### In Progress
- RFC 7858: DNS over TLS (DoT)
- RFC 8484: DNS over HTTPS (DoH)
- RFC 7873: DNS Cookies
- RFC 8198: Aggressive NSEC caching
- RFC 8624: DNSSEC algorithm requirements

### Planned
- RFC 9250: DNS over QUIC (DoQ)
- RFC 9230: Oblivious DoH (ODoH)
- RFC 7816: Query name minimization
- RFC 8914: Extended DNS Errors (EDE)

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, email: security@dnsscience.io (or create when ready)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to respond within 48 hours and issue fixes within 7 days for critical issues.

## Security Best Practices for Deployment

### Network Configuration
1. **Firewall rules:** Limit DNS ports (53, 853, 443) to necessary traffic
2. **Rate limiting:** Use kernel-level rate limiting (nftables, iptables)
3. **DDoS protection:** Deploy behind Cloudflare, AWS Shield, or similar
4. **Monitoring:** Set up alerts for query rate spikes, error rates

### System Configuration
1. **User privileges:** Run as non-root user (dns or dnsscienced)
2. **Chroot jail:** Isolate process with minimal filesystem access
3. **Seccomp/AppArmor:** Restrict system calls (Linux)
4. **Resource limits:** Set ulimits for memory, file descriptors

### Application Configuration
1. **DNSSEC validation:** Always enable for recursive resolvers
2. **Minimal logging:** Don't log full client IPs (GDPR)
3. **Regular updates:** Keep dnsscienced and dependencies current
4. **Backup keys:** Secure offsite backup of DNSSEC keys

## Security Changelog

### Version 0.1.0 (Current)
- ✅ Compression bomb protection (CVE-2024-8508 mitigation)
- ✅ RRset size limits
- ✅ Sharded cache with lock-free counters
- ✅ Serve stale support
- ✅ Fuzzing infrastructure

### Upcoming
- ⏳ Response Rate Limiting (RRL)
- ⏳ DNS Cookies support
- ⏳ DoT/DoH/DoQ transports
- ⏳ DNSSEC validation engine
- ⏳ Worker pool implementation

---

**Last Updated:** 2026-01-27
**Version:** 0.1.0-alpha
**Maintainers:** DNS Science Team
