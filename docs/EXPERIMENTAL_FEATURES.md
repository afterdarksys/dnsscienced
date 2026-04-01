# Experimental IETF Draft Features

## Overview

DNSScienced supports experimental and draft IETF protocols through a comprehensive configuration framework. These features are **disabled by default** to ensure production stability and can be selectively enabled based on deployment needs.

⚠️ **Warning**: Experimental features may have security, stability, or interoperability issues. Use in production at your own risk.

## Quick Start

Enable experimental features in your configuration file:

```yaml
server:
  experimental:
    enabled: true  # Master switch for all experimental features

    # Enable specific protocols as needed
    dns_sd:
      enabled: true
    doq:
      enabled: true
```

## Supported Protocols

### 1. DNS-SD Service Registration Protocol (RFC 9665)

**Status**: RFC Published
**Use Case**: IoT device and service registration

DNS Service Discovery (DNS-SD) with Service Registration Protocol (SRP) allows devices to dynamically register their services in DNS without manual configuration.

**Key Features**:
- Dynamic service registration
- Automatic lease management
- Multi-service support per client
- Authentication support

**Configuration**:
```yaml
experimental:
  dns_sd:
    enabled: true
    allow_registration: true
    default_ttl: 3600s
    max_services_per_client: 10
    lease_timeout: 7200s
    require_auth: true
    browse_domains:
      - "local."
      - "_services._dns-sd._udp.local."
```

**Example Use Cases**:
- IoT sensor registration
- Printer/scanner discovery
- Smart home device announcements
- Zeroconf/Bonjour replacements

**Protocol Details**:
- Port: 53 (standard DNS)
- Update mechanism: DNS UPDATE (RFC 2136)
- Service naming: `_service._proto.domain`

---

### 2. DNS over QUIC (RFC 9250)

**Status**: RFC Published
**Use Case**: Modern encrypted DNS transport

DNS over QUIC (DoQ) provides encrypted DNS queries using the QUIC protocol, offering improved performance over DoT/DoH with features like 0-RTT and connection migration.

**Key Features**:
- Encrypted transport (TLS 1.3)
- Multiplexed streams
- 0-RTT support (optional)
- Better performance than TCP-based protocols
- Connection migration support

**Configuration**:
```yaml
experimental:
  doq:
    enabled: true
    address: ":853"
    cert_file: "/etc/dnsscienced/tls/cert.pem"
    key_file: "/etc/dnsscienced/tls/key.pem"
    max_streams: 100
    idle_timeout: 30s
    enable_0rtt: false  # Security vs performance trade-off
```

**Security Considerations**:
- Requires valid TLS certificates
- 0-RTT may enable replay attacks
- Default port: 853 (IANA assigned)

**Performance Benefits**:
- Faster connection establishment
- Better congestion control
- Head-of-line blocking eliminated

---

### 3. DNS Stateful Operations (RFC 8490)

**Status**: RFC Published
**Use Case**: Long-lived DNS connections with push notifications

DSO enables stateful DNS sessions over persistent connections, supporting push notifications and subscriptions for dynamic data.

**Key Features**:
- Long-lived TCP connections
- Server-initiated push notifications
- Subscribe to query updates
- Session keepalive
- Graceful session termination

**Configuration**:
```yaml
experimental:
  dso:
    enabled: true
    keep_alive: 60s
    inactivity_timeout: 300s
    max_sessions: 1000
    enable_push: true
    enable_subscribe: true
```

**Use Cases**:
- Real-time monitoring dashboards
- Dynamic service discovery
- Zone transfer notifications
- Instant cache invalidation

**Protocol Flow**:
1. Client establishes DSO session
2. Negotiates capabilities (push, subscribe)
3. Maintains connection with keepalives
4. Server pushes updates as they occur

---

### 4. DELEG Record (draft-ietf-dnsop-deleg)

**Status**: IETF Draft
**Use Case**: Extensible DNS delegation

The DELEG record provides an extensible mechanism for DNS delegation, supporting modern protocols like DoH, DoT, and SVCB-style parameters.

**Key Features**:
- Extensible delegation metadata
- Support for DoH/DoT endpoints
- IPv4/IPv6 addresses
- Service binding parameters
- Replaces/enhances NS records

**Configuration**:
```yaml
experimental:
  deleg:
    enabled: true
    allow_in_zones: true
    enable_caching: true
    cache_ttl: 3600s
    supported_types:
      - "ipv4"
      - "ipv6"
      - "dohpath"
      - "svcb"
```

**Zone File Example**:
```
example.com.  IN  DELEG  0 ns1 (
                         ipv4=192.0.2.1
                         ipv6=2001:db8::1
                         dohpath=/dns-query
                       )
```

**Migration Path**:
- Coexists with NS records
- Gradual rollout support
- Fallback to legacy NS

---

### 5. DNS DID (draft-duda-dnsop-dns-did)

**Status**: IETF Draft
**Use Case**: Decentralized identifiers in DNS

DNS DID enables decentralized identity infrastructure using DNS as a trust anchor, supporting W3C DID specifications.

**Key Features**:
- DID document resolution via DNS
- Signature verification
- Multiple DID methods
- Trust anchor support
- Caching for performance

**Configuration**:
```yaml
experimental:
  did:
    enabled: true
    supported_methods:
      - "did:dns"
      - "did:web"
    resolution_timeout: 5s
    enable_caching: true
    cache_ttl: 3600s
    verify_signatures: true
    trust_anchor: ""  # Optional root trust anchor
```

**DID Resolution Example**:
```
Query: did:dns:example.com
→ Lookup: _did.example.com. TXT
→ Returns: DID document (JSON-LD)
→ Verify: Cryptographic signatures
```

**Use Cases**:
- Decentralized authentication
- Verifiable credentials
- Self-sovereign identity
- Blockchain-free DID infrastructure

---

### 6. IoT DNS Guidelines (draft-ietf-iotops-iot-dns-guidelines)

**Status**: IETF Draft
**Use Case**: DNS optimizations for IoT and constrained devices

Implements best practices for DNS in IoT environments, focusing on battery life, bandwidth conservation, and constrained device support.

**Key Features**:
- Aggressive negative caching
- TTL adjustments for battery saving
- UDP payload size optimization
- Minimal response mode
- DNS push for efficiency
- CoAP integration

**Configuration**:
```yaml
experimental:
  iot_dns:
    enabled: true
    aggressive_ncaching: true
    min_ttl: 300s   # 5 minutes - prevent battery drain
    max_ttl: 86400s # 24 hours
    optimize_udp_size: true
    max_udp_payload: 512  # Conservative for constrained devices
    minimal_responses: true
    enable_push: true
    coap_optimization: false
```

**Optimizations**:

1. **TTL Management**: Prevents frequent re-queries
2. **Payload Minimization**: Reduces bandwidth usage
3. **Negative Caching**: Avoids repeated NXDOMAIN queries
4. **Push Notifications**: Eliminates polling
5. **UDP Size Limits**: Prevents fragmentation

**Battery Impact**:
- Normal DNS: ~100 queries/day = high battery drain
- Optimized DNS: ~10 queries/day = minimal impact

---

## Configuration Best Practices

### Production Deployment

**Conservative Approach** (Recommended):
```yaml
experimental:
  enabled: false  # Disable all experimental features
```

**Selective Enablement**:
```yaml
experimental:
  enabled: true

  # Only enable stable, published RFCs
  dns_sd:
    enabled: true
  doq:
    enabled: true
  dso:
    enabled: true

  # Keep drafts disabled
  deleg:
    enabled: false
  did:
    enabled: false
  iot_dns:
    enabled: false
```

### Testing/Development

**Full Experimental**:
```yaml
experimental:
  enabled: true
  dns_sd:
    enabled: true
  doq:
    enabled: true
  dso:
    enabled: true
  deleg:
    enabled: true
  did:
    enabled: true
  iot_dns:
    enabled: true
```

## Logging and Monitoring

When experimental features are enabled, DNSScienced logs them at startup:

```
⚠️  Experimental Features Enabled (3):
   • DNS-SD SRP (RFC 9665)
   • DNS over QUIC (RFC 9250)
   • DNS Stateful Operations (RFC 8490)
```

Enable verbose logging to track feature usage:
```yaml
logging:
  level: debug
  experimental_metrics: true
```

## Security Considerations

### General Guidelines

1. **Isolation**: Run experimental features in isolated environments
2. **Authentication**: Enable authentication where supported
3. **Rate Limiting**: Apply strict rate limits
4. **Monitoring**: Watch for anomalous behavior
5. **Fallback**: Ensure graceful degradation

### Per-Feature Security

| Feature | Security Level | Risks | Mitigations |
|---------|---------------|-------|-------------|
| DNS-SD | Medium | Unauthorized registration | Require authentication |
| DoQ | High | TLS vulnerabilities | Use strong ciphers, disable 0-RTT |
| DSO | Medium | Resource exhaustion | Limit max sessions |
| DELEG | Low | Cache poisoning | Validate DNSSEC |
| DID | High | Signature bypass | Verify all signatures |
| IoT DNS | Low | TTL manipulation | Enforce min/max TTL |

## Performance Impact

### Resource Usage

| Feature | CPU Impact | Memory Impact | Bandwidth Impact |
|---------|-----------|---------------|------------------|
| DNS-SD | Low | Medium | Low |
| DoQ | Medium | High | Low (encrypted) |
| DSO | Low | Medium | Low |
| DELEG | Minimal | Low | Minimal |
| DID | Medium | Medium | Medium |
| IoT DNS | Minimal | Low | Reduced |

### Benchmarks

*Coming soon: Performance benchmarks for each experimental feature*

## Compatibility Matrix

| Feature | Client Support | Server Support | Standards Status |
|---------|---------------|----------------|------------------|
| DNS-SD | iOS, Android, mDNS clients | DNSScienced | RFC 9665 |
| DoQ | curl 8+, Firefox 112+ | DNSScienced | RFC 9250 |
| DSO | Custom clients | DNSScienced | RFC 8490 |
| DELEG | None (draft) | DNSScienced | Draft |
| DID | DID resolvers | DNSScienced | Draft |
| IoT DNS | IoT devices | DNSScienced | Draft |

## Troubleshooting

### Feature Not Working

1. **Check master switch**:
   ```yaml
   experimental:
     enabled: true  # Must be true
   ```

2. **Check feature flag**:
   ```yaml
   experimental:
     doq:
       enabled: true  # Individual feature
   ```

3. **Check logs**:
   ```bash
   journalctl -u dnsscienced | grep -i experimental
   ```

4. **Verify configuration**:
   ```bash
   dnsscienced -config config.yaml -check
   ```

### Common Issues

**DoQ not listening**:
- Check TLS certificates exist
- Verify port 853 not in use
- Check firewall rules

**DNS-SD registration failing**:
- Enable authentication
- Check browse domains
- Verify update permissions

**DSO sessions dropping**:
- Increase keepalive interval
- Check inactivity timeout
- Monitor max sessions limit

## Contributing

Help improve experimental feature support:

1. **Test**: Deploy in lab environments
2. **Report**: File issues on GitHub
3. **Document**: Share use cases and configs
4. **Benchmark**: Run performance tests
5. **Contribute**: Submit patches and improvements

## References

### RFCs
- [RFC 9665](https://www.rfc-editor.org/rfc/rfc9665.html) - DNS-SD Service Registration Protocol
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) - DNS over Dedicated QUIC Connections
- [RFC 8490](https://www.rfc-editor.org/rfc/rfc8490.html) - DNS Stateful Operations

### IETF Drafts
- [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) - DELEG Record
- [draft-duda-dnsop-dns-did](https://datatracker.ietf.org/doc/draft-duda-dnsop-dns-did/) - DNS DID
- [draft-ietf-iotops-iot-dns-guidelines](https://datatracker.ietf.org/doc/draft-ietf-iotops-iot-dns-guidelines/) - IoT DNS Guidelines

### Example Configurations
- [config-experimental.yaml](../examples/config-experimental.yaml) - Full example config
- [README.md](../README.md) - Main documentation

## Support

For questions or issues with experimental features:
- GitHub Issues: https://github.com/dnsscience/dnsscienced/issues
- Tag with: `experimental`
- Provide: Config file, logs, DNS queries

---

### 7. PROXY Protocol v2 (HAProxy Support)

**Status**: Industry Standard
**Use Case**: Running DNS behind load balancers while preserving client IPs

PROXY protocol v2 allows DNSScienced to run behind HAProxy, nginx, or other load balancers while preserving the original client IP address for logging, ACLs, and rate limiting.

**Key Features**:
- Client IP preservation behind load balancers
- Trusted proxy verification
- Mixed mode support (proxied + direct connections)
- X-Forwarded-For fallback (optional)
- Header timeout protection

**Configuration**:
```yaml
experimental:
  proxyv2:
    enabled: true
    trusted_proxies:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.1/8"
      - "::1/128"
    require_header: false
    header_timeout: 5s
    allow_xff: false
    log_headers: false
    reject_non_proxied: false
```

**HAProxy Configuration**:
```
frontend dns_frontend
    bind :53
    mode tcp
    option tcplog
    default_backend dns_backend

backend dns_backend
    mode tcp
    balance roundrobin
    option tcp-check
    
    # Enable PROXY protocol
    server dns1 10.0.1.10:53 send-proxy-v2 check
    server dns2 10.0.1.11:53 send-proxy-v2 check
    server dns3 10.0.1.12:53 send-proxy-v2 check
```

**nginx Stream Configuration**:
```nginx
stream {
    upstream dns_backend {
        server 10.0.1.10:53;
        server 10.0.1.11:53;
        server 10.0.1.12:53;
    }

    server {
        listen 53;
        proxy_pass dns_backend;
        proxy_protocol on;
    }
}
```

**Security Considerations**:
- **Always** restrict `trusted_proxies` to known load balancer IPs
- Consider `require_header: true` for dedicated proxy deployments
- Use `reject_non_proxied: true` to block direct connections
- Monitor for PROXY header spoofing attempts

**Deployment Scenarios**:

1. **High Availability**:
   - HAProxy frontend on multiple nodes
   - DNSScienced backends receive PROXY headers
   - Client IP preserved for ACLs and RRL

2. **DDoS Protection**:
   - Cloudflare/AWS Shield → nginx → DNSScienced
   - Real client IPs available for rate limiting
   - PROXY protocol preserves source address

3. **Multi-Datacenter**:
   - GeoDNS load balancer
   - Regional HAProxy instances
   - Central DNSScienced cluster

**Performance Impact**:
- Negligible CPU overhead
- +16 bytes per TCP connection header
- No impact on UDP (not supported by PROXY protocol)

**Limitations**:
- TCP only (PROXY protocol doesn't support UDP)
- Requires trusted network between proxy and DNS server
- Additional parsing latency (~100-200ns)

---

## Updated Protocol Summary

| Feature | Status | Port | Protocol | Use Case |
|---------|--------|------|----------|----------|
| DNS-SD SRP | RFC 9665 | 53 | UDP/TCP | IoT service registration |
| DoQ | RFC 9250 | 853 | QUIC/UDP | Encrypted DNS with 0-RTT |
| DSO | RFC 8490 | 53 | TCP | Push notifications |
| DELEG | Draft | 53 | UDP/TCP | Extensible delegation |
| DID | Draft | 53 | UDP/TCP | Decentralized identity |
| IoT DNS | Draft | 53 | UDP/TCP | IoT optimizations |
| **PROXYv2** | **Standard** | **any** | **TCP** | **Load balancer support** |
