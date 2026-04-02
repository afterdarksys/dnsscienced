# Defensive DNS Configuration

DNSScienced includes comprehensive defensive DNS features to handle broken clients, non-compliant firewalls, and edge cases commonly encountered in production DNS deployments.

## Overview

These features are based on battle-tested approaches from BIND 9 and other production DNS servers. They help work around real-world issues without compromising service availability.

## Features

### 1. Stale Answer Support (RFC 8767)

**Purpose:** Serve expired (stale) cache entries when authoritative servers are unreachable.

**Use Cases:**
- Upstream server temporarily down or slow
- Network connectivity issues to authoritative nameservers
- DDoS attacks on authoritative servers
- Improve resilience during outages

**Configuration:**
```yaml
defensive:
  stale_answers:
    enabled: true
    max_stale_time: 168h        # Maximum age of stale records (1 week)
    client_timeout: 1800ms      # Timeout before serving stale (1.8s)
    serve_on_error: true        # Serve stale on SERVFAIL
```

**Trade-offs:**
- ✅ Improved availability during outages
- ✅ Better user experience (stale data > no data)
- ⚠️ May serve outdated records
- ⚠️ TTL violations (but RFC 8767 compliant)

---

### 2. EDNS UDP Size Controls

**Purpose:** Work around broken firewalls and clients that drop large UDP packets.

**Problem:** Many firewalls and middleboxes:
- Drop UDP packets > 512 bytes
- Fail EDNS negotiation
- Fragment packets incorrectly
- Block DNS responses with EDNS0

**Configuration:**
```yaml
defensive:
  edns:
    enabled: true
    udp_size: 1232              # Safe size for most networks
    max_udp_size: 4096          # Maximum response size
```

**Size Recommendations:**
- **512**: Safest, works everywhere (pre-EDNS0 size)
- **1232**: Recommended for IPv4 (fits in typical MTU with overhead)
- **1452**: IPv6 safe size
- **4096**: Optimal but may cause issues on broken networks

**Trade-offs:**
- ✅ Works through broken firewalls
- ✅ Avoids fragmentation issues
- ⚠️ Smaller responses (may trigger TCP fallback)
- ⚠️ Reduced performance for large records (DNSSEC, TXT)

---

### 3. DNSSEC Validation Controls

**Purpose:** Handle broken DNSSEC implementations and troubleshooting.

**Configuration:**
```yaml
defensive:
  dnssec:
    validation: true
    trust_anchor_file: /etc/dnsscienced/trust-anchors.conf
    break_validation: false     # DANGER: Only for troubleshooting!
    permissive_mode: false      # Log but don't fail
    negative_trust_anchors:     # Domains to skip validation
      - broken-dnssec.example.com
```

**Options:**

**`break_validation`** ⚠️ USE WITH EXTREME CAUTION
- Completely bypasses DNSSEC validation
- Only for troubleshooting non-compliant zones
- **NEVER** enable in production without good reason
- Defeats the security benefits of DNSSEC

**`permissive_mode`**
- Logs validation failures but doesn't fail queries
- Useful for identifying broken DNSSEC without breaking service
- Better than `break_validation` for troubleshooting

**`negative_trust_anchors`**
- Selective bypass for specific broken domains
- RFC 7646 compliant approach
- Preferred over global `break_validation`

---

### 4. Fetch Quotas and Rate Limiting

**Purpose:** Prevent flooding broken or misconfigured authoritative servers.

**Problem:** Recursive resolvers can unintentionally DoS authoritative servers:
- Thundering herd on cache miss
- Broken domains causing retry storms
- Misconfigured clients hammering the resolver

**Configuration:**
```yaml
defensive:
  fetch_quotas:
    enabled: true
    fetches_per_server: 100     # Max concurrent to one server
    fetches_per_zone: 200       # Max concurrent per zone
    spillover_quota: 50         # Extra when server is slow
```

**Trade-offs:**
- ✅ Protects authoritative servers
- ✅ Prevents accidental DoS from misconfiguration
- ⚠️ May delay responses under heavy load
- ⚠️ Complex tuning for optimal performance

---

### 5. DNS Name Compression

**Purpose:** Compatibility with very old or broken DNS clients.

**Configuration:**
```yaml
defensive:
  compression:
    enabled: true               # Standard compression (RFC 1035)
    no_case_compress: false     # Disable case-preserving compression
```

**When to Disable:**
- Ancient DNS clients (pre-1990s implementations)
- Embedded devices with broken DNS parsers
- Custom DNS implementations that don't support compression

**Trade-offs:**
- ✅ Works with ancient/broken clients
- ⚠️ Larger response sizes
- ⚠️ Increased bandwidth usage
- ⚠️ May trigger UDP size limits

---

### 6. DNS Cookies (RFC 7873)

**Purpose:** Protect against amplification attacks and source address spoofing.

**Configuration:**
```yaml
defensive:
  cookies:
    require_server_cookie: false # Require valid cookie for recursion
    strict_validation: false     # Reject invalid cookies
```

**How It Works:**
1. Server sends cookie in response
2. Client includes cookie in subsequent queries
3. Server validates cookie to confirm legitimate client

**When to Enable `require_server_cookie`:**
- Under active amplification attack
- High abuse from spoofed sources
- Strict security requirements

**Trade-offs:**
- ✅ Prevents amplification attacks
- ✅ Distinguishes legitimate clients from spoofed queries
- ⚠️ Breaks clients that don't support cookies (old implementations)
- ⚠️ May cause issues with some load balancers

---

### 7. Blackhole / ACLs

**Purpose:** Block queries from known malicious or broken client networks.

**Configuration:**
```yaml
defensive:
  blackhole:
    enabled: true
    action: drop                # "drop" (silent) or "refused" (REFUSED response)
    cidrs:
      - 192.0.2.0/24           # RFC 5737 TEST-NET-1
      - 198.51.100.0/24        # RFC 5737 TEST-NET-2
```

**Actions:**
- **`drop`**: Silently drop packets (no response)
  - Good for high-volume abuse
  - Prevents response amplification
  - Client gets timeout

- **`refused`**: Send DNS REFUSED response
  - More polite (client knows query was rejected)
  - Better for legitimate misconfigurations
  - Can still be amplification vector (response > query)

**Use Cases:**
- Block abusive bot networks
- Prevent queries from RFC reserved space
- Block known attack sources
- Geographic restrictions (if needed)

---

### 8. Query Logging

**Purpose:** Track and troubleshoot non-compliant client queries.

**Configuration:**
```yaml
defensive:
  query_logging:
    enabled: true
    log_file: /var/log/dnsscienced/queries.log
    categories:
      - queries                 # All queries
      - errors                  # Query errors
      - unmatched               # Queries for non-existent zones
    include_clients:            # Only log from these networks
      - 10.0.0.0/8
    exclude_clients:            # Don't log from these
      - 127.0.0.0/8
    log_noncompliant: true      # Log protocol violations
```

**Categories:**
- **queries**: All DNS queries
- **responses**: DNS responses sent
- **errors**: Query processing errors
- **unmatched**: Queries that don't match any zone

**Performance Consideration:**
- Query logging is I/O intensive
- Can impact performance at high QPS
- Use `include_clients` to limit logging scope
- Consider separate log partition/disk

---

### 9. RRset Ordering

**Purpose:** Control order of records in responses to work around broken clients.

**Problem:** Some clients:
- Always use first IP in a list
- Don't randomize or round-robin
- Cause hotspots and uneven load distribution

**Configuration:**
```yaml
defensive:
  rrset_order:
    method: random              # "random", "cyclic", "fixed", "none"
    seed: 0                     # 0 = time-based random seed
```

**Methods:**
- **`random`**: Randomize order for each query (default, recommended)
- **`cyclic`**: Round-robin rotation (stateful)
- **`fixed`**: Always return same order (deterministic)
- **`none`**: Zone file order (no reordering)

**Use Cases:**
- Load balancing for clients that don't round-robin
- Testing and debugging (use `fixed` or seed)
- Compliance requirements (some regulations require randomization)

---

### 10. Views / Split-Horizon DNS

**Purpose:** Serve different responses to different client groups.

**Configuration:**
```yaml
defensive:
  views:
    - name: internal
      match_clients:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
      zones_dir: /opt/dnsscienced/zones/internal
      recursion: true
      priority: 100

    - name: external
      match_clients:
        - 0.0.0.0/0             # Match all (default)
      zones_dir: /opt/dnsscienced/zones/external
      recursion: false
      priority: 10
```

**How Views Work:**
1. Views are checked in **priority order** (highest first)
2. First matching view is used
3. Client IP matched against `match_clients` CIDRs
4. Different zones and policies per view

**Use Cases:**
- Internal vs external DNS (split-horizon)
- Different recursion policies (internal=yes, external=no)
- Geographic load balancing
- Compliance (different data for different regions)
- Testing (separate view for test clients)

**Priority Recommendations:**
- Specific views: High priority (100+)
- Default/catchall: Low priority (10)
- Allows specific overrides without affecting defaults

---

## Recommended Configurations

### Conservative (Maximum Compatibility)
```yaml
defensive:
  stale_answers:
    enabled: true
    max_stale_time: 24h
    client_timeout: 2s
  edns:
    enabled: true
    udp_size: 512               # Safest
  dnssec:
    validation: true
    permissive_mode: false
  compression:
    enabled: true
```

### Balanced (Recommended for Production)
```yaml
defensive:
  stale_answers:
    enabled: true
    max_stale_time: 168h        # 1 week
    client_timeout: 1800ms
  edns:
    enabled: true
    udp_size: 1232              # Works on most networks
  dnssec:
    validation: true
  fetch_quotas:
    enabled: true
    fetches_per_server: 100
  rrset_order:
    method: random
```

### Performance (Modern Clients Only)
```yaml
defensive:
  stale_answers:
    enabled: true
    max_stale_time: 168h
  edns:
    enabled: true
    udp_size: 4096              # Maximum performance
  dnssec:
    validation: true
  cookies:
    require_server_cookie: false
  rrset_order:
    method: random
```

### High Security (Under Attack)
```yaml
defensive:
  edns:
    enabled: true
    udp_size: 512               # Reduce amplification
  cookies:
    require_server_cookie: true # Require cookies
    strict_validation: true
  blackhole:
    enabled: true
    action: drop
    cidrs:
      - <attacker-networks>
  fetch_quotas:
    enabled: true
    fetches_per_server: 50      # Tighter limits
```

---

## Troubleshooting Guide

### Issue: Clients not receiving responses

**Check:**
1. `edns.udp_size` - Try lowering to 512
2. `blackhole.cidrs` - Ensure client not blackholed
3. `cookies.require_server_cookie` - Disable if enabled
4. Query logging - Check for protocol violations

### Issue: Stale data being served

**Check:**
1. `stale_answers.enabled` - Disable if not desired
2. `stale_answers.max_stale_time` - Reduce if too long
3. Upstream connectivity - Fix authoritative server issues

### Issue: DNSSEC validation failures

**Check:**
1. Trust anchors - Ensure `trust_anchor_file` is up-to-date
2. Clock sync - DNSSEC requires accurate time
3. `negative_trust_anchors` - Add broken domains
4. `permissive_mode` - Temporarily enable for troubleshooting

### Issue: High query latency

**Check:**
1. Query logging - Disable or reduce scope
2. `fetch_quotas` - May be too restrictive
3. `stale_answers.client_timeout` - May be too short
4. Upstream server performance

---

## Security Considerations

### DO NOT:
- Enable `break_validation` in production
- Set `udp_size` > 4096 (amplification risk)
- Disable `compression` without good reason
- Use `blackhole.action: refused` during amplification attacks

### DO:
- Enable `stale_answers` for resilience
- Use `cookies` for public resolvers
- Enable `query_logging` during investigations (disable after)
- Use `negative_trust_anchors` instead of `break_validation`
- Monitor and tune `fetch_quotas` based on traffic

---

## References

- RFC 8767: Serving Stale Data
- RFC 7873: DNS Cookies
- RFC 7646: Negative Trust Anchors in DNSSEC
- RFC 1035: DNS Name Compression
- BIND 9 Administrator Reference Manual
