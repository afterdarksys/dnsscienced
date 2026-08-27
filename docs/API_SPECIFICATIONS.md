# DNSScienced API Specifications

> **Mixed implementation/design reference:** Some interfaces in this document
> are proposed and may not exist in the current build. Confirm availability in
> source and generated gRPC definitions. Current capability boundaries are
> summarized in the [README](../README.md).

## Overview

This document specifies all internal and external APIs for DNSScienced, including:
- REST Management API
- Control Socket API
- Plugin API
- Internal Package APIs

---

## REST Management API

### Base URL and Versioning

```
Base URL: https://<server>:8443/api/v1
Content-Type: application/json
Authentication: Bearer token or mTLS
```

### Authentication

```yaml
# API Key Authentication
Authorization: Bearer <api-key>

# mTLS Authentication
Client Certificate: Required
Subject: CN=admin,O=example.com

# Response format for all endpoints
response_format:
  success:
    status: "success"
    data: <response_data>
    meta:
      request_id: "uuid"
      timestamp: "ISO8601"

  error:
    status: "error"
    error:
      code: "ERROR_CODE"
      message: "Human-readable message"
      details: {}
    meta:
      request_id: "uuid"
      timestamp: "ISO8601"
```

---

### Server Endpoints

#### GET /server/status

Returns server health and operational status.

```yaml
Request:
  Method: GET
  Path: /api/v1/server/status

Response:
  status: "success"
  data:
    server:
      id: "auth1.example.com"
      version: "1.2.3"
      uptime_seconds: 86400
      daemon: "dnsscience-authd"

    health:
      status: "healthy"  # healthy, degraded, unhealthy
      checks:
        - name: "zones"
          status: "pass"
        - name: "dnssec"
          status: "pass"
        - name: "cache"
          status: "pass"

    resources:
      cpu_percent: 15.5
      memory_bytes: 1073741824
      memory_percent: 12.5
      goroutines: 150
      file_descriptors: 1024

    network:
      connections:
        udp: 0
        tcp: 150
        tls: 25
        https: 10
```

#### GET /server/config

Returns current configuration (sensitive values redacted).

```yaml
Request:
  Method: GET
  Path: /api/v1/server/config
  Query Parameters:
    - section: string (optional, e.g., "network", "zones", "security")

Response:
  status: "success"
  data:
    config:
      global:
        server-id: "auth1.example.com"
      network:
        listen:
          - address: "0.0.0.0"
            port: 53
      # ... (configuration tree)
```

#### POST /server/reload

Triggers configuration reload.

```yaml
Request:
  Method: POST
  Path: /api/v1/server/reload
  Body:
    sections:  # Optional: reload specific sections only
      - "zones"
      - "acl"

Response:
  status: "success"
  data:
    reload:
      status: "completed"
      duration_ms: 150
      reloaded:
        - "zones"
        - "acl"
      warnings: []
```

---

### Statistics Endpoints

#### GET /stats

Returns comprehensive query statistics.

```yaml
Request:
  Method: GET
  Path: /api/v1/stats
  Query Parameters:
    - period: string (1m, 5m, 1h, 24h, 7d)
    - breakdown: string (type, rcode, transport, zone)

Response:
  status: "success"
  data:
    period: "5m"
    timestamp: "2024-01-15T10:30:00Z"

    queries:
      total: 1500000
      per_second: 5000

      by_type:
        A: 750000
        AAAA: 300000
        MX: 50000
        TXT: 100000
        OTHER: 300000

      by_rcode:
        NOERROR: 1400000
        NXDOMAIN: 80000
        SERVFAIL: 5000
        REFUSED: 15000

      by_transport:
        udp: 1200000
        tcp: 200000
        dot: 80000
        doh: 20000

    latency:
      avg_ms: 0.5
      p50_ms: 0.3
      p95_ms: 1.2
      p99_ms: 5.0

    cache:
      size_entries: 500000
      size_bytes: 524288000
      hit_rate: 0.85
      hits: 1275000
      misses: 225000

    dnssec:
      validations_total: 450000
      secure: 400000
      insecure: 40000
      bogus: 10000
```

#### GET /stats/zones/{zone}

Returns per-zone statistics.

```yaml
Request:
  Method: GET
  Path: /api/v1/stats/zones/example.com
  Query Parameters:
    - period: string (1m, 5m, 1h, 24h)

Response:
  status: "success"
  data:
    zone: "example.com"
    period: "5m"

    queries:
      total: 50000
      per_second: 166

      by_type:
        A: 30000
        AAAA: 15000
        MX: 5000

      by_rcode:
        NOERROR: 48000
        NXDOMAIN: 2000

    top_queried:
      - name: "www.example.com"
        count: 15000
      - name: "mail.example.com"
        count: 8000
      - name: "api.example.com"
        count: 5000
```

#### GET /stats/clients

Returns client statistics.

```yaml
Request:
  Method: GET
  Path: /api/v1/stats/clients
  Query Parameters:
    - limit: int (default: 100)
    - sort: string (queries, rate_limited)
    - period: string (5m, 1h, 24h)

Response:
  status: "success"
  data:
    period: "5m"
    clients:
      - ip: "10.0.1.100"
        queries: 5000
        rate_limited: false
        by_type:
          A: 3000
          AAAA: 2000

      - ip: "10.0.1.101"
        queries: 50000
        rate_limited: true
        rate_limit_drops: 45000
```

---

### Zone Management Endpoints

#### GET /zones

List all configured zones.

```yaml
Request:
  Method: GET
  Path: /api/v1/zones
  Query Parameters:
    - type: string (primary, secondary, stub, forward)

Response:
  status: "success"
  data:
    zones:
      - name: "example.com"
        type: "primary"
        serial: 2024011501
        records: 150
        dnssec:
          enabled: true
          algorithm: "ECDSAP256SHA256"
          ksk_id: 12345
          zsk_id: 67890
        status: "loaded"
        last_reload: "2024-01-15T10:00:00Z"

      - name: "example.org"
        type: "secondary"
        serial: 2024011401
        primary: "192.0.2.1"
        status: "loaded"
        last_transfer: "2024-01-15T08:00:00Z"
```

#### GET /zones/{zone}

Get zone details and records.

```yaml
Request:
  Method: GET
  Path: /api/v1/zones/example.com
  Query Parameters:
    - include_records: bool (default: false)
    - record_type: string (filter by type)

Response:
  status: "success"
  data:
    zone:
      name: "example.com"
      type: "primary"
      file: "/etc/dnsscienced/zones/example.com.dnszone"

      soa:
        primary: "ns1.example.com"
        admin: "hostmaster.example.com"
        serial: 2024011501
        refresh: 3600
        retry: 600
        expire: 604800
        minimum: 300

      dnssec:
        enabled: true
        algorithm: "ECDSAP256SHA256"
        ksk:
          id: 12345
          created: "2024-01-01T00:00:00Z"
          expires: "2025-01-01T00:00:00Z"
        zsk:
          id: 67890
          created: "2024-01-01T00:00:00Z"
          expires: "2024-04-01T00:00:00Z"

      transfer:
        allow:
          - "192.0.2.0/24"
        notify:
          - "192.0.2.2"
          - "192.0.2.3"

      statistics:
        queries_total: 500000
        queries_per_second: 100

    records:  # If include_records=true
      - name: "@"
        type: "NS"
        ttl: 3600
        data: "ns1.example.com."
      - name: "www"
        type: "A"
        ttl: 300
        data: "192.0.2.10"
```

#### POST /zones/{zone}/reload

Reload zone from file.

```yaml
Request:
  Method: POST
  Path: /api/v1/zones/example.com/reload

Response:
  status: "success"
  data:
    reload:
      zone: "example.com"
      status: "completed"
      serial:
        old: 2024011501
        new: 2024011502
      records: 152
      duration_ms: 50
```

#### POST /zones/{zone}/notify

Send NOTIFY to secondaries.

```yaml
Request:
  Method: POST
  Path: /api/v1/zones/example.com/notify
  Body:
    servers:  # Optional: specific servers
      - "192.0.2.2"

Response:
  status: "success"
  data:
    notify:
      zone: "example.com"
      serial: 2024011502
      sent_to:
        - server: "192.0.2.2"
          status: "acknowledged"
        - server: "192.0.2.3"
          status: "acknowledged"
```

#### POST /zones/{zone}/transfer

Initiate zone transfer (secondary zones).

```yaml
Request:
  Method: POST
  Path: /api/v1/zones/example.org/transfer
  Body:
    type: "ixfr"  # axfr or ixfr
    server: "192.0.2.1"  # Optional: specific primary

Response:
  status: "success"
  data:
    transfer:
      zone: "example.org"
      type: "ixfr"
      status: "completed"
      serial:
        old: 2024011401
        new: 2024011501
      records_changed: 5
      duration_ms: 150
```

#### POST /zones/{zone}/records

Add or update records (Dynamic DNS).

```yaml
Request:
  Method: POST
  Path: /api/v1/zones/example.com/records
  Body:
    updates:
      - operation: "add"
        name: "new-host"
        type: "A"
        ttl: 300
        data: "192.0.2.100"

      - operation: "delete"
        name: "old-host"
        type: "A"

      - operation: "update"
        name: "www"
        type: "A"
        old_data: "192.0.2.10"
        new_data: "192.0.2.11"
        ttl: 300

Response:
  status: "success"
  data:
    updates:
      applied: 3
      new_serial: 2024011503
      results:
        - operation: "add"
          name: "new-host.example.com"
          status: "success"
        - operation: "delete"
          name: "old-host.example.com"
          status: "success"
        - operation: "update"
          name: "www.example.com"
          status: "success"
```

---

### Cache Management Endpoints

#### GET /cache/stats

Get cache statistics.

```yaml
Request:
  Method: GET
  Path: /api/v1/cache/stats

Response:
  status: "success"
  data:
    cache:
      backend: "memory"  # memory, redis
      size:
        entries: 500000
        bytes: 524288000
        max_bytes: 1073741824
        utilization: 0.49

      performance:
        hit_rate: 0.85
        hits_total: 12750000
        misses_total: 2250000

      entries_by_type:
        A: 200000
        AAAA: 150000
        CNAME: 50000
        MX: 30000
        TXT: 40000
        NS: 20000
        OTHER: 10000

      ttl:
        avg_seconds: 1800
        min_seconds: 60
        max_seconds: 86400

      evictions:
        total: 50000
        by_reason:
          expired: 45000
          lru: 5000
```

#### GET /cache/lookup

Look up specific cache entries.

```yaml
Request:
  Method: GET
  Path: /api/v1/cache/lookup
  Query Parameters:
    - name: string (required)
    - type: string (optional, e.g., "A", "AAAA")

Response:
  status: "success"
  data:
    entries:
      - name: "example.com"
        type: "A"
        class: "IN"
        ttl: 250
        original_ttl: 300
        data: "93.184.216.34"
        cached_at: "2024-01-15T10:25:00Z"
        expires_at: "2024-01-15T10:30:00Z"
        source: "198.51.100.1"
        dnssec_status: "secure"

      - name: "example.com"
        type: "AAAA"
        class: "IN"
        ttl: 250
        original_ttl: 300
        data: "2606:2800:220:1:248:1893:25c8:1946"
        cached_at: "2024-01-15T10:25:00Z"
        expires_at: "2024-01-15T10:30:00Z"
```

#### DELETE /cache

Flush cache entries.

```yaml
Request:
  Method: DELETE
  Path: /api/v1/cache
  Body:
    scope: "all"  # all, domain, type

    # For domain scope
    domain: "example.com"
    include_subdomains: true

    # For type scope
    type: "A"

Response:
  status: "success"
  data:
    flush:
      scope: "domain"
      domain: "example.com"
      entries_removed: 150
```

---

### DNSSEC Management Endpoints

#### GET /dnssec/status/{zone}

Get DNSSEC status for zone.

```yaml
Request:
  Method: GET
  Path: /api/v1/dnssec/status/example.com

Response:
  status: "success"
  data:
    zone: "example.com"
    dnssec:
      enabled: true
      signed: true
      algorithm: "ECDSAP256SHA256"

      keys:
        ksk:
          - id: 12345
            algorithm: "ECDSAP256SHA256"
            flags: 257
            created: "2024-01-01T00:00:00Z"
            published: "2024-01-01T00:00:00Z"
            activated: "2024-01-02T00:00:00Z"
            inactive: null
            deleted: null
            status: "active"
            ds_records:
              - digest_type: "SHA-256"
                digest: "abc123..."
              - digest_type: "SHA-384"
                digest: "def456..."

        zsk:
          - id: 67890
            algorithm: "ECDSAP256SHA256"
            flags: 256
            created: "2024-01-01T00:00:00Z"
            activated: "2024-01-01T00:00:00Z"
            inactive: "2024-04-01T00:00:00Z"
            status: "active"

          - id: 67891
            algorithm: "ECDSAP256SHA256"
            flags: 256
            created: "2024-03-15T00:00:00Z"
            status: "published"  # Pre-published for rollover

      validation:
        last_check: "2024-01-15T10:00:00Z"
        chain_valid: true
        signatures_valid: true
        expiring_soon: false
```

#### POST /dnssec/sign/{zone}

Re-sign zone.

```yaml
Request:
  Method: POST
  Path: /api/v1/dnssec/sign/example.com
  Body:
    increment_serial: true

Response:
  status: "success"
  data:
    signing:
      zone: "example.com"
      status: "completed"
      serial:
        old: 2024011502
        new: 2024011503
      signatures:
        created: 150
        duration_ms: 250
```

#### POST /dnssec/rollover/{zone}

Initiate key rollover.

```yaml
Request:
  Method: POST
  Path: /api/v1/dnssec/rollover/example.com
  Body:
    key_type: "zsk"  # ksk or zsk
    algorithm: "ECDSAP256SHA256"  # Optional: change algorithm

Response:
  status: "success"
  data:
    rollover:
      zone: "example.com"
      key_type: "zsk"
      status: "initiated"

      old_key:
        id: 67890
        status: "active"
        will_inactive: "2024-01-22T00:00:00Z"
        will_delete: "2024-01-29T00:00:00Z"

      new_key:
        id: 67892
        status: "published"
        will_activate: "2024-01-22T00:00:00Z"

      timeline:
        - phase: "publish"
          date: "2024-01-15T00:00:00Z"
          status: "completed"
        - phase: "activate"
          date: "2024-01-22T00:00:00Z"
          status: "pending"
        - phase: "retire_old"
          date: "2024-01-22T00:00:00Z"
          status: "pending"
        - phase: "delete_old"
          date: "2024-01-29T00:00:00Z"
          status: "pending"
```

#### GET /dnssec/ds/{zone}

Get DS records for parent delegation.

```yaml
Request:
  Method: GET
  Path: /api/v1/dnssec/ds/example.com

Response:
  status: "success"
  data:
    zone: "example.com"
    ds_records:
      - key_tag: 12345
        algorithm: 13
        digest_type: 2
        digest: "abc123def456..."
        record: "example.com. IN DS 12345 13 2 abc123def456..."

      - key_tag: 12345
        algorithm: 13
        digest_type: 4
        digest: "789ghi012jkl..."
        record: "example.com. IN DS 12345 13 4 789ghi012jkl..."
```

---

### Security Endpoints

#### GET /security/acl

List access control lists.

```yaml
Request:
  Method: GET
  Path: /api/v1/security/acl

Response:
  status: "success"
  data:
    acls:
      - name: "trusted"
        networks:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
        used_by:
          - "recursion"
          - "transfer"

      - name: "blocked"
        networks:
          - "203.0.113.0/24"
        used_by:
          - "query-deny"
```

#### GET /security/rate-limit

Get rate limiting status.

```yaml
Request:
  Method: GET
  Path: /api/v1/security/rate-limit

Response:
  status: "success"
  data:
    rate_limit:
      enabled: true
      config:
        queries_per_second: 1000
        responses_per_second: 1000
        slip: 2
        window_seconds: 1

      statistics:
        period: "5m"
        drops_total: 5000
        by_reason:
          qps_exceeded: 3000
          rps_exceeded: 2000

        top_limited:
          - ip: "10.0.1.200"
            drops: 2500
          - ip: "10.0.1.201"
            drops: 1500
```

#### GET /security/rpz

Get Response Policy Zone status.

```yaml
Request:
  Method: GET
  Path: /api/v1/security/rpz

Response:
  status: "success"
  data:
    rpz:
      zones:
        - name: "rpz.dnsscience.io"
          type: "remote"
          entries: 50000
          last_update: "2024-01-15T10:00:00Z"
          actions:
            nxdomain: 45000
            nodata: 3000
            passthru: 2000

      statistics:
        period: "24h"
        matches_total: 15000
        by_action:
          nxdomain: 12000
          nodata: 2500
          passthru: 500
```

#### GET /security/events

Get security event log.

```yaml
Request:
  Method: GET
  Path: /api/v1/security/events
  Query Parameters:
    - type: string (all, attack, rate_limit, blocked)
    - limit: int (default: 100)
    - since: string (ISO8601 timestamp)

Response:
  status: "success"
  data:
    events:
      - id: "evt_12345"
        timestamp: "2024-01-15T10:30:15Z"
        type: "rate_limit_exceeded"
        severity: "warning"
        source_ip: "10.0.1.200"
        details:
          queries_in_window: 1500
          limit: 1000
          action: "drop"

      - id: "evt_12346"
        timestamp: "2024-01-15T10:30:20Z"
        type: "attack_detected"
        severity: "critical"
        source_ip: "203.0.113.50"
        details:
          attack_type: "random_subdomain"
          target_zone: "example.com"
          queries_per_second: 50000
          action: "block"
```

---

## Control Socket API

Unix socket API for local administration.

### Socket Path

```
/var/run/dnsscienced/control.sock
```

### Protocol

```yaml
protocol:
  format: "line-delimited JSON"
  authentication: "peer credentials (SO_PEERCRED)"
  authorization: "Unix permissions on socket"

request_format:
  command: "string"
  args: {}

response_format:
  status: "success" | "error"
  data: {}
  error: {}  # If status=error
```

### Commands

```yaml
commands:
  # Server control
  status:
    description: "Get server status"
    args: {}

  reload:
    description: "Reload configuration"
    args:
      section: "string (optional)"

  shutdown:
    description: "Graceful shutdown"
    args:
      timeout_seconds: "int (default: 30)"

  # Zone control
  zone_list:
    description: "List zones"
    args: {}

  zone_reload:
    description: "Reload zone"
    args:
      zone: "string (required)"

  zone_notify:
    description: "Send NOTIFY"
    args:
      zone: "string (required)"
      servers: "[]string (optional)"

  zone_freeze:
    description: "Freeze zone for editing"
    args:
      zone: "string (required)"

  zone_thaw:
    description: "Thaw frozen zone"
    args:
      zone: "string (required)"

  # Cache control
  cache_stats:
    description: "Cache statistics"
    args: {}

  cache_flush:
    description: "Flush cache"
    args:
      domain: "string (optional)"
      type: "string (optional)"

  # Debug
  trace:
    description: "Trace query resolution"
    args:
      name: "string (required)"
      type: "string (default: A)"

  querylog:
    description: "Toggle query logging"
    args:
      enable: "bool (required)"

  debug:
    description: "Toggle debug mode"
    args:
      enable: "bool (required)"
```

### Example Session

```bash
# Connect to control socket
$ socat - UNIX-CONNECT:/var/run/dnsscienced/control.sock

# Send command
{"command": "status"}

# Response
{"status":"success","data":{"server":{"id":"auth1","uptime":86400},"health":"healthy"}}

# Zone reload
{"command": "zone_reload", "args": {"zone": "example.com"}}

# Response
{"status":"success","data":{"zone":"example.com","serial":2024011503}}
```

---

## Plugin API

### Plugin Interface

```go
// Plugin is the interface all plugins must implement
type Plugin interface {
    // Name returns the plugin name
    Name() string

    // Version returns the plugin version
    Version() string

    // Init initializes the plugin with configuration
    Init(config map[string]interface{}) error

    // Start begins plugin operation
    Start() error

    // Stop gracefully stops the plugin
    Stop() error

    // Health returns plugin health status
    Health() HealthStatus
}

// QueryPlugin processes DNS queries
type QueryPlugin interface {
    Plugin

    // Query is called for each DNS query
    // Return modified message, action, and error
    Query(ctx context.Context, msg *dns.Message, meta *QueryMeta) (*dns.Message, Action, error)
}

// ResponsePlugin processes DNS responses
type ResponsePlugin interface {
    Plugin

    // Response is called for each DNS response
    Response(ctx context.Context, query *dns.Message, response *dns.Message, meta *QueryMeta) (*dns.Message, error)
}

// Action indicates what to do after plugin processing
type Action int

const (
    ActionContinue Action = iota  // Continue to next plugin
    ActionRespond                  // Respond immediately
    ActionDrop                     // Drop the query
    ActionFail                     // Return SERVFAIL
)

// QueryMeta contains query metadata
type QueryMeta struct {
    ClientIP    net.IP
    ClientPort  int
    Protocol    string      // udp, tcp, dot, doh, doq
    ReceivedAt  time.Time
    ServerAddr  net.Addr
    EDNS        *EDNSData
    Tags        map[string]string  // Plugin-added tags
}

// HealthStatus represents plugin health
type HealthStatus struct {
    Status  string            // healthy, degraded, unhealthy
    Message string
    Details map[string]interface{}
}
```

### Plugin Registration

```go
// Registration function called on plugin load
func Register() Plugin {
    return &MyPlugin{}
}

// Plugin metadata (via init or build tags)
var PluginInfo = PluginMetadata{
    Name:        "my-plugin",
    Version:     "1.0.0",
    Author:      "DNS Science",
    Description: "Example plugin",
    Hooks:       []string{"query", "response"},
    ConfigSchema: map[string]ConfigField{
        "threshold": {Type: "int", Default: 100, Required: false},
    },
}
```

### Plugin Configuration

```yaml
# In dnsscienced.conf
plugins:
  - name: "my-plugin"
    path: /usr/lib/dnsscienced/plugins/my-plugin.so
    enabled: true
    order: 10  # Execution order (lower = earlier)
    config:
      threshold: 150
      mode: "strict"
```

### Plugin Hooks

```yaml
hooks:
  query:
    description: "Called when query is received, before processing"
    signature: "Query(ctx, msg, meta) -> (msg, action, error)"
    use_cases:
      - "Query filtering"
      - "Query modification"
      - "Access control"
      - "Rate limiting"

  response:
    description: "Called before sending response"
    signature: "Response(ctx, query, response, meta) -> (response, error)"
    use_cases:
      - "Response modification"
      - "Response logging"
      - "Response signing"

  cache_lookup:
    description: "Called before cache lookup"
    signature: "CacheLookup(ctx, key) -> (result, found, error)"
    use_cases:
      - "Custom cache backends"
      - "Cache bypass logic"

  cache_store:
    description: "Called before cache store"
    signature: "CacheStore(ctx, key, value, ttl) -> (store, error)"
    use_cases:
      - "TTL modification"
      - "Selective caching"

  upstream_select:
    description: "Called to select upstream resolver"
    signature: "UpstreamSelect(ctx, query) -> (upstream, error)"
    use_cases:
      - "Intelligent routing"
      - "Load balancing"
      - "Geo-based routing"
```

---

## Internal Package APIs

### pkg/dns - DNS Message API

```go
package dns

// Message represents a DNS message
type Message struct {
    ID      uint16
    Header  Header
    Question []Question
    Answer   []RR
    Authority []RR
    Additional []RR
}

// Header represents DNS header
type Header struct {
    ID      uint16
    QR      bool      // Query/Response
    Opcode  Opcode
    AA      bool      // Authoritative Answer
    TC      bool      // Truncated
    RD      bool      // Recursion Desired
    RA      bool      // Recursion Available
    Z       uint8     // Reserved
    AD      bool      // Authenticated Data
    CD      bool      // Checking Disabled
    Rcode   Rcode
    QDCount uint16
    ANCount uint16
    NSCount uint16
    ARCount uint16
}

// Question represents a DNS question
type Question struct {
    Name  Name
    Type  Type
    Class Class
}

// RR is the interface for all resource records
type RR interface {
    Header() *RRHeader
    String() string
    Pack(buf []byte) (int, error)
    Unpack(buf []byte, offset int) (int, error)
}

// RRHeader is common to all RRs
type RRHeader struct {
    Name   Name
    Type   Type
    Class  Class
    TTL    uint32
    RDLen  uint16
}

// Parser functions
func ParseMessage(data []byte) (*Message, error)
func (m *Message) Pack() ([]byte, error)

// Builder pattern
func NewMessage() *MessageBuilder
type MessageBuilder struct { ... }
func (b *MessageBuilder) SetID(id uint16) *MessageBuilder
func (b *MessageBuilder) SetQuestion(name string, qtype Type) *MessageBuilder
func (b *MessageBuilder) AddAnswer(rr RR) *MessageBuilder
func (b *MessageBuilder) Build() (*Message, error)
```

### pkg/zone - Zone API

```go
package zone

// Zone represents a DNS zone
type Zone struct {
    Name    string
    SOA     *dns.SOA
    Records map[string][]dns.RR  // Indexed by name
    DNSSEC  *DNSSECConfig
}

// Parser interface
type Parser interface {
    Parse(reader io.Reader) (*Zone, error)
    ParseFile(path string) (*Zone, error)
}

// Available parsers
func NewNativeParser() Parser      // .dnszone format
func NewBindParser() Parser        // BIND format
func NewDjbdnsParser() Parser      // tinydns format

// Zone operations
func (z *Zone) Lookup(name string, qtype dns.Type) []dns.RR
func (z *Zone) LookupExact(name string, qtype dns.Type) []dns.RR
func (z *Zone) LookupWildcard(name string, qtype dns.Type) []dns.RR
func (z *Zone) GetSOA() *dns.SOA
func (z *Zone) GetNS() []*dns.NS
func (z *Zone) Validate() []ValidationError

// Zone modification (for dynamic updates)
func (z *Zone) AddRecord(rr dns.RR) error
func (z *Zone) DeleteRecord(name string, qtype dns.Type) error
func (z *Zone) UpdateRecord(old, new dns.RR) error
func (z *Zone) IncrementSerial() error
```

### pkg/resolver - Resolver API

```go
package resolver

// Resolver performs recursive DNS resolution
type Resolver struct {
    Config   *Config
    Cache    cache.Cache
    Upstream []Upstream
}

// Config for resolver
type Config struct {
    RootHints       string
    TrustAnchors    string
    DNSSECValidation bool
    MaxDepth        int
    Timeout         time.Duration
}

// Resolution
func (r *Resolver) Resolve(ctx context.Context, name string, qtype dns.Type) (*dns.Message, error)
func (r *Resolver) ResolveWithTrace(ctx context.Context, name string, qtype dns.Type) (*dns.Message, *Trace, error)

// Trace contains resolution path
type Trace struct {
    Steps []TraceStep
}

type TraceStep struct {
    Query    *dns.Message
    Response *dns.Message
    Server   string
    Duration time.Duration
    Cached   bool
    DNSSEC   *DNSSECValidation
}
```

### pkg/cache - Cache API

```go
package cache

// Cache is the interface for DNS caching
type Cache interface {
    Get(key string) (*Entry, bool)
    Set(key string, entry *Entry) error
    Delete(key string) error
    Flush() error
    Stats() *Stats
}

// Entry represents a cache entry
type Entry struct {
    RRs       []dns.RR
    CachedAt  time.Time
    ExpiresAt time.Time
    Source    string
    DNSSEC    DNSSECStatus
}

// Stats contains cache statistics
type Stats struct {
    Entries     int64
    SizeBytes   int64
    Hits        int64
    Misses      int64
    Evictions   int64
    HitRate     float64
}

// Implementations
func NewMemoryCache(maxSize int64) Cache
func NewRistrettoCache(config *ristretto.Config) Cache
func NewRedisCache(client *redis.Client) Cache
```

### pkg/server - Server API

```go
package server

// Server handles DNS requests
type Server struct {
    Config    *Config
    Handler   Handler
    Listeners []Listener
}

// Handler processes DNS requests
type Handler interface {
    ServeDNS(ctx context.Context, w ResponseWriter, r *dns.Message)
}

// ResponseWriter writes DNS responses
type ResponseWriter interface {
    Write(msg *dns.Message) error
    WriteError(rcode dns.Rcode) error
    RemoteAddr() net.Addr
    Protocol() string
}

// Server lifecycle
func NewServer(config *Config) (*Server, error)
func (s *Server) Start() error
func (s *Server) Stop(ctx context.Context) error
func (s *Server) Reload() error

// Listener types
type UDPListener struct { ... }
type TCPListener struct { ... }
type TLSListener struct { ... }   // DoT
type HTTPListener struct { ... }  // DoH
type QUICListener struct { ... }  // DoQ
```

---

## Webhook Events API

### Event Types

```yaml
events:
  # Zone events
  zone.loaded:
    description: "Zone loaded successfully"
    payload:
      zone: string
      serial: int
      records: int

  zone.reload_failed:
    description: "Zone reload failed"
    payload:
      zone: string
      error: string

  zone.transfer_completed:
    description: "Zone transfer completed"
    payload:
      zone: string
      type: string  # axfr, ixfr
      serial: int

  # DNSSEC events
  dnssec.key_expiring:
    description: "DNSSEC key expiring soon"
    payload:
      zone: string
      key_type: string
      key_id: int
      expires_at: timestamp

  dnssec.rollover_required:
    description: "Key rollover needed"
    payload:
      zone: string
      key_type: string

  # Security events
  security.attack_detected:
    description: "Attack detected"
    payload:
      type: string
      source: string
      target: string
      severity: string

  security.rate_limit_triggered:
    description: "Rate limit exceeded"
    payload:
      client: string
      queries: int
      limit: int

  # Server events
  server.health_changed:
    description: "Server health status changed"
    payload:
      old_status: string
      new_status: string
      reason: string
```

### Webhook Configuration

```yaml
# In dnsscienced.conf
webhooks:
  - name: "alerts"
    url: "https://hooks.example.com/dns-events"
    events:
      - "security.*"
      - "dnssec.key_expiring"
      - "server.health_changed"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
    retry:
      max_attempts: 3
      backoff: exponential

  - name: "logging"
    url: "https://logging.example.com/events"
    events:
      - "*"
    format: "cloudevents"  # or "custom"
```

### Webhook Payload Format

```json
{
  "specversion": "1.0",
  "type": "io.dnsscience.security.attack_detected",
  "source": "dnsscience://auth1.example.com",
  "id": "evt-12345-67890",
  "time": "2024-01-15T10:30:15Z",
  "datacontenttype": "application/json",
  "data": {
    "type": "random_subdomain",
    "source": "203.0.113.50",
    "target": "example.com",
    "severity": "critical"
  }
}
```

---

## gRPC API (Future)

### Service Definition

```protobuf
syntax = "proto3";

package dnsscience.v1;

service DNSService {
  // Query operations
  rpc Query(QueryRequest) returns (QueryResponse);
  rpc StreamQueries(stream QueryRequest) returns (stream QueryResponse);

  // Zone management
  rpc ListZones(ListZonesRequest) returns (ListZonesResponse);
  rpc GetZone(GetZoneRequest) returns (GetZoneResponse);
  rpc ReloadZone(ReloadZoneRequest) returns (ReloadZoneResponse);

  // Cache management
  rpc GetCacheStats(GetCacheStatsRequest) returns (GetCacheStatsResponse);
  rpc FlushCache(FlushCacheRequest) returns (FlushCacheResponse);

  // Server control
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
  rpc Reload(ReloadRequest) returns (ReloadResponse);
}

message QueryRequest {
  string name = 1;
  string type = 2;
  string class = 3;
  bool dnssec = 4;
}

message QueryResponse {
  int32 rcode = 1;
  repeated ResourceRecord answer = 2;
  repeated ResourceRecord authority = 3;
  repeated ResourceRecord additional = 4;
  QueryMeta meta = 5;
}

message ResourceRecord {
  string name = 1;
  string type = 2;
  string class = 3;
  uint32 ttl = 4;
  string data = 5;
}
```

---

*Document Version: 1.0*
*API Specifications*
