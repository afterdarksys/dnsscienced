# DNSScienced Deployment & Operations Guide

## Overview

This document covers deployment architectures, installation procedures, operational best practices, and troubleshooting for DNSScienced components.

---

## Deployment Architectures

### Single Server Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SINGLE SERVER DEPLOYMENT                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Single Host                                  │   │
│  │                                                                      │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                       │   │
│  │  │ dnsscience-authd │    │ dnsscience-cached│                       │   │
│  │  │                  │    │                  │                       │   │
│  │  │  Port 53 (auth)  │    │  Port 5353       │                       │   │
│  │  │  Zone files      │    │  (recursive)     │                       │   │
│  │  └──────────────────┘    └──────────────────┘                       │   │
│  │           │                       │                                  │   │
│  │           └───────────┬───────────┘                                  │   │
│  │                       │                                              │   │
│  │              ┌────────▼────────┐                                     │   │
│  │              │   Shared Cache  │                                     │   │
│  │              │    (Memory)     │                                     │   │
│  │              └─────────────────┘                                     │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Use Case: Development, small networks, testing                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### High Availability Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      HIGH AVAILABILITY DEPLOYMENT                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                        ┌─────────────────┐                                  │
│                        │   Load Balancer │                                  │
│                        │  (DNS Anycast)  │                                  │
│                        └────────┬────────┘                                  │
│                                 │                                           │
│           ┌─────────────────────┼─────────────────────┐                     │
│           │                     │                     │                     │
│           ▼                     ▼                     ▼                     │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐              │
│  │   Node 1       │   │   Node 2       │   │   Node 3       │              │
│  │                │   │                │   │                │              │
│  │ dnsscience-*   │   │ dnsscience-*   │   │ dnsscience-*   │              │
│  │ (Active)       │   │ (Active)       │   │ (Active)       │              │
│  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘              │
│          │                    │                    │                        │
│          └────────────────────┼────────────────────┘                        │
│                               │                                             │
│                      ┌────────▼────────┐                                    │
│                      │  Redis Cluster  │                                    │
│                      │  (Shared Cache) │                                    │
│                      └─────────────────┘                                    │
│                                                                             │
│  Features:                                                                  │
│  • Anycast IP for automatic failover                                        │
│  • Shared cache for consistency                                             │
│  • Health-based routing                                                     │
│  • Geographic distribution                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Multi-Site Global Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MULTI-SITE GLOBAL DEPLOYMENT                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                     ┌─────────────────────────┐                             │
│                     │     Global Anycast      │                             │
│                     │   DNS: 198.51.100.53    │                             │
│                     └───────────┬─────────────┘                             │
│                                 │                                           │
│    ┌────────────────────────────┼────────────────────────────┐              │
│    │                            │                            │              │
│    ▼                            ▼                            ▼              │
│                                                                             │
│ ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│ │   US-EAST        │  │   EU-WEST        │  │   APAC           │           │
│ │                  │  │                  │  │                  │           │
│ │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ ┌──────────────┐ │           │
│ │ │  Node Pool   │ │  │ │  Node Pool   │ │  │ │  Node Pool   │ │           │
│ │ │  (3 nodes)   │ │  │ │  (3 nodes)   │ │  │ │  (3 nodes)   │ │           │
│ │ └──────┬───────┘ │  │ └──────┬───────┘ │  │ └──────┬───────┘ │           │
│ │        │         │  │        │         │  │        │         │           │
│ │ ┌──────▼───────┐ │  │ ┌──────▼───────┐ │  │ ┌──────▼───────┐ │           │
│ │ │ Redis Cache  │ │  │ │ Redis Cache  │ │  │ │ Redis Cache  │ │           │
│ │ │ (Regional)   │ │  │ │ (Regional)   │ │  │ │ (Regional)   │ │           │
│ │ └──────────────┘ │  │ └──────────────┘ │  │ └──────────────┘ │           │
│ │                  │  │                  │  │                  │           │
│ └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘           │
│          │                     │                     │                      │
│          └─────────────────────┼─────────────────────┘                      │
│                                │                                            │
│                       ┌────────▼────────┐                                   │
│                       │  Primary Zone   │                                   │
│                       │    Storage      │                                   │
│                       │  (Replicated)   │                                   │
│                       └─────────────────┘                                   │
│                                                                             │
│  Zone Replication:                                                          │
│  • Primary in US-EAST                                                       │
│  • AXFR/IXFR to secondaries                                                 │
│  • NOTIFY on changes                                                        │
│  • < 1 minute propagation                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Kubernetes Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        KUBERNETES DEPLOYMENT                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Namespace: dnsscience                                                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Services                                     │   │
│  │                                                                      │   │
│  │  ┌────────────────────┐    ┌────────────────────┐                   │   │
│  │  │  dnsscience-authd  │    │  dnsscience-cached │                   │   │
│  │  │  (LoadBalancer)    │    │  (ClusterIP)       │                   │   │
│  │  │  UDP/TCP 53        │    │  UDP/TCP 53        │                   │   │
│  │  └─────────┬──────────┘    └─────────┬──────────┘                   │   │
│  │            │                         │                              │   │
│  └────────────┼─────────────────────────┼──────────────────────────────┘   │
│               │                         │                                   │
│  ┌────────────┼─────────────────────────┼──────────────────────────────┐   │
│  │            │      StatefulSets       │                              │   │
│  │            ▼                         ▼                              │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                       │   │
│  │  │ authd-0          │    │ cached-0         │                       │   │
│  │  │ authd-1          │    │ cached-1         │                       │   │
│  │  │ authd-2          │    │ cached-2         │                       │   │
│  │  └──────────────────┘    └──────────────────┘                       │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        ConfigMaps & Secrets                          │   │
│  │                                                                      │   │
│  │  ┌────────────────────┐    ┌────────────────────┐                   │   │
│  │  │ dnsscience-config  │    │ dnsscience-zones   │                   │   │
│  │  │ (dnsscienced.conf) │    │ (zone files)       │                   │   │
│  │  └────────────────────┘    └────────────────────┘                   │   │
│  │                                                                      │   │
│  │  ┌────────────────────┐    ┌────────────────────┐                   │   │
│  │  │ dnssec-keys        │    │ tsig-keys          │                   │   │
│  │  │ (KSK/ZSK)          │    │ (transfer auth)    │                   │   │
│  │  └────────────────────┘    └────────────────────┘                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Persistent Volumes                               │   │
│  │                                                                      │   │
│  │  ┌────────────────────┐    ┌────────────────────┐                   │   │
│  │  │ zones-pvc          │    │ cache-pvc          │                   │   │
│  │  │ (ReadWriteMany)    │    │ (ReadWriteOnce)    │                   │   │
│  │  └────────────────────┘    └────────────────────┘                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### System Requirements

```yaml
# Minimum Requirements
minimum:
  cpu: 2 cores
  memory: 2GB RAM
  disk: 10GB SSD
  os:
    - Linux (kernel 4.19+)
    - FreeBSD 12+
    - macOS 11+ (development only)

# Recommended for Production
production:
  cpu: 8+ cores
  memory: 16GB+ RAM
  disk: 100GB+ NVMe SSD
  network: 10Gbps+
  os: Linux (kernel 5.10+ for io_uring)

# High Performance
high_performance:
  cpu: 32+ cores (NUMA-aware)
  memory: 64GB+ RAM
  disk: NVMe with low latency
  network: 25Gbps+ (with DPDK support)
  os: Linux with real-time kernel patches
```

### Package Installation

```bash
# Debian/Ubuntu
curl -fsSL https://packages.dnsscience.io/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/dnsscience.gpg
echo "deb [signed-by=/usr/share/keyrings/dnsscience.gpg] https://packages.dnsscience.io/apt stable main" | sudo tee /etc/apt/sources.list.d/dnsscience.list
sudo apt update
sudo apt install dnsscienced

# RHEL/CentOS/Fedora
sudo dnf config-manager --add-repo https://packages.dnsscience.io/rpm/dnsscience.repo
sudo dnf install dnsscienced

# FreeBSD
pkg install dnsscienced

# From Source
git clone https://github.com/dnsscience/dnsscienced.git
cd dnsscienced
make build
sudo make install
```

### Binary Locations

```
/usr/local/bin/dnsscience-authd      # Authoritative server
/usr/local/bin/dnsscience-cached     # Recursive resolver
/usr/local/bin/dnsscience-checkzone  # Zone validator
/usr/local/bin/dnsscience-keygen     # DNSSEC key generator
/usr/local/bin/dnsscience-signzone   # Zone signer
/usr/local/bin/dnsscience-convert    # Zone converter
/usr/local/bin/dnssciencectl         # Control utility
```

### Configuration Directories

```
/etc/dnsscienced/                    # Configuration root
├── dnsscienced.conf                 # Main configuration
├── zones/                           # Zone files
│   ├── example.com.dnszone          # Native format
│   └── legacy.com.zone              # BIND format
├── keys/                            # DNSSEC keys
│   ├── Kexample.com.+013+12345.key
│   └── Kexample.com.+013+12345.private
├── plugins/                         # Plugin configs
│   ├── dip.yaml                     # DNS Intelligence Platform
│   └── web3.yaml                    # Web3 modules
└── certs/                           # TLS certificates
    ├── server.crt
    └── server.key

/var/lib/dnsscienced/                # Runtime data
├── cache/                           # Persistent cache
├── journal/                         # Zone journals (IXFR)
└── state/                           # Server state

/var/log/dnsscienced/                # Logs
├── query.log                        # Query log
├── security.log                     # Security events
└── error.log                        # Error log
```

---

## Initial Configuration

### Authoritative Server Setup

```yaml
# /etc/dnsscienced/dnsscienced.conf
server:
  daemon: dnsscience-authd

global:
  server-id: "auth1.example.com"
  version-hide: true

network:
  listen:
    - address: "0.0.0.0"
      port: 53
      protocol: [udp, tcp]
    - address: "::"
      port: 53
      protocol: [udp, tcp]
    # DoT
    - address: "0.0.0.0"
      port: 853
      protocol: tls
      tls:
        certificate: /etc/dnsscienced/certs/server.crt
        key: /etc/dnsscienced/certs/server.key

zones:
  - name: "example.com"
    type: primary
    file: /etc/dnsscienced/zones/example.com.dnszone
    dnssec:
      enable: true
      algorithm: ECDSAP256SHA256

  - name: "10.in-addr.arpa"
    type: primary
    file: /etc/dnsscienced/zones/10.in-addr.arpa.dnszone

logging:
  query-log:
    enable: true
    file: /var/log/dnsscienced/query.log
    format: json
```

### Recursive Resolver Setup

```yaml
# /etc/dnsscienced/dnsscienced.conf
server:
  daemon: dnsscience-cached

global:
  server-id: "cache1.example.com"

network:
  listen:
    - address: "127.0.0.1"
      port: 53
      protocol: [udp, tcp]
    - address: "::1"
      port: 53
      protocol: [udp, tcp]

resolver:
  # Root hints
  root-hints: /etc/dnsscienced/root.hints

  # DNSSEC validation
  dnssec-validation: auto
  trust-anchors: /etc/dnsscienced/trust-anchors.conf

  # Forwarding (optional)
  forward-zones:
    - zone: "internal.example.com"
      servers:
        - 10.0.0.1
        - 10.0.0.2

cache:
  # Memory cache
  memory:
    max-size: 1GB
    min-ttl: 60
    max-ttl: 86400

  # Redis (optional, for distributed)
  # redis:
  #   cluster:
  #     - redis-1:6379
  #     - redis-2:6379
  #     - redis-3:6379

security:
  # Access control
  acl:
    - name: "trusted"
      networks:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16

  # Rate limiting
  rate-limit:
    queries-per-second: 1000
    slip: 2
```

### Systemd Service Setup

```ini
# /etc/systemd/system/dnsscience-authd.service
[Unit]
Description=DNSScience Authoritative DNS Server
After=network.target

[Service]
Type=notify
User=dnsscience
Group=dnsscience
ExecStart=/usr/local/bin/dnsscience-authd -c /etc/dnsscienced/dnsscienced.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/dnsscienced /var/log/dnsscienced
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/dnsscience-cached.service
[Unit]
Description=DNSScience Recursive DNS Resolver
After=network.target

[Service]
Type=notify
User=dnsscience
Group=dnsscience
ExecStart=/usr/local/bin/dnsscience-cached -c /etc/dnsscienced/dnsscienced.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/dnsscienced /var/log/dnsscienced
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

---

## Operations

### Service Management

```bash
# Start services
sudo systemctl start dnsscience-authd
sudo systemctl start dnsscience-cached

# Enable at boot
sudo systemctl enable dnsscience-authd
sudo systemctl enable dnsscience-cached

# Check status
sudo systemctl status dnsscience-authd
dnssciencectl status

# Reload configuration (no downtime)
sudo systemctl reload dnsscience-authd
# or
dnssciencectl reload

# View logs
journalctl -u dnsscience-authd -f
tail -f /var/log/dnsscienced/query.log | jq .
```

### dnssciencectl Commands

```bash
# Status and info
dnssciencectl status                    # Server status
dnssciencectl stats                     # Query statistics
dnssciencectl zones                     # List zones
dnssciencectl zone example.com          # Zone details

# Cache management
dnssciencectl cache stats               # Cache statistics
dnssciencectl cache dump example.com    # Dump cache for domain
dnssciencectl cache flush               # Flush all cache
dnssciencectl cache flush example.com   # Flush specific domain

# Zone management
dnssciencectl zone reload example.com   # Reload zone
dnssciencectl zone notify example.com   # Send NOTIFY
dnssciencectl zone freeze example.com   # Freeze for editing
dnssciencectl zone thaw example.com     # Resume updates
dnssciencectl zone sign example.com     # Re-sign zone

# DNSSEC
dnssciencectl dnssec status example.com # DNSSEC status
dnssciencectl dnssec ds example.com     # Show DS records
dnssciencectl dnssec rollover example.com ksk  # Key rollover

# Debugging
dnssciencectl trace example.com A       # Trace resolution
dnssciencectl querylog on               # Enable query logging
dnssciencectl debug on                  # Debug mode
```

### Zone Management

```bash
# Validate zone before deployment
dnsscience-checkzone example.com /etc/dnsscienced/zones/example.com.dnszone

# Convert BIND zone to native format
dnsscience-convert --from bind --to native \
  /path/to/example.com.zone \
  /etc/dnsscienced/zones/example.com.dnszone

# Sign a zone
dnsscience-signzone \
  --zone example.com \
  --input /etc/dnsscienced/zones/example.com.dnszone \
  --output /etc/dnsscienced/zones/example.com.signed.dnszone \
  --ksk /etc/dnsscienced/keys/Kexample.com.+013+12345 \
  --zsk /etc/dnsscienced/keys/Kexample.com.+013+67890

# Generate DNSSEC keys
dnsscience-keygen --algorithm ECDSAP256SHA256 \
  --type ksk example.com \
  --output /etc/dnsscienced/keys/

dnsscience-keygen --algorithm ECDSAP256SHA256 \
  --type zsk example.com \
  --output /etc/dnsscienced/keys/
```

### Configuration Hot Reload

```yaml
# Items that can be reloaded without restart
hot_reload_supported:
  - Zone files
  - ACLs
  - Rate limits
  - RPZ zones
  - Logging configuration
  - Plugin configuration

# Items requiring restart
restart_required:
  - Listen addresses/ports
  - TLS certificates
  - Core server settings
  - Cache backend changes
```

---

## Zone Transfer Setup

### Primary Server Configuration

```yaml
zones:
  - name: "example.com"
    type: primary
    file: /etc/dnsscienced/zones/example.com.dnszone

    # Allow zone transfers
    transfer:
      allow:
        - key: "transfer-key"     # TSIG authentication
        - network: "10.0.0.0/24"  # Network-based
      also-notify:
        - 10.0.0.2                # Secondary server
        - 10.0.0.3

# TSIG keys
keys:
  - name: "transfer-key"
    algorithm: hmac-sha256
    secret: "base64-encoded-secret=="
```

### Secondary Server Configuration

```yaml
zones:
  - name: "example.com"
    type: secondary

    primary:
      servers:
        - address: 10.0.0.1
          port: 53
      key: "transfer-key"

    # Local copy
    file: /var/lib/dnsscienced/zones/example.com.dnszone

    # Refresh settings
    refresh-retry: 300      # Retry after 5 minutes on failure
    expire-after: 604800    # Expire after 1 week without refresh

keys:
  - name: "transfer-key"
    algorithm: hmac-sha256
    secret: "base64-encoded-secret=="
```

---

## Performance Tuning

### System-Level Tuning

```bash
# /etc/sysctl.d/99-dnsscience.conf

# Network buffers
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 31457280
net.core.wmem_default = 31457280
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65536

# UDP tuning
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# TCP tuning (DNS over TCP, DoT, and DoH)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# File descriptors
fs.file-max = 2097152
fs.nr_open = 2097152

# Enable BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

```bash
# Apply settings
sudo sysctl -p /etc/sysctl.d/99-dnsscience.conf
```

`tcp_syncookies` and `tcp_max_syn_backlog` protect connections before they
reach the process. Keep SYN cookies enabled, but treat sustained activation as
an overload signal: cookies preserve availability by omitting TCP options and
do not replace upstream anycast, scrubbing, or NIC/XDP filtering.

The application independently bounds established connections, per-client
connections, completed handshakes per second, idle lifetime, and queries per
connection:

```yaml
server:
  read_timeout: 5s
  write_timeout: 5s
  idle_timeout: 60s
  tcp_protection:
    enabled: true
    max_connections: 20000
    max_connections_per_client: 128
    accept_rate_per_second: 10000
    accept_burst: 20000
    max_queries_per_connection: 100
```

Size `LimitNOFILE` above `max_connections` plus UDP, control-plane, upstream,
and logging descriptors. Alert on
`dnsscienced_tcp_connections_rejected_total`, especially the `accept_rate` and
`global_capacity` reasons, and on sustained SYN-cookie activity from Linux
network telemetry.

### Application-Level Tuning

```yaml
# Implemented settings in dnsscienced.conf
runtime:
  max_procs: 0
  gc_percent: 100
  memory_limit_mb: 768

server:
  udp_listeners: 4
  recursive:
    workers: 100
    worker_queue_size: 1000
    nameserver_parallelism: 2
    nameserver_hedge_delay: 25ms

cache:
  max_entries: 100000
  max_memory_mb: 512
  shard_count: 256
  prefetch: true
```

### NUMA Optimization

DNSScienced does not implement per-worker CPU affinity or NUMA placement.
Resolver workers are goroutines and are not permanently attached to OS threads.
Use systemd `CPUAffinity=`, container CPU sets, or an equivalent process-level
control, and keep `runtime.max_procs` aligned with the assigned CPU quota.

Receive/send batching and XDP are not configuration options. They remain measured
Linux-specific research items; see [Runtime and Resolver Performance
Tuning](PERFORMANCE_TUNING.md).

---

## Monitoring Setup

### Prometheus Integration

```yaml
# dnsscienced.conf
metrics:
  prometheus:
    enable: true
    listen: "0.0.0.0:9153"
    path: "/metrics"

  # Metric labels
  labels:
    instance: "auth1"
    datacenter: "us-east-1"
```

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'dnsscience'
    static_configs:
      - targets:
        - 'dns-auth1:9153'
        - 'dns-auth2:9153'
        - 'dns-cache1:9153'
        - 'dns-cache2:9153'

    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '([^:]+):\d+'
        replacement: '${1}'
```

### Grafana Dashboard

```json
{
  "title": "DNSScienced Overview",
  "panels": [
    {
      "title": "Queries per Second",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(dns_queries_total[1m])",
          "legendFormat": "{{instance}} - {{type}}"
        }
      ]
    },
    {
      "title": "Query Latency (p99)",
      "type": "graph",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m]))",
          "legendFormat": "{{instance}}"
        }
      ]
    },
    {
      "title": "Cache Hit Rate",
      "type": "gauge",
      "targets": [
        {
          "expr": "dns_cache_hits_total / (dns_cache_hits_total + dns_cache_misses_total) * 100"
        }
      ]
    },
    {
      "title": "DNSSEC Validation",
      "type": "stat",
      "targets": [
        {
          "expr": "dns_dnssec_validations_total{result='secure'}"
        }
      ]
    }
  ]
}
```

### Alerting Rules

```yaml
# prometheus-alerts.yml
groups:
  - name: dnsscience
    rules:
      - alert: DNSQueryLatencyHigh
        expr: histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "DNS query latency high on {{ $labels.instance }}"
          description: "P99 latency is {{ $value }}s"

      - alert: DNSCacheHitRateLow
        expr: >
          dns_cache_hits_total / (dns_cache_hits_total + dns_cache_misses_total) < 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "DNS cache hit rate below 80% on {{ $labels.instance }}"

      - alert: DNSRateLimitDrops
        expr: rate(dns_rate_limit_drops_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "DNS rate limiting active on {{ $labels.instance }}"

      - alert: DNSServiceDown
        expr: up{job="dnsscience"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "DNS service down on {{ $labels.instance }}"
```

---

## Logging Configuration

### Query Logging

```yaml
logging:
  query-log:
    enable: true
    file: /var/log/dnsscienced/query.log

    # Format options: json, clf (common log format), custom
    format: json

    # Fields to log
    fields:
      - timestamp
      - client-ip
      - client-port
      - query-name
      - query-type
      - query-class
      - response-code
      - response-flags
      - response-size
      - duration
      - protocol
      - dnssec-validated
      - cache-hit
      - upstream-server

    # Sampling (for high-volume)
    sampling:
      enable: true
      rate: 0.1          # Log 10% of queries
      always-log:        # Always log these
        - response-code: SERVFAIL
        - response-code: NXDOMAIN
        - duration: "> 1s"

    # Rotation
    rotation:
      max-size: 100MB
      max-files: 10
      compress: true
```

### Security Event Logging

```yaml
logging:
  security-log:
    enable: true
    file: /var/log/dnsscienced/security.log
    format: json

    events:
      - rate-limit-exceeded
      - blocked-query
      - dnssec-validation-failed
      - tsig-authentication-failed
      - acl-denied
      - attack-detected

    # Syslog forwarding
    syslog:
      enable: true
      server: "syslog.example.com:514"
      facility: local0
      priority: info
```

### Log Aggregation

```yaml
# Fluent Bit configuration for log shipping
[INPUT]
    Name              tail
    Path              /var/log/dnsscienced/query.log
    Parser            json
    Tag               dns.query
    Refresh_Interval  5

[INPUT]
    Name              tail
    Path              /var/log/dnsscienced/security.log
    Parser            json
    Tag               dns.security

[OUTPUT]
    Name              elasticsearch
    Match             dns.*
    Host              elasticsearch.example.com
    Port              9200
    Index             dnsscience
    Type              _doc
```

---

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# /usr/local/bin/dnsscience-backup.sh

BACKUP_DIR="/var/backups/dnsscienced"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/${DATE}"

mkdir -p "${BACKUP_PATH}"

# Backup configuration
tar -czf "${BACKUP_PATH}/config.tar.gz" /etc/dnsscienced/

# Backup zones (freeze first to ensure consistency)
dnssciencectl zone freeze --all
tar -czf "${BACKUP_PATH}/zones.tar.gz" /etc/dnsscienced/zones/
dnssciencectl zone thaw --all

# Backup DNSSEC keys (encrypted)
tar -czf - /etc/dnsscienced/keys/ | \
  gpg --symmetric --cipher-algo AES256 \
  -o "${BACKUP_PATH}/keys.tar.gz.gpg"

# Backup state
tar -czf "${BACKUP_PATH}/state.tar.gz" /var/lib/dnsscienced/

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -type d -mtime +30 -exec rm -rf {} \;

# Sync to remote storage
aws s3 sync "${BACKUP_DIR}" s3://backups-bucket/dnsscienced/
```

### Recovery Procedure

```bash
#!/bin/bash
# Recovery procedure

# 1. Stop services
sudo systemctl stop dnsscience-authd dnsscience-cached

# 2. Restore configuration
cd /
sudo tar -xzf /var/backups/dnsscienced/YYYYMMDD_HHMMSS/config.tar.gz

# 3. Restore zones
sudo tar -xzf /var/backups/dnsscienced/YYYYMMDD_HHMMSS/zones.tar.gz

# 4. Restore keys (decrypt)
gpg --decrypt /var/backups/dnsscienced/YYYYMMDD_HHMMSS/keys.tar.gz.gpg | \
  sudo tar -xzf - -C /

# 5. Restore state
sudo tar -xzf /var/backups/dnsscienced/YYYYMMDD_HHMMSS/state.tar.gz

# 6. Validate zones
for zone in /etc/dnsscienced/zones/*.dnszone; do
  dnsscience-checkzone $(basename $zone .dnszone) $zone
done

# 7. Start services
sudo systemctl start dnsscience-authd dnsscience-cached

# 8. Verify
dnssciencectl status
dnssciencectl zones
```

### DNSSEC Key Backup

```yaml
# Keys are critical - special handling required
dnssec_key_backup:
  # HSM-backed keys (recommended for production)
  hsm:
    backup: "Managed by HSM vendor"
    recovery: "HSM restore procedure"

  # File-based keys
  file_based:
    encryption: "AES-256-GCM"
    key_escrow:
      - primary: "Secure offline storage"
      - secondary: "Bank safe deposit box"

    procedure:
      1: "Export keys with encryption"
      2: "Verify backup integrity"
      3: "Store in multiple locations"
      4: "Test recovery quarterly"
```

---

## Troubleshooting

### Common Issues

```yaml
issue_resolution:
  high_latency:
    symptoms:
      - "Query response time > 100ms"
      - "Cache miss rate increasing"
    diagnosis:
      - "dnssciencectl stats | grep latency"
      - "dnssciencectl cache stats"
      - "Check upstream resolver health"
    resolution:
      - "Verify cache is functioning"
      - "Check network path to upstreams"
      - "Review resource utilization"

  zone_load_failure:
    symptoms:
      - "Zone not loaded"
      - "SERVFAIL for zone queries"
    diagnosis:
      - "dnsscience-checkzone zone-name zone-file"
      - "journalctl -u dnsscience-authd | grep ERROR"
    resolution:
      - "Fix syntax errors in zone file"
      - "Verify file permissions"
      - "Check SOA serial format"

  dnssec_validation_failure:
    symptoms:
      - "SERVFAIL on DNSSEC-enabled domains"
      - "Bogus responses in log"
    diagnosis:
      - "dnssciencectl trace domain.com A"
      - "Check trust anchor timestamps"
    resolution:
      - "Update trust anchors"
      - "Verify system time sync"
      - "Check upstream resolver DNSSEC"

  memory_exhaustion:
    symptoms:
      - "OOM killer triggered"
      - "Cache evictions spike"
    diagnosis:
      - "dnssciencectl cache stats"
      - "Check memory limits in config"
    resolution:
      - "Increase cache size limits"
      - "Enable aggressive eviction"
      - "Add more RAM or nodes"
```

### Diagnostic Commands

```bash
# Server health check
dnssciencectl health

# Detailed statistics
dnssciencectl stats --verbose

# Trace a query through resolution
dnssciencectl trace example.com A --verbose

# Check DNSSEC chain
dnssciencectl dnssec verify example.com

# View active connections
dnssciencectl connections

# Monitor in real-time
dnssciencectl top

# Export diagnostic bundle
dnssciencectl diagnostic --output /tmp/diag.tar.gz
```

### Debug Mode

```yaml
# Enable debug mode (temporary)
debug:
  enable: true

  # Detailed logging
  log-level: debug

  # Packet capture
  packet-capture:
    enable: true
    file: /tmp/dns-capture.pcap
    filter: "port 53"

  # Performance profiling
  profiling:
    enable: true
    endpoint: "localhost:6060"
    # Access via: go tool pprof http://localhost:6060/debug/pprof/profile
```

---

## Upgrade Procedures

### Rolling Upgrade

```bash
#!/bin/bash
# Rolling upgrade for multi-node deployment

NODES=("dns1" "dns2" "dns3")

for node in "${NODES[@]}"; do
  echo "Upgrading $node..."

  # Remove from load balancer
  lb-remove $node

  # Wait for connections to drain
  sleep 30

  # Stop service
  ssh $node "sudo systemctl stop dnsscience-authd"

  # Upgrade package
  ssh $node "sudo apt update && sudo apt upgrade dnsscienced"

  # Start service
  ssh $node "sudo systemctl start dnsscience-authd"

  # Verify health
  ssh $node "dnssciencectl health"

  # Add back to load balancer
  lb-add $node

  echo "$node upgraded successfully"
  sleep 60  # Wait before next node
done
```

### Configuration Migration

```bash
# Check configuration compatibility before upgrade
dnsscience-authd --config /etc/dnsscienced/dnsscienced.conf --validate

# Migrate configuration if needed
dnsscience-migrate-config \
  --input /etc/dnsscienced/dnsscienced.conf \
  --output /etc/dnsscienced/dnsscienced.conf.new \
  --from-version 1.0 \
  --to-version 2.0
```

---

## Security Hardening

### System Hardening

```bash
# Create dedicated user
sudo useradd -r -s /usr/sbin/nologin dnsscience

# Set file permissions
sudo chown -R root:dnsscience /etc/dnsscienced
sudo chmod 750 /etc/dnsscienced
sudo chmod 640 /etc/dnsscienced/dnsscienced.conf
sudo chmod 600 /etc/dnsscienced/keys/*

# Runtime directories
sudo chown -R dnsscience:dnsscience /var/lib/dnsscienced
sudo chown -R dnsscience:dnsscience /var/log/dnsscienced
```

### Firewall Rules

```bash
# UFW example
sudo ufw allow 53/udp comment "DNS UDP"
sudo ufw allow 53/tcp comment "DNS TCP"
sudo ufw allow 853/tcp comment "DNS over TLS"
# Restrict metrics to monitoring network
sudo ufw allow from 10.0.0.0/24 to any port 9153 proto tcp comment "Prometheus metrics"

# iptables example
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 853 -j ACCEPT
iptables -A INPUT -p tcp --dport 9153 -s 10.0.0.0/24 -j ACCEPT
```

### SELinux Policy

```bash
# Install SELinux policy module
sudo semodule -i dnsscience.pp

# Label files
sudo restorecon -Rv /etc/dnsscienced
sudo restorecon -Rv /var/lib/dnsscienced
sudo restorecon -Rv /var/log/dnsscienced
```

---

*Document Version: 1.0*
*Deployment & Operations Guide*
