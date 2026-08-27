# DNSScienced Production Deployment Guide

## Overview

This guide covers deploying DNSScienced for high-performance production environments handling millions of queries per second across thousands of zones.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [OS Tuning](#os-tuning)
6. [Monitoring & Observability](#monitoring--observability)
7. [High Availability](#high-availability)
8. [Security Hardening](#security-hardening)
9. [Performance Optimization](#performance-optimization)
10. [Operational Procedures](#operational-procedures)

---

## Prerequisites

### Operating System
- **Recommended**: Ubuntu 22.04 LTS or RHEL 9
- **Kernel**: Linux 5.15+ with BPF support
- **Architecture**: x86_64 (ARM64 supported but not optimized)

### Hardware (per instance for 850k QPS cached, 50k QPS recursive)
- **CPU**: 16+ cores (32 recommended for 4M+ QPS)
- **RAM**: 64GB+ (128GB for optimal cache performance)
- **Network**: 10Gbps NIC minimum
- **Storage**:
  - 100GB NVMe SSD for logs and compiled zones
  - 1TB+ if storing extensive query logs

### Dependencies
```bash
# Ubuntu/Debian
apt-get update
apt-get install -y build-essential git protobuf-compiler

# RHEL/CentOS
dnf install -y gcc git protobuf-compiler
```

---

## System Requirements

### File Descriptor Limits

Edit `/etc/security/limits.conf`:
```
dnsscienced soft nofile 1000000
dnsscienced hard nofile 1000000
```

### Kernel Parameters

Create `/etc/sysctl.d/99-dnsscienced.conf`:
```ini
# Network stack optimization
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216

# UDP buffers
net.ipv4.udp_mem = 8388608 12582912 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Connection handling
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# Port range for outbound connections
net.ipv4.ip_local_port_range = 10000 65535

# TCP optimization
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 1

# IPv6
net.ipv6.conf.all.disable_ipv6 = 0
```

Apply with:
```bash
sysctl -p /etc/sysctl.d/99-dnsscienced.conf
```

### Huge Pages (Optional for 128GB+ RAM)

For deployments with 128GB+ RAM:
```bash
echo 2048 > /proc/sys/vm/nr_hugepages
echo "vm.nr_hugepages = 2048" >> /etc/sysctl.conf
```

---

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/afterdarksys/dnsscienced.git
cd dnsscienced

# Build binaries
go build -o dnsscienced cmd/dnsscienced/main.go
go build -o dnsscienced-compile cmd/dnsscienced-compile/main.go
go build -o dnsscienced-log cmd/dnsscienced-log/main.go
go build -o dnsscienced-roothints cmd/dnsscienced-roothints/main.go

# Install binaries
install -m 0755 dnsscienced /usr/local/bin/
install -m 0755 dnsscienced-compile /usr/local/bin/
install -m 0755 dnsscienced-log /usr/local/bin/
install -m 0755 dnsscienced-roothints /usr/local/bin/

# Create directories
mkdir -p /etc/dnsscienced/{zones,keys,rpz,threatscripts}
mkdir -p /var/log/dnsscienced
mkdir -p /var/cache/dnsscienced/compiled
```

### Systemd Service

Create `/etc/systemd/system/dnsscienced.service`:
```ini
[Unit]
Description=DNSScienced High-Performance DNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dnsscienced
Group=dnsscienced
ExecStart=/usr/local/bin/dnsscienced -config /etc/dnsscienced/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1000000
LimitNPROC=512
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Create user:
```bash
useradd -r -s /sbin/nologin dnsscienced
chown -R dnsscienced:dnsscienced /etc/dnsscienced /var/log/dnsscienced /var/cache/dnsscienced
```

Enable and start:
```bash
systemctl daemon-reload
systemctl enable dnsscienced
systemctl start dnsscienced
```

---

## Configuration

### Production Config Template

Use the production template:
```bash
cp examples/config-production.yaml /etc/dnsscienced/config.yaml
```

### Key Configuration Tuning

#### Cache Memory Limits
```yaml
cache:
  max_entries: 10000000      # 10M entries
  max_memory_mb: 4096        # 4GB cache
  shard_count: 256           # Power of 2 for optimal distribution
```

Calculation:
- 10M entries × ~400 bytes/entry ≈ 4GB
- Adjust based on available RAM

#### TCP Connection Limits
```yaml
server:
  max_tcp_connections: 10000   # Concurrent TCP
  tcp_read_timeout: 5s
  tcp_write_timeout: 5s
  tcp_idle_timeout: 30s
```

For high TCP load (zone transfers, DoT):
- Increase `max_tcp_connections` to 50000+
- Monitor with `ss -s | grep TCP:`

#### Upstream Resolvers
```yaml
resolver:
  upstreams:
    - "internal-resolver-1.example.com:53"
    - "internal-resolver-2.example.com:53"
    - "8.8.8.8:53"    # Public fallback
  retries: 2
  timeout: 2s
```

**Best Practice**: Use internal recursive resolvers as primary, public DNS as fallback.

---

## OS Tuning

### Network Interface Tuning

For 10Gbps+ throughput:
```bash
# Enable multi-queue on NIC
ethtool -L eth0 combined 16

# Enable receive-side scaling
ethtool -K eth0 rxhash on

# Ring buffer size
ethtool -G eth0 rx 4096 tx 4096

# Interrupt coalescing (reduce CPU interrupts)
ethtool -C eth0 rx-usecs 50 tx-usecs 50
```

### CPU Affinity (NUMA systems)

For NUMA systems with 2+ sockets:
```bash
# Pin DNSScienced to NUMA node 0
numactl --cpunodebind=0 --membind=0 /usr/local/bin/dnsscienced -config /etc/dnsscienced/config.yaml
```

Update systemd service:
```ini
[Service]
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/local/bin/dnsscienced -config /etc/dnsscienced/config.yaml
```

### IRQ Affinity

Distribute NIC interrupts across CPUs:
```bash
#!/bin/bash
# irq-balance.sh
for irq in $(grep eth0 /proc/interrupts | awk '{print $1}' | tr -d ':'); do
    cpu=$((irq % $(nproc)))
    echo $cpu > /proc/irq/$irq/smp_affinity_list
done
```

---

## Monitoring & Observability

### Prometheus Metrics

DNSScienced exposes Prometheus metrics on `:9090/metrics`:

**Key Metrics to Monitor**:

| Metric | Alert Threshold | Description |
|--------|-----------------|-------------|
| `dnsscienced_cache_hits_total` / `dnsscienced_cache_misses_total` | Hit rate < 80% | Cache effectiveness |
| `dnsscienced_rrl_dropped_total` | > 1000/s | Rate limiting active |
| `dnsscienced_upstream_failures_total` | > 1% of queries | Upstream health |
| `dnsscienced_query_duration_seconds{quantile="0.99"}` | > 50ms | Query latency p99 |
| `dnsscienced_cache_memory_bytes` | > 90% of max | Memory pressure |
| `dnsscienced_active_connections{protocol="tcp"}` | > 80% of max | TCP exhaustion risk |

**Prometheus Scrape Config**:
```yaml
scrape_configs:
  - job_name: 'dnsscienced'
    static_configs:
      - targets: ['dns1.example.com:9090', 'dns2.example.com:9090']
```

### Health Checks

**Kubernetes Liveness Probe**:
```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
```

**Kubernetes Readiness Probe**:
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Query Logging

Enable for troubleshooting only (disk I/O intensive):
```yaml
logging:
  enable_query_log: true
  query_log_path: "/var/log/dnsscienced/queries.log"
  query_log_format: "json"
```

**Log Rotation** (`/etc/logrotate.d/dnsscienced`):
```
/var/log/dnsscienced/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 dnsscienced dnsscienced
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/dnsscienced.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

### Query Log Analysis

Filter logs with `dnsscienced-log`:
```bash
# Show all blocked queries from last hour
dnsscienced-log --blocked --since 1h

# Find all queries for specific domain
dnsscienced-log --domain example.com

# Show cache misses from specific client
dnsscienced-log --cache-miss --client 192.0.2.15

# Export to CSV for analysis
dnsscienced-log --format csv --since 24h > queries.csv
```

---

## High Availability

### Active-Active with Anycast

**Architecture**:
- 3+ servers in each datacenter
- BGP anycast IP (e.g., 192.0.2.53)
- ECMP load balancing

**BGP Configuration (BIRD)**:
```
protocol static {
    ipv4;
    route 192.0.2.53/32 via "lo";
}

protocol bgp upstream {
    local as 65001;
    neighbor 198.51.100.1 as 65000;
    ipv4 {
        export where net = 192.0.2.53/32;
    };
}
```

### Load Balancer Deployment

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

**DNSScienced PROXY protocol config**:
```yaml
experimental:
  proxyv2:
    enabled: true
    trusted_proxies:
      - "10.0.0.0/8"
    require_header: false
```

### Graceful Reload

Reload configuration without dropping queries:
```bash
# Send SIGHUP for graceful reload
systemctl reload dnsscienced

# Or directly
kill -HUP $(cat /var/run/dnsscienced.pid)
```

**What gets reloaded**:
- Zone files
- Configuration (most settings)
- ACLs and rate limits

**What requires restart**:
- Listen addresses
- Experimental features

---

## Security Hardening

### Firewall Rules (iptables)

```bash
# Allow DNS queries
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Allow monitoring
iptables -A INPUT -p tcp --dport 9090 -s monitoring-subnet -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -s lb-subnet -j ACCEPT

# Rate limit new connections
iptables -A INPUT -p tcp --dport 53 -m state --state NEW -m limit --limit 1000/s --limit-burst 2000 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
```

### AppArmor Profile

Create `/etc/apparmor.d/usr.local.bin.dnsscienced`:
```
#include <tunables/global>

/usr/local/bin/dnsscienced {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability net_bind_service,

  /usr/local/bin/dnsscienced mr,
  /etc/dnsscienced/** r,
  /var/log/dnsscienced/** rw,
  /var/cache/dnsscienced/** rw,

  network inet dgram,
  network inet6 dgram,
  network inet stream,
  network inet6 stream,
}
```

Enable:
```bash
apparmor_parser -r /etc/apparmor.d/usr.local.bin.dnsscienced
```

### DNSSEC for Authoritative Zones

Generate keys:
```bash
# KSK (Key Signing Key)
dnssec-keygen -a ECDSAP256SHA256 -b 2048 -f KSK example.com

# ZSK (Zone Signing Key)
dnssec-keygen -a ECDSAP256SHA256 -b 1024 example.com

# Move keys
mv K*.key K*.private /etc/dnsscienced/keys/
```

Enable in config:
```yaml
dnssec:
  enabled: true
  keys_dir: "/etc/dnsscienced/keys"
  auto_sign: true
  signature_validity: 30d
```

---

## Performance Optimization

### Compiled Zone Format

Compile zones for 2-5x faster loading:
```bash
# Compile all zones
for zone in /etc/dnsscienced/zones/*.zone; do
    dnsscienced-compile -input "$zone" -output "/var/cache/dnsscienced/compiled/$(basename "$zone" .zone).dzc"
done
```

Enable in config:
```yaml
zones:
  prefer_compiled: true
  auto_compile: true
  compiled_dir: "/var/cache/dnsscienced/compiled"
```

### Memory-Aware Caching

Set memory limits to prevent OOM:
```yaml
cache:
  max_memory_mb: 4096           # Hard limit
  max_entries: 10000000         # Secondary limit
```

Monitor with:
```bash
# Cache memory usage
curl -s localhost:9090/metrics | grep dnsscienced_cache_memory_bytes

# Cache hit rate
curl -s localhost:9090/metrics | grep dnsscienced_cache_hits_total
```

### Negative Caching

Cache NXDOMAIN/NODATA responses per RFC 2308:
```yaml
cache:
  enable_negative_cache: true
  negative_cache_ttl: 300s      # 5 minutes
```

Reduces upstream load for non-existent domains.

---

## Operational Procedures

### Root Hints Management

Auto-update root hints weekly:
```yaml
roothints:
  enabled: true
  auto_update: true
  update_interval: 168h         # 7 days
  validate_update: true
  backup_old: true
```

Manual update:
```bash
# Check for updates
dnsscienced-roothints --check

# Force update
dnsscienced-roothints --update

# Rollback
dnsscienced-roothints --rollback /etc/dnsscienced/root.hints.20240101-120000.bak
```

### Zone Management

**Add New Zone**:
```bash
# 1. Add zone file
vi /etc/dnsscienced/zones/newzone.com.zone

# 2. Compile (optional but recommended)
dnsscienced-compile -input /etc/dnsscienced/zones/newzone.com.zone

# 3. Reload
systemctl reload dnsscienced
```

**Update Existing Zone**:
```bash
# 1. Edit zone file
vi /etc/dnsscienced/zones/example.com.zone

# 2. Increment serial
# (automatic if using compiled zones)

# 3. Reload
systemctl reload dnsscienced

# 4. Verify
dig @localhost example.com SOA
```

### Backup & Recovery

**Backup Script** (`/usr/local/bin/dnsscienced-backup.sh`):
```bash
#!/bin/bash
BACKUP_DIR="/backup/dnsscienced/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup zones
tar czf "$BACKUP_DIR/zones.tar.gz" /etc/dnsscienced/zones/

# Backup config
cp /etc/dnsscienced/config.yaml "$BACKUP_DIR/"

# Backup DNSSEC keys
tar czf "$BACKUP_DIR/keys.tar.gz" /etc/dnsscienced/keys/

# Rotate old backups (keep 30 days)
find /backup/dnsscienced/ -type d -mtime +30 -exec rm -rf {} +
```

**Recovery**:
```bash
# Restore zones
tar xzf /backup/dnsscienced/20240101/zones.tar.gz -C /

# Restore config
cp /backup/dnsscienced/20240101/config.yaml /etc/dnsscienced/

# Reload
systemctl reload dnsscienced
```

### Performance Testing

**QPS Benchmark**:
```bash
# Using dnsperf
dnsperf -s 127.0.0.1 -d queryfile.txt -l 60 -Q 100000

# Using queryperf
queryperf -d queryfile.txt -s 127.0.0.1 -l 60
```

**Concurrent Connections Test**:
```bash
# TCP connection stress test
for i in {1..10000}; do
    (dig @127.0.0.1 +tcp example.com &)
done
```

### Troubleshooting

**High Memory Usage**:
```bash
# Check cache stats
curl -s localhost:9090/metrics | grep cache

# Force cache flush (emergency only)
# (Requires implementing flush API endpoint)
```

**Slow Queries**:
```bash
# Check query latency
curl -s localhost:9090/metrics | grep query_duration

# Find slow upstreams
curl -s localhost:9090/metrics | grep upstream_duration

# Check query log
dnsscienced-log --since 5m | grep latency_ms | sort -k9 -nr | head
```

**High RRL Drops**:
```bash
# Check RRL stats
curl -s localhost:9090/metrics | grep rrl_dropped

# Identify source IPs (requires query log)
dnsscienced-log --since 1h --blocked | grep RRL | awk '{print $2}' | sort | uniq -c | sort -nr
```

---

## Migration Checklist

- [ ] Deploy to staging environment
- [ ] Load test at expected QPS + 20%
- [ ] Validate cache hit rates > 80%
- [ ] Configure monitoring and alerts
- [ ] Set up log rotation
- [ ] Test graceful reload (SIGHUP)
- [ ] Test upstream failover
- [ ] Verify health check endpoints
- [ ] Configure backup automation
- [ ] Document runbook procedures
- [ ] Train operations team
- [ ] Schedule production cutover
- [ ] Prepare rollback plan

---

## Support

- GitHub Issues: https://github.com/afterdarksys/dnsscienced/issues
- Documentation: https://github.com/afterdarksys/dnsscienced/docs
- Security: security@dnsscienced.org
