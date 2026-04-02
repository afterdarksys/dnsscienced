# DNSScienced Admin CLI Reference

## Overview

The `dnsscienced-admin` CLI provides runtime control of DNSScienced servers through a gRPC admin API on port 9091.

## Installation

```bash
go build -o dnsscienced-admin cmd/dnsscienced-admin/main.go
install -m 0755 dnsscienced-admin /usr/local/bin/
```

## Connection

By default, connects to `localhost:9091`. Override with `--addr`:

```bash
dnsscienced-admin --addr dns1.example.com:9091 cache stats
```

## Cache Management

### Flush Cache

Flush all cache entries:
```bash
dnsscienced-admin cache flush all
```

Flush specific name:
```bash
dnsscienced-admin cache flush name example.com
```

Flush all entries under domain:
```bash
dnsscienced-admin cache flush domain example.com
# Flushes: example.com, www.example.com, mail.example.com, etc.
```

Flush entire TLD:
```bash
dnsscienced-admin cache flush tld com
# Flushes all .com domains
```

Flush only negative cache entries (NXDOMAIN/NODATA):
```bash
dnsscienced-admin cache flush negative
```

Flush only expired entries:
```bash
dnsscienced-admin cache flush expired
```

### Cache Statistics

View detailed cache statistics:
```bash
dnsscienced-admin cache stats
```

Output:
```
Cache Statistics:
  Entries:     5234821
  Memory:      2147483648 bytes (2048.00 MB)
  Max Memory:  4294967296 bytes (4096.00 MB)
  Hits:        125382940
  Misses:      8234721
  Hit Rate:    93.84%
  Evictions:   234821
  Expirations: 1234567
```

### Purge by Pattern

Purge entries matching glob pattern:
```bash
# Purge all subdomains of example.com
dnsscienced-admin cache purge "*.example.com"

# Purge test domains
dnsscienced-admin cache purge "test*"
```

## Zone Management

### Reload Zones

Reload all zones from disk (SIGHUP equivalent):
```bash
dnsscienced-admin zone reload
```

### Refresh Specific Zone

Force refresh of a single zone:
```bash
dnsscienced-admin zone refresh example.com
```

### List Zones

List all loaded zones:
```bash
dnsscienced-admin zone list
```

Output:
```
Loaded Zones (3):
  example.com                     Records:   1234  Compiled: true
  example.org                     Records:    567  Compiled: true
  internal.local                  Records:    123  Compiled: false
```

## Query Logging Control

### Enable/Disable Logging

Enable query logging at runtime:
```bash
dnsscienced-admin logging enable
```

Disable query logging:
```bash
dnsscienced-admin logging disable
```

### Logging Status

Check query logging status:
```bash
dnsscienced-admin logging status
```

## Rate Limiting Control

### View Rate Limit Status

```bash
dnsscienced-admin ratelimit status
```

Output:
```
Rate Limiting Status:
  Enabled:            true
  Responses/sec:      10
  Errors/sec:         5
  NXDOMAINs/sec:      5
  Total Dropped:      12345
  Total Slipped:      6789
```

## Server Status & Metrics

### Server Status

View comprehensive server status:
```bash
dnsscienced-admin server status
```

Output:
```
Server Status:
  Version:     1.0.0
  Uptime:      5d12h34m56s
  Healthy:     true
  Goroutines:  2048
  Memory:      3072.50 MB
  Zones:       127

Components:
  ✓ cache           OK
  ✓ zones           127 zones loaded
  ✓ resolver        OK
  ✓ listeners       OK
```

### Server Metrics

View performance metrics:
```bash
dnsscienced-admin server metrics
```

Output:
```
Server Metrics:
  Total Queries:      125391175
  UDP Queries:        125000000
  TCP Queries:        391175
  Cache Hits:         117234821
  Cache Misses:       8156354
  Upstream Failures:  12450
  Avg Latency:        1.24 ms
  P99 Latency:        8.73 ms
```

### Graceful Shutdown

Initiate graceful shutdown with 30 second grace period:
```bash
dnsscienced-admin server shutdown 30
```

## Connection Management

### List Active Connections

```bash
dnsscienced-admin connections list
```

Output:
```
Active Connections (142 total):
  conn-1234  192.0.2.15:52341  TCP    Queries: 234  Duration: 12m34s
  conn-5678  192.0.2.16:41523  TCP    Queries: 89   Duration: 5m12s
  ...
```

## Common Operational Tasks

### After Deploying New Zone File

```bash
# Method 1: Reload all zones
dnsscienced-admin zone reload

# Method 2: Refresh specific zone
dnsscienced-admin zone refresh newzone.com

# Method 3: Send SIGHUP signal
kill -HUP $(pidof dnsscienced)
```

### Clear Cache for Updated Record

```bash
# Clear specific record
dnsscienced-admin cache flush name www.example.com

# Clear entire domain
dnsscienced-admin cache flush domain example.com
```

### Responding to DDoS Attack

```bash
# Check cache stats for unusual patterns
dnsscienced-admin cache stats

# Check rate limiting effectiveness
dnsscienced-admin ratelimit status

# Flush negative cache (often filled during attacks)
dnsscienced-admin cache flush negative

# View server metrics
dnsscienced-admin server metrics
```

### Memory Pressure

```bash
# Check memory usage
dnsscienced-admin server status

# Check cache memory
dnsscienced-admin cache stats

# Flush expired entries to free memory
dnsscienced-admin cache flush expired

# Nuclear option: flush entire cache
dnsscienced-admin cache flush all
```

### Pre-Deployment Validation

```bash
# Check server health
dnsscienced-admin server status

# Verify zones loaded
dnsscienced-admin zone list

# Check cache performance
dnsscienced-admin cache stats

# View recent metrics
dnsscienced-admin server metrics
```

## Monitoring Integration

### Prometheus Queries

Use admin CLI in monitoring scripts:

```bash
#!/bin/bash
# Check cache hit rate
STATS=$(dnsscienced-admin cache stats)
HIT_RATE=$(echo "$STATS" | grep "Hit Rate:" | awk '{print $3}' | tr -d '%')

if (( $(echo "$HIT_RATE < 80" | bc -l) )); then
    echo "ALERT: Cache hit rate below 80%: ${HIT_RATE}%"
fi
```

### Automated Cache Maintenance

```bash
#!/bin/bash
# Cron job to flush expired entries daily
# Add to /etc/cron.daily/dnsscienced-cache-cleanup

/usr/local/bin/dnsscienced-admin cache flush expired
```

## Security Considerations

### Network Access

Restrict admin API access using firewall:

```bash
# Only allow from management subnet
iptables -A INPUT -p tcp --dport 9091 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 9091 -j DROP
```

### SSH Tunneling

For remote access, use SSH tunnel:

```bash
# Create tunnel
ssh -L 9091:localhost:9091 dns-server.example.com

# In another terminal, use admin CLI
dnsscienced-admin --addr localhost:9091 server status
```

### Future Authentication

Future versions will support:
- TLS client certificates
- API tokens
- Role-based access control (RBAC)

## Troubleshooting

### Connection Refused

```bash
$ dnsscienced-admin server status
Error: connection refused
```

**Solutions**:
1. Check admin API is enabled in config
2. Verify server is running: `systemctl status dnsscienced`
3. Check firewall rules
4. Verify port 9091 is listening: `ss -tlnp | grep 9091`

### Timeout

```bash
$ dnsscienced-admin --timeout 30s server status
```

Increase timeout for slow operations like full zone reload.

### Permission Denied

Admin API operations may be restricted in config:

```yaml
admin:
  allow_cache_flush: true
  allow_zone_reload: true
  allow_shutdown: false  # Disabled in production
```

## Examples

### Cache Warming Script

```bash
#!/bin/bash
# Warm cache with common queries after flush

DOMAINS=(
    "www.example.com"
    "mail.example.com"
    "api.example.com"
)

# Flush cache
dnsscienced-admin cache flush all

# Warm up
for domain in "${DOMAINS[@]}"; do
    dig @localhost "$domain" A
    dig @localhost "$domain" AAAA
done
```

### Zone Update Script

```bash
#!/bin/bash
# Update zone and verify

ZONE="example.com"
ZONE_FILE="/etc/dnsscienced/zones/${ZONE}.zone"

# Increment serial (assuming YYYYMMDDNN format)
sed -i "s/\([0-9]\{10\}\)/$(date +%Y%m%d01)/" "$ZONE_FILE"

# Compile zone
dnsscienced-compile -input "$ZONE_FILE"

# Reload
dnsscienced-admin zone refresh "$ZONE"

# Clear cache for zone
dnsscienced-admin cache flush domain "$ZONE"

# Verify
dig @localhost "$ZONE" SOA
```

### Health Check Script

```bash
#!/bin/bash
# Comprehensive health check

echo "=== Server Status ==="
dnsscienced-admin server status

echo -e "\n=== Cache Stats ==="
dnsscienced-admin cache stats

echo -e "\n=== Zones ==="
dnsscienced-admin zone list | head -20

echo -e "\n=== Rate Limiting ==="
dnsscienced-admin ratelimit status
```

## API Reference

For programmatic access, use the gRPC API directly:

```go
import (
    pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
    "google.golang.org/grpc"
)

conn, _ := grpc.Dial("localhost:9091", grpc.WithInsecure())
client := pb.NewAdminServiceClient(conn)

resp, _ := client.GetCacheStats(context.Background(), &emptypb.Empty{})
fmt.Printf("Cache hit rate: %.2f%%\n", resp.HitRate * 100)
```

See `api/grpc/proto/admin.proto` for full API specification.
