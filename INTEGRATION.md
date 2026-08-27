# DNSScienced + ads-httpproxy Integration Guide

## Overview

This integration enables **real-time threat intelligence** between dnsscienced (DNS server with caching) and ads-httpproxy (HTTP proxy) using gRPC.

## Architecture

```
HTTP Client → ads-httpproxy → gRPC → dnsscienced → Threat Intel Decision
                    ↓                        ↓
              Block/Allow            URLhaus + Custom Feeds
```

## Features Implemented

### Phase 1: Basic Integration ✅

#### dnsscienced Side

1. **New gRPC RPC Method: `CheckURL`**
   - Location: `api/grpc/proto/cache.proto:18`
   - Accepts full URL for threat evaluation
   - Returns: `blocked`, `threat_score`, `category`

2. **Threat Intelligence Enrichment**
   - Location: `internal/cache/enrichment.go`
   - OSINT feed aggregation (URLhaus malware domains)
   - Lock-free in-memory provider for zero-I/O lookups
   - Configurable via DarkAPI key or public feeds

3. **Cache Service Handler**
   - Location: `api/grpc/services/cache.go:44`
   - `CheckURL()` implementation with 80+ score blocking threshold
   - Integrated ThreatScorer into CacheService

4. **Configuration Support**
   - Location: `cmd/dnsscienced/main.go`
   - YAML config file support: `--config <file>`
   - CLI flags override config file values

#### ads-httpproxy Side

1. **gRPC Client**
   - Location: `internal/dnscache/client.go`
   - Connection pooling and retry logic
   - 50ms timeout for low-latency proxy decisions
   - Methods: `CheckThreat()`, `CheckURL()`, `Watch()`

2. **Threat Manager Integration**
   - Location: `internal/threat/manager.go:269`
   - `CheckURLViaCache()` - Full URL threat evaluation
   - `CheckDomainViaCache()` - Domain-only threat check

3. **Middleware Integration**
   - Location: `internal/proxy/middleware.go:33`
   - Automatic domain checking in request pipeline
   - Fail-open behavior on errors (avoids outages)
   - Returns 403 Forbidden for malicious domains

## Configuration

### dnsscienced

```yaml
# config.yaml
server:
  udp_addr: ":53"
  grpc_addr: ":8443"
  enable_recursive: true
  recursive_config:
    cache_config:
      darkapi_key: "your-api-key-here"  # Optional
```

Start with:
```bash
./dnsscienced --config config.yaml
```

### ads-httpproxy

```yaml
# config.yaml
dns_science:
  enabled: true
  rpc_addr: "localhost:8443"  # dnsscienced gRPC endpoint
  feed_url: ""                 # Optional additional feed
  refresh_interval: "1h"
```

Start with:
```bash
./ads-httpproxy --config config.yaml
```

## Testing

### Test Malicious Domain Blocking

1. Start dnsscienced:
   ```bash
   cd /Users/ryan/development/dnsscienced
   ./dnsscienced --config test-config.yaml
   ```

2. Start ads-httpproxy:
   ```bash
   cd /Users/ryan/development/ads-httpproxy
   ./ads-httpproxy --config test-config.yaml
   ```

3. Test with curl (URLhaus-listed domain):
   ```bash
   curl -x http://localhost:8080 http://malicious-test-domain.com
   # Expected: 403 Forbidden
   ```

4. Test with benign domain:
   ```bash
   curl -x http://localhost:8080 http://google.com
   # Expected: 200 OK
   ```

## Threat Feeds

Currently integrated:
- **URLhaus** (abuse.ch): Malware distribution domains
- **DarkAPI** (optional): Commercial threat intel API

### Feed Refresh

- Feeds refresh every 6 hours by default
- Configurable via `refresh_interval` in config

## Performance

- **Cache Lookup Latency**: < 1ms for cached entries
- **gRPC Call Overhead**: ~50ms timeout (fail-open)
- **Memory Usage**: ~100MB for 1M domain cache

## Metrics

Both services expose Prometheus metrics:

### dnsscienced
- `cache_lookups_total`
- `threat_score_distribution`
- `grpc_requests_total`

### ads-httpproxy
- `dns_cache_queries_total`
- `blocked_by_cache_total`
- `threat_check_latency_seconds`

## Roadmap

### Phase 2: Streaming Intelligence (Not Started)
- [ ] `WatchCache()` RPC server implementation
- [ ] Real-time threat event streaming
- [ ] Push-based threat updates (no polling)

### Phase 3: Advanced Features (Future)
- [ ] Multi-source feed aggregation
- [ ] DGA detection
- [ ] Response Policy Zones (RPZ)
- [ ] Machine learning threat scoring

## Troubleshooting

### "Failed to connect to DNS Science gRPC"
- Verify dnsscienced is running: `ps aux | grep dnsscienced`
- Check gRPC port: `netstat -an | grep 8443`
- Verify config: `rpc_addr` in ads-httpproxy matches dnsscienced `grpc_addr`

### "Threat lookup failed"
- Check dnsscienced logs for errors
- Verify threat feeds are loading: check startup logs
- Test gRPC directly: `grpcurl -plaintext localhost:8443 list`

### High Latency
- Reduce gRPC timeout in `internal/dnscache/client.go:46`
- Enable local caching in ads-httpproxy (future feature)
- Check network between services

## Security

- **Transport**: Currently uses insecure gRPC (internal traffic)
- **TODO**: Add mTLS support for production
- **TODO**: Implement gRPC authentication

## Development

### Regenerate Protobuf
```bash
cd /Users/ryan/development/dnsscienced
make proto
# or
protoc --go_out=. --go-grpc_out=. api/grpc/proto/*.proto
```

### Update ads-httpproxy Proto Deps
```bash
cd /Users/ryan/development/ads-httpproxy
go get github.com/afterdarksys/dnsscienced@latest
go mod tidy
```

## Credits

Built with:
- gRPC for high-performance RPC
- URLhaus (abuse.ch) for malware domain intelligence
- Go 1.25+ for concurrency and performance
