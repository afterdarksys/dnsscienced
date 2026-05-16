# Phase 06: Admin API — Stubs & Registration - Research

**Researched:** 2026-05-16
**Domain:** Go gRPC service implementation, DNS zone management, internal package interfaces
**Confidence:** HIGH

---

## Summary

The AdminService defined in `api/grpc/proto/admin.proto` has 23 RPCs. The `internal/admin/service.go`
file has skeleton implementations for all of them but the service is **never registered** in
`api/grpc/registry/register.go` — the call `pb.RegisterAdminServiceServer(s, ...)` is simply absent.
This is the single highest-priority fix in this phase.

The deeper problem is that `admin.Service` holds a `*reload.Manager` and a `*health.Health` but no
`SrvAdapter`/live-server reference. Almost every stub that requires zone data, RRL counters, or logging
config has no path to that data. The `services.ManagementService` (already registered and functional)
already solves zone CRUD — it uses `SrvAdapter` backed by the live `*server.Server`. The AdminService
stubs for zone/record CRUD should either (a) delegate to ManagementService logic, or (b) receive their
own `SrvAdapter` + `zonesDir` + `compileBin` so they can call the same internal helpers directly.

The six categories of work are:

1. **Registration** — one line in `register.go`.
2. **Zone CRUD** — AdminService needs a `SrvAdapter`, `zonesDir`, and `compileBin`; the implementation
   can reuse the exact same helpers already in `ManagementService` (`serializeCompileReload`, `buildRR`,
   `removeRecord`, `rrContent`, etc.).
3. **ListZones missing fields** — `SourceFile`, `Compiled` (`.dzc` check), and `Serial` (from SOA)
   are already available; just wiring is missing.
4. **SetQueryLogging / GetQueryLoggingStatus** — `Logger` has no dynamic enable/disable methods;
   new methods must be added to `internal/logging/logger.go`.
5. **SetRateLimit / GetRateLimitStatus** — `rrl.Limiter` exposes `GetStats()` and `cfg` but has
   no setter methods; new accessor/mutator methods are needed.
6. **GetMetrics, ListConnections, KillConnection** — metrics need UDP/TCP split counters (not
   currently tracked by `internal/server.Server`); connection tracking does not exist.

**Primary recommendation:** Extend `admin.Service` with `SrvAdapter + zonesDir + compileBin`
fields, add dynamic methods to `logging.Logger` and `rrl.Limiter`, add UDP/TCP atomic counters
to `internal/server.Server`, and stub ListConnections/KillConnection with a not-yet-implemented
response rather than a silent no-op.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| AdminService registration | gRPC registry layer | — | `register.go` is the single wiring point |
| Zone CRUD (CreateZone, UpdateZone, DeleteZone, GetZone) | Admin gRPC service | internal/server (SrvAdapter) | DNS state lives in server.Server; file ops use zonesDir |
| Record CRUD (Create/Update/Delete/ListRecords) | Admin gRPC service | internal/zone | Same pattern as ManagementService |
| SetQueryLogging / GetQueryLoggingStatus | logging.Logger | Admin gRPC service | Logger owns logging state |
| SetRateLimit / GetRateLimitStatus | rrl.Limiter | Admin gRPC service | Limiter owns rate-limit config and stats |
| GetMetrics (UDP/TCP split, latency) | internal/server.Server | Admin gRPC service | Server owns atomic counters per transport |
| ListConnections / KillConnection | internal/server.Server | Admin gRPC service | Server owns TCP listener, connection table |
| ListZones (SourceFile, Compiled, Serial) | Admin gRPC service | internal/zone | Serial in zone.SOA; compiled = .dzc exists |

---

## Per-Stub Analysis

### TASK A: Registration (Critical — blocks all AdminService calls)

**File:** `api/grpc/registry/register.go`

**What is missing:** `pb.RegisterAdminServiceServer(s, adminSvc)` is not called anywhere.
`RegisterAll` registers DNS, Zone, Cache, Server, DNSSEC, Management, and Firewall — but not Admin.

**What is needed:**
- Construct `admin.NewService(...)` inside `RegisterAll`.
- `admin.NewService` currently takes `(cache, reloadMgr, healthMgr, logger, shutdownFn)`.
- The `cache` and `reloadMgr` fields are not available via `SrvIface`. Either pass them
  separately to `RegisterAll`, or extend `SrvIface`.
- Simpler path: `admin.Service` is redesigned to accept a `SrvAdapter` (same as ManagementService),
  dropping `reloadMgr` and replacing it with direct zone operations via SrvAdapter.

**Recommended approach:**

```go
// In registry/register.go RegisterAll():
adminSvc := admin.NewService(
    newLiveCacheMgr(srv),   // already exists
    srv,                     // new: SrvAdapter for zone/stats access
    zonesDir,
    compileBin,
    version,
)
pb.RegisterAdminServiceServer(s, adminSvc)
```

[VERIFIED: register.go line 38-61 — no RegisterAdminServiceServer call present]

---

### TASK B: admin.Service struct — add fields

`admin.Service` currently holds:
- `*cache.ShardedCache` — fine, used by FlushCache/GetCacheStats/PurgeCache (working)
- `*reload.Manager` — only used by `RefreshZone`, `ListZones`, `ReloadZones` (stubs)
- `*health.Health` — used by GetServerStatus
- `*logging.Logger` — needed but has no dynamic methods yet
- `shutdownFn func() error` — used by ShutdownServer (working)

**Missing fields for new stubs:**
- `SrvAdapter` (or `*services.SrvAdapter`-equivalent) — for zone CRUD, stats
- `zonesDir string` — for file operations
- `compileBin string` — for compilation
- A reference to `*rrl.Limiter` — for SetRateLimit / GetRateLimitStatus

**Import cycle concern:** `internal/admin` cannot import `internal/server` (that would create a
cycle via the existing `services` package imports). Use the same `SrvAdapter` interface pattern
already established in `api/grpc/services/management.go`.

The simplest solution: extend `admin.Service.NewService` signature, passing SrvAdapter.
Or, pass a minimal interface defined in `internal/admin`.

[VERIFIED: internal/admin/service.go lines 22-48 — current struct and constructor]
[VERIFIED: api/grpc/services/management.go lines 23-32 — SrvAdapter pattern]

---

### TASK C: CreateZone / UpdateZone / DeleteZone / GetZone

**What they need:** Same as `ManagementService` — serialize to `.dnszone`, run compiler, load `.dzc`,
call `srv.AddZone`. The code in `management.go` is production-ready and tested.

**Implementation path (code reuse):**

Option 1: Delegate — `admin.Service` holds a `*ManagementService` or calls `ManagementService`
methods directly. Avoids duplication.

Option 2: Duplicate helpers — copy `serializeCompileReload`, `buildRR`, `removeRecord` into
`internal/admin`. Not preferred.

Option 3: Extract shared helpers into a new package (`internal/zoneops` or `api/grpc/services/helpers.go`).

**Recommendation:** Option 1 — instantiate a `*ManagementService` inside `admin.Service` and
delegate. This is three lines and avoids duplication.

**proto contract (from admin.proto):**

- `CreateZone`: takes `zone_name`, `zone_content` (YAML), `compile bool`. Returns `record_count`,
  `zone_file_path`. *Note:* zone_content is raw YAML; ManagementService uses a structured proto —
  this admin proto API is lower-level.
- `UpdateZone`: takes `zone_name`, `zone_content`, `compile`, `reload`. Returns `record_count`.
- `DeleteZone`: takes `zone_name`, `delete_files bool`. Returns bool+message.
- `GetZone`: takes `zone_name`. Returns `AdminZoneInfo` + `zone_content` (YAML text).

**Key difference from ManagementService:** `AdminCreateZoneRequest.zone_content` is a raw YAML
string rather than a structured protobuf SOA + records. The service needs to:
1. Write `zone_content` bytes directly to `<zonesDir>/<zone_name>.dnszone`
2. Run compiler
3. Load compiled zone
4. Call `srv.AddZone`

For UpdateZone with `reload=true`: same flow.
For GetZone returning `zone_content`: read the `.dnszone` file from disk.

[VERIFIED: admin.proto lines 242-285 — message shapes for zone CRUD]

---

### TASK D: CreateRecord / UpdateRecord / DeleteRecord / ListRecords

**What they need:** Identical to ManagementService record operations. The `buildRR`, `removeRecord`,
`rrContent`, `makeRecordID`, `parseRecordID` helpers in `management.go` cover all cases.

**Implementation:** Delegate to ManagementService or extract helpers.

**proto contract differences from ManagementService:**
- `AdminCreateRecordRequest` uses `owner`, `record_type`, `content`, `ttl`, `priority` fields —
  slightly different naming from `mgmt.DNSRecord` which uses `name`, `record_type`, `content`.
  Mapping is straightforward.
- `record_id` format is `owner:type:content` (matches ManagementService).

[VERIFIED: admin.proto lines 289-347 — record CRUD message shapes]

---

### TASK E: ListZones — fix missing fields

**Currently broken:** `SourceFile` returns `""`, `Compiled` returns `false`, `Serial` returns `0`.

**Fix:**
```go
// SourceFile: construct from zonesDir
sourceFile := filepath.Join(s.zonesDir, domain+".dnszone")

// Compiled: check if .dzc exists
dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
compiled := false
if _, err := os.Stat(dzcPath); err == nil {
    compiled = true
}

// Serial: from zone.SOA
serial := uint32(0)
if z := s.srv.GetZone(origin); z != nil && z.SOA != nil {
    serial = z.SOA.Serial
}
```

[VERIFIED: internal/zone/zone.go line 20 — Zone.SOA is *dns.SOA with Serial field]
[VERIFIED: internal/admin/service.go lines 208-227 — ListZones current stub]

---

### TASK F: SetQueryLogging / GetQueryLoggingStatus

**Current state:** Both return hardcoded `false`/empty. `Logger` has no dynamic enable/disable.

**What needs to be added to `internal/logging/logger.go`:**

```go
// SetQueryLogEnabled dynamically enables or disables query logging.
func (l *Logger) SetQueryLogEnabled(enabled bool) error {
    l.mu.Lock()
    defer l.mu.Unlock()
    if enabled && l.config.EnableQueryLog == false {
        l.config.EnableQueryLog = true
        return l.setupQueryLog()  // opens file
    }
    if !enabled {
        l.config.EnableQueryLog = false
        if l.queryFile != nil {
            l.queryFile.Close()
            l.queryFile = nil
        }
    }
    return nil
}

// IsQueryLogEnabled returns current query logging state.
func (l *Logger) IsQueryLogEnabled() bool {
    l.mu.Lock()
    defer l.mu.Unlock()
    return l.config.EnableQueryLog
}

// QueryLogConfig returns current query log path and format.
func (l *Logger) QueryLogConfig() (path, format string) {
    l.mu.Lock()
    defer l.mu.Unlock()
    return l.config.QueryLogPath, l.config.QueryLogFormat
}
```

**GetQueryLoggingStatus.log_size_bytes:** Use `os.Stat(l.config.QueryLogPath).Size()`.
**GetQueryLoggingStatus.queries_logged:** Not currently tracked — add an `atomic.Int64` to Logger.

[VERIFIED: internal/logging/logger.go — Logger.mu sync.Mutex exists, config.EnableQueryLog field exists]

---

### TASK G: SetRateLimit / GetRateLimitStatus

**Current state:** Both return hardcoded `false`/empty. `rrl.Limiter` exposes `GetStats()` and
exposes its `cfg` field — but `cfg` is unexported after `NewLimiter` and has no setter.

**What needs to be added to `internal/rrl/limiter.go`:**

```go
// UpdateConfig atomically updates the rate limit configuration.
// Existing in-flight bucket tokens are not reset.
func (l *Limiter) UpdateConfig(cfg Config) {
    // cfg is a value type — safe to assign
    l.cfg = cfg
}

// GetConfig returns a copy of the current configuration.
func (l *Limiter) GetConfig() Config {
    return l.cfg  // Config is a value type, no locking needed for simple read
}
```

**Thread safety note:** `l.cfg` is read by `Check()` concurrently. Because `Config` is a struct
value (not a pointer), updating it is not atomic. Options:
- Use `sync/atomic.Value` to store/load the Config struct.
- Use a `sync.RWMutex` around config reads/writes.
- Accept the brief window of inconsistency (acceptable for rate limit tuning).

Recommendation: `sync.RWMutex` — simpler than atomic.Value for a struct.

**Admin service implementation:**
```go
func (s *Service) GetRateLimitStatus(...) (*pb.AdminRateLimitStatusResponse, error) {
    stats := s.rrlLimiter.GetStats()
    cfg := s.rrlLimiter.GetConfig()
    return &pb.AdminRateLimitStatusResponse{
        Enabled:            cfg.Enabled,
        ResponsesPerSecond: int32(cfg.ResponsesPerSecond),
        ErrorsPerSecond:    int32(cfg.ErrorsPerSecond),
        NxdomainsPerSecond: int32(cfg.NXDOMAINsPerSecond),
        TotalDropped:       stats.Dropped,
        TotalSlipped:       stats.Slipped,
    }, nil
}
```

[VERIFIED: internal/rrl/limiter.go lines 111-127 — Limiter struct, cfg field is plain Config value]
[VERIFIED: internal/rrl/limiter.go lines 349-367 — GetStats() returns Stats struct]

---

### TASK H: GetMetrics — UDP/TCP split, latency percentiles

**Current state:** `internal/server.Server` has `queries`, `answers`, `errors`, `nxdomain` as
`atomic.Uint64`. No UDP/TCP split, no latency tracking.

**What needs to be added to `internal/server/server.go`:**

```go
// New fields in Server struct:
udpQueries atomic.Uint64
tcpQueries atomic.Uint64

// In handleDNS, after client IP detection:
if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
    s.udpQueries.Add(1)
} else {
    s.tcpQueries.Add(1)
}
```

**Latency percentiles:** Tracking true p99 requires a histogram or sliding window — this is
non-trivial. Options:
a. Return `0.0` with a `// TODO` comment (scope-safe).
b. Add a simple exponential moving average for `avg_latency_ms` only.
c. Use a fixed-size ring buffer for last N query durations.

Recommendation: Add UDP/TCP counters and EMA avg latency; leave p99 as `0.0` for this phase
with a clear TODO. Latency measurement requires wrapping the `dns.ResponseWriter` which is
straightforward but adds complexity.

**GetMetrics implementation:**
```go
func (s *Service) GetMetrics(ctx context.Context, _ *emptypb.Empty) (*pb.AdminMetricsResponse, error) {
    stats := s.cache.GetStats()
    srvStats := s.srv.GetStats()
    return &pb.AdminMetricsResponse{
        QueriesTotal:     srvStats.Queries,
        QueriesUdp:       srvStats.UDPQueries,  // new field
        QueriesTcp:       srvStats.TCPQueries,  // new field
        CacheHits:        stats.Hits,
        CacheMisses:      stats.Misses,
        UpstreamFailures: srvStats.Errors,
        AvgLatencyMs:     0.0,  // TODO: add EMA tracking
        P99LatencyMs:     0.0,  // TODO: add histogram
    }, nil
}
```

[VERIFIED: internal/server/server.go lines 125-130 — existing atomic counters]
[VERIFIED: internal/server/server.go lines 333-335 — RemoteAddr type assertions]

---

### TASK I: ListConnections / KillConnection

**Current state:** No connection tracking exists anywhere in the codebase. The `miekg/dns` library's
`dns.Server` does not expose its active connection table.

**What would be required for full implementation:**
- A `sync.Map` or mutex-protected map of `connectionID -> connectionInfo` in `internal/server.Server`.
- A custom `dns.ResponseWriter` wrapper that registers/deregisters connections.
- A method `KillConnection(id string) bool` that calls `net.Conn.Close()`.
- The `dns.Server` struct in miekg/dns does track TCP connections internally but does not expose them.

**Scope assessment:** Full implementation is a non-trivial transport-layer change. For this phase,
the recommendation is to implement these stubs with a clear **not-yet-implemented** gRPC status
rather than a silent success-false response:

```go
func (s *Service) ListConnections(...) (*pb.AdminListConnectionsResponse, error) {
    return nil, status.Error(codes.Unimplemented, "connection tracking not yet implemented")
}
func (s *Service) KillConnection(...) (*pb.AdminKillConnectionResponse, error) {
    return nil, status.Error(codes.Unimplemented, "connection tracking not yet implemented")
}
```

This is honest (returns proper gRPC error, not misleading success=false) and unblocks the rest
of the phase. Connection tracking can be added as a follow-on phase.

[VERIFIED: internal/server/server.go — no connection tracking map present]

---

## Standard Stack

### Core (already in use)
| Package | Version | Purpose |
|---------|---------|---------|
| `google.golang.org/grpc` | existing | gRPC server/registration |
| `google.golang.org/protobuf` | existing | protobuf types (emptypb, timestamppb) |
| `github.com/miekg/dns` | existing | DNS RR types, FQDN helpers |

### Internal packages touched
| Package | File | Change Required |
|---------|------|----------------|
| `internal/admin` | `service.go` | Add SrvAdapter, zonesDir, compileBin, *rrl.Limiter fields |
| `internal/logging` | `logger.go` | Add SetQueryLogEnabled, IsQueryLogEnabled, QueryLogConfig, queriesLogged counter |
| `internal/rrl` | `limiter.go` | Add UpdateConfig, GetConfig with RWMutex |
| `internal/server` | `server.go` | Add udpQueries, tcpQueries atomics; expose in GetStats() |
| `api/grpc/registry` | `register.go` | Add pb.RegisterAdminServiceServer call |

---

## Architecture Patterns

### Pattern: Service delegation via internal field

The ManagementService pattern (used for zone CRUD) is the established template. AdminService
should follow the same pattern:

```
admin.Service
  ├── *cache.ShardedCache          (existing — FlushCache, GetCacheStats, PurgeCache)
  ├── SrvAdapter                   (new — zone ops, server stats)
  ├── string zonesDir              (new — zone file I/O)
  ├── string compileBin            (new — compiler path)
  ├── *rrl.Limiter                 (new — rate limit ops)
  ├── *logging.Logger              (existing — query log ops)
  ├── *health.Health               (existing — GetServerStatus)
  └── func() error shutdownFn      (existing — ShutdownServer)
```

### Pattern: SrvAdapter interface (no import cycle)

`internal/admin` must NOT import `internal/server`. Define a minimal interface in `internal/admin`:

```go
// In internal/admin/service.go
type SrvAdapter interface {
    GetZone(origin string) *zone.Zone
    AddZone(z *zone.Zone) error
    RemoveZone(origin string)
    GetStats() ServerStats
}

type ServerStats struct {
    Queries    uint64
    UDPQueries uint64
    TCPQueries uint64
    Errors     uint64
    NXDomain   uint64
}
```

Alternatively, reuse `services.SrvAdapter` if the import direction allows it. Since
`api/grpc/services` is above `internal/admin` in the dependency graph, this import is safe.

[VERIFIED: api/grpc/services/management.go lines 23-32 — services.SrvAdapter definition]

### Pattern: Zone file write → compile → AddZone

```go
// 1. Write YAML
os.WriteFile(dnszonePath, []byte(req.ZoneContent), 0644)

// 2. Compile (external binary)
exec.CommandContext(ctx, compileBin, "-input", dnszonePath, "-output", dzcPath, "-verify")

// 3. Load compiled
z, _ := zone.LoadCompiledZone(dzcPath)

// 4. Hot-reload
srv.AddZone(z)
```

This exact pattern is in `ManagementService.serializeCompileReload` — copy or delegate.

[VERIFIED: api/grpc/services/management.go lines 704-733]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Zone CRUD logic | Custom zone writer | `ManagementService.serializeCompileReload` pattern | Already handles compile, reload, error cases |
| RR construction | Custom string parser | `management.buildRR` helpers | Handles A, AAAA, CNAME, MX, TXT, SRV, generic fallback |
| Record ID scheme | Custom format | `makeRecordID`/`parseRecordID` (owner:type:content) | Consistent across CLI and gRPC |
| DNS name normalization | Manual | `dns.Fqdn()`, `strings.ToLower()` | Handles trailing dots, case |
| RRL stats | Re-derive from buckets | `rrl.Limiter.GetStats()` | Atomic, zero-cost |

---

## Common Pitfalls

### Pitfall 1: Import cycle when admin imports internal/server

**What goes wrong:** `internal/admin` imports `internal/server`, which imports packages that
transitively import `api/grpc/...` — cycle.

**Prevention:** Define a minimal interface in `internal/admin` (or use `services.SrvAdapter`)
instead of depending on the concrete `*server.Server`.

### Pitfall 2: rrl.Limiter.cfg concurrent access

**What goes wrong:** `SetRateLimit` writes `l.cfg` while `Check()` reads it in goroutines.
**Prevention:** Wrap cfg access with `sync.RWMutex`.

### Pitfall 3: Logger.SetQueryLogEnabled races with LogQuery

**What goes wrong:** Closing `queryFile` while a concurrent `LogQuery` writes to it.
**Prevention:** `Logger.mu` is already a `sync.Mutex` — hold it during file open/close and
during writes (LogQuery must also hold mu).

### Pitfall 4: Zone name normalization inconsistency

**What goes wrong:** AdminService receives "example.com" (no dot); `srv.GetZone` expects
"example.com." (FQDN). Zones not found.
**Prevention:** Always `dns.Fqdn(strings.TrimSuffix(name, "."))` before calling srv.GetZone.
ManagementService does this on every call — replicate the pattern.

### Pitfall 5: CreateZone with zone_content overwrites existing zone silently

**What goes wrong:** No conflict check before writing `<zone>.dnszone`.
**Prevention:** Check `srv.GetZone(origin) != nil` and return `codes.AlreadyExists`.

### Pitfall 6: admin.Service registered with wrong/no cache reference

**What goes wrong:** `NewService` currently takes `*cache.ShardedCache` directly. The
`registry/register.go` already has `newLiveCacheMgr(srv)` but that returns a different type
(ports.CacheManager). Need to pass the raw `*cache.ShardedCache`.
**Prevention:** The admin service should accept the concrete `*cache.ShardedCache` — this is
already how it is. The registry needs to obtain it via a new interface method on SrvIface, or
the admin service should accept a cache-stats interface.

---

## Code Examples

### Example: RegisterAdminServiceServer in registry.go
```go
// Source: pattern from existing pb.RegisterZoneServiceServer at line 48
adminSvc := admin.NewService(
    /* cache */ someCache,
    /* srv   */ srv,
    /* zonesDir */ zonesDir,
    /* compileBin */ compileBin,
    /* rrlLimiter */ nil, // or obtained via SrvIface extension
    /* logger */ nil,     // or passed in
    /* healthMgr */ nil,  // or passed in
    /* shutdownFn */ nil,
)
pb.RegisterAdminServiceServer(s, adminSvc)
```

### Example: GetRateLimitStatus with new Limiter methods
```go
// Source: internal/rrl/limiter.go GetStats() pattern
func (l *Limiter) GetConfig() Config {
    l.cfgMu.RLock()
    defer l.cfgMu.RUnlock()
    return l.cfg
}
```

### Example: ListZones with SourceFile/Compiled/Serial
```go
// Source: management.go ListZones pattern + os.Stat
for name, zone := range zones {
    domain := strings.TrimSuffix(name, ".")
    dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
    dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
    _, compiledErr := os.Stat(dzcPath)
    serial := uint32(0)
    if zone.SOA != nil {
        serial = zone.SOA.Serial
    }
    zoneInfos = append(zoneInfos, &pb.AdminZoneInfo{
        Name:        name,
        RecordCount: int32(zone.GetStats().Records),
        LastLoaded:  timestamppb.New(s.reloadMgr.GetLastReload()),
        SourceFile:  dnszonePath,
        Compiled:    compiledErr == nil,
        Serial:      serial,
    })
}
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|-----------------|--------|
| Reload Manager zone storage | SrvAdapter + live server zones map | AdminService should use SrvAdapter, not reloadMgr |
| Stub returning success=false | Return `codes.Unimplemented` gRPC status | Clients can distinguish "not done" from "tried and failed" |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `services.SrvAdapter` is importable from `internal/admin` without cycle | TASK A, Pattern section | If cycle exists, define a parallel interface in internal/admin |
| A2 | `dns.Server` in miekg/dns does not expose active TCP connections | TASK I | If it does, ListConnections could be partially implemented |
| A3 | `rrl.Limiter.cfg` is a value (not pointer) type — write is not atomic | TASK G | If rrl is refactored to pointer, concurrent write is still unsafe |

---

## Environment Availability

Step 2.6: SKIPPED — this phase is code-only changes to existing Go packages. No external
tools beyond the existing Go toolchain and `dnsscienced-compile` binary (already handled in
ManagementService) are required.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go testing (`go test`) |
| Config file | none |
| Quick run command | `go test ./internal/admin/... ./internal/rrl/... ./internal/logging/... -run . -count=1` |
| Full suite command | `go test ./... -count=1` |

### Phase Requirements to Test Map

| Behavior | Test Type | Automated Command | File Exists? |
|----------|-----------|-------------------|-------------|
| AdminService is reachable (not Unimplemented) | integration/smoke | `go test ./api/grpc/... -run TestAdminService` | No — Wave 0 |
| CreateZone writes file + compiles + loads | unit | `go test ./internal/admin/... -run TestCreateZone` | No — Wave 0 |
| ListZones returns SourceFile/Compiled/Serial | unit | `go test ./internal/admin/... -run TestListZones` | No — Wave 0 |
| SetQueryLogging enables/disables logging | unit | `go test ./internal/logging/... -run TestSetQueryLogEnabled` | No — Wave 0 |
| GetRateLimitStatus returns live stats | unit | `go test ./internal/rrl/... -run TestGetConfig` | No — Wave 0 |
| GetMetrics returns UDP+TCP split | unit | `go test ./internal/server/... -run TestUDPTCPCounters` | No — Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/admin/... ./internal/rrl/... ./internal/logging/...`
- **Per wave merge:** `go test ./...`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/admin/service_test.go` — unit tests for zone CRUD, metrics, logging stubs
- [ ] `internal/logging/logger_test.go` — dynamic enable/disable coverage
- [ ] `internal/rrl/limiter_test.go` — GetConfig/UpdateConfig coverage (file exists, check if dynamic methods covered)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no (handled by gRPC API key interceptor) | existing interceptor in api/grpc/server/server.go |
| V3 Session Management | no | stateless RPC |
| V4 Access Control | yes — ShutdownServer, KillConnection, DeleteZone are destructive | require valid API key (already enforced) |
| V5 Input Validation | yes | validate zone_name, zone_content before file write |
| V6 Cryptography | no | — |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal via zone_name in file path | Tampering | Sanitize: reject zone names containing `/` or `..` |
| Zone content injection (malformed YAML written to disk) | Tampering | Compiler validates; catch compiler errors and return error |
| Unauthorized ShutdownServer | Elevation of Privilege | API key interceptor; already in place |

---

## Sources

### Primary (HIGH confidence)
- `internal/admin/service.go` — all current stub implementations, verified by direct read
- `api/grpc/registry/register.go` — confirmed AdminService registration is absent
- `api/grpc/proto/admin.proto` — full RPC and message contract, verified by direct read
- `api/grpc/services/management.go` — zone/record CRUD reference implementation
- `api/grpc/services/live_zone_manager.go` — SrvAdapter zone operations pattern
- `internal/rrl/limiter.go` — Limiter struct, cfg, GetStats
- `internal/logging/logger.go` — Logger struct, Config, no dynamic methods
- `internal/server/server.go` — atomic counters, AddZone, GetZone, GetStats
- `internal/zone/zone.go` — Zone.SOA, GetStats, AddRecord

### Secondary (MEDIUM confidence)
- `cmd/dnsscienced/main.go` — wiring pattern for gRPC registry, SrvAdapter adapter in main

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages verified by direct source read
- Architecture: HIGH — import paths and interface boundaries verified
- Pitfalls: HIGH — concurrent access patterns read from source; import cycle risk confirmed by checking package graph
- Per-stub implementation paths: HIGH — each stub traced to required internal APIs

**Research date:** 2026-05-16
**Valid until:** 60 days (codebase is internal, not subject to external dependency churn)
