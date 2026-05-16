---
phase: 06-admin-api-stubs-registration
plan: 02
subsystem: api
tags: [go, grpc, admin, registry, adapter, cache, server]

# Dependency graph
requires:
  - phase: 06-admin-api-stubs-registration
    plan: 01
    provides: "server.Stats.UDPQueries/TCPQueries; rrl.Limiter.GetConfig/UpdateConfig; Logger admin methods"
provides:
  - "pb.RegisterAdminServiceServer called in RegisterAll — AdminService RPCs now reachable"
  - "admin.AdminSrvAdapter interface + AdminSrvStats struct in internal/admin"
  - "admin.Service extended with srv, zonesDir, compileBin, rrlLimiter fields"
  - "services.SrvStats.UDPQueries/TCPQueries fields"
  - "services.SrvAdapter.GetShardedCache() + GetAdminStats() methods"
  - "resolver.Recursive.GetCache() + server.Server.GetCache() accessor chain"
  - "Nil guards on RefreshZone, ListZones, ReloadZones, GetServerStatus"
affects:
  - "06-03 (zone/cache stub implementations — use srv/zonesDir/compileBin)"
  - "06-04 (metrics/logging/RRL stubs — use srv, rrlLimiter)"
  - "06-05 (TSIG package)"
  - "06-06 (admin RPCs)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Duck typing across adapter boundary: serverSrvAdapter satisfies both services.SrvAdapter and admin.AdminSrvAdapter"
    - "Nil-guard defensive pattern: check field != nil before dereferencing in every RPC that uses reloadMgr/healthMgr"
    - "Cache accessor chain: resolver.Recursive.GetCache() -> server.Server.GetCache() -> serverSrvAdapter.GetShardedCache()"

key-files:
  created: []
  modified:
    - api/grpc/services/management.go
    - api/grpc/registry/register.go
    - internal/admin/service.go
    - internal/server/server.go
    - internal/resolver/recursive.go
    - cmd/dnsscienced/main.go

key-decisions:
  - "Add GetAdminStats() to services.SrvAdapter (not just admin.AdminSrvAdapter) so SrvIface type alias automatically carries it — avoids runtime type assertion in RegisterAll"
  - "Expose cache via accessor chain (resolver.GetCache -> server.GetCache -> adapter.GetShardedCache) rather than threading *cache.ShardedCache through NewService separately"
  - "Pass nil for reloadMgr/healthMgr/logger/rrlLimiter in RegisterAll Phase 6; nil-guarded at RPC call sites; Phase 7 wires real values"
  - "AdminSrvStats defined in internal/admin (not services) to avoid import cycle: services -> admin -> pb is acyclic"

patterns-established:
  - "Nil-guard pattern for manager fields: if s.reloadMgr == nil { return safe default response, nil }"
  - "Duck typing via type alias: SrvIface = services.SrvAdapter — adding methods to interface automatically requires them from all concrete adapters"

requirements-completed:
  - ADMIN-REG-01
  - ADMIN-STRUCT-01

# Metrics
duration: 5min
completed: 2026-05-16
---

# Phase 6 Plan 02: AdminService Registration and Struct Extension Summary

**AdminService registered in gRPC registry via pb.RegisterAdminServiceServer; admin.Service extended with AdminSrvAdapter interface + zonesDir/compileBin/rrlLimiter fields; SrvStats gains UDPQueries/TCPQueries; cache accessor chain wired through resolver -> server -> adapter; go build ./... passes.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-05-16T13:59:39Z
- **Completed:** 2026-05-16T14:04:18Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments
- `pb.RegisterAdminServiceServer` now called in `RegisterAll` — AdminService RPCs are reachable (previously returned Unimplemented regardless)
- `admin.Service` struct extended with `srv AdminSrvAdapter`, `zonesDir`, `compileBin`, `rrlLimiter` fields; `NewService` signature updated
- `services.SrvStats` gains `UDPQueries`/`TCPQueries` fields; `serverSrvAdapter.GetStats()` populates them from `server.Stats`
- Cache accessible via `resolver.Recursive.GetCache()` → `server.Server.GetCache()` → `serverSrvAdapter.GetShardedCache()`
- Nil guards added to `RefreshZone`, `ListZones`, `ReloadZones`, `GetServerStatus` per T-06-05 threat mitigation

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend SrvStats with UDP/TCP fields and update main.go adapter** - `33f4de5` (feat)
2. **Task 2: Add AdminSrvAdapter interface and new fields to admin.Service** - `8f7e08c` (feat)
3. **Task 3: Register AdminService in registry and wire adapter chain** - `0b29705` (feat)

## Files Created/Modified
- `api/grpc/services/management.go` - Added UDPQueries/TCPQueries to SrvStats; added GetShardedCache/GetAdminStats to SrvAdapter; added cache/admin imports
- `api/grpc/registry/register.go` - Added admin import; NoopSrvAdapter.GetShardedCache/GetAdminStats; admin.NewService + pb.RegisterAdminServiceServer in RegisterAll
- `internal/admin/service.go` - Added AdminSrvStats struct, AdminSrvAdapter interface, new struct fields (srv/zonesDir/compileBin/rrlLimiter), updated NewService, nil guards on 4 methods
- `internal/server/server.go` - Added Server.GetCache() delegating to recursive.GetCache()
- `internal/resolver/recursive.go` - Added Recursive.GetCache() returning r.cache
- `cmd/dnsscienced/main.go` - Added admin/cache imports; serverSrvAdapter.GetShardedCache() and GetAdminStats(); UDPQueries/TCPQueries populated in GetStats()

## Decisions Made
- Added `GetAdminStats() admin.AdminSrvStats` and `GetShardedCache() *cache.ShardedCache` to `services.SrvAdapter` so `SrvIface` (type alias) automatically requires both from all concrete adapters; no runtime type assertion needed in `RegisterAll`
- Cache chain uses new accessor methods at each layer rather than passing `*cache.ShardedCache` as a constructor parameter — consistent with the existing `GetFirewall()` pattern
- `AdminSrvStats` defined in `internal/admin` to keep import graph acyclic: `api/grpc/services` → `internal/admin` → `api/grpc/proto/pb` has no cycle back

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added nil guards to GetServerStatus for both reloadMgr and healthMgr**
- **Found during:** Task 3 (Register AdminService)
- **Issue:** Plan specified nil guards for RefreshZone/ListZones/ReloadZones but GetServerStatus also dereferences both reloadMgr and healthMgr — would panic when called with nil managers
- **Fix:** Extracted zoneCount and healthy into local vars with nil checks before constructing the response
- **Files modified:** internal/admin/service.go
- **Verification:** go build ./... exits 0; logic matches T-06-05 mitigation spec
- **Committed in:** 0b29705 (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 Rule 2 — missing critical nil guard)
**Impact on plan:** Essential for safety. GetServerStatus was called out in the plan text for nil-guarding but the code block was incomplete. No scope creep.

## Issues Encountered
- `services.SrvAdapter` needed `GetAdminStats()` added (to make SrvIface carry it for the RegisterAll call site) — plan noted this via duck typing but the Go type system requires explicit interface satisfaction. Resolved by adding the method to SrvAdapter and importing `internal/admin` from `api/grpc/services` (no import cycle exists).

## Threat Flags

None — no new network endpoints beyond those already present. AdminService is always registered but protected by the existing API key interceptor (T-06-04 mitigated by pre-existing middleware). T-06-05 (nil reloadMgr tampering) mitigated via nil guards on all four methods that dereference it. T-06-06 (nil cache in NoopSrvAdapter) accepted as design.

## Next Phase Readiness
- AdminService RPCs are now reachable end-to-end via gRPC
- Plans 03-04 can implement real stub logic using `s.srv`, `s.zonesDir`, `s.compileBin`, `s.rrlLimiter`
- Phase 7 will wire `logger` and `rrlLimiter` into NewService (replace nil); no interface changes needed

---
*Phase: 06-admin-api-stubs-registration*
*Completed: 2026-05-16*
