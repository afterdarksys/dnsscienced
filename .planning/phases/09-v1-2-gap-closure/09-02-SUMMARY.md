---
phase: 09-v1-2-gap-closure
plan: "02"
subsystem: admin-grpc
status: COMPLETE
tags: [admin, grpc, wiring, production-gaps]
dependency_graph:
  requires: ["09-01"]
  provides: ["ADMIN-LOG-02", "ADMIN-RRL-02", "ADMIN-CONN-01", "ADMIN-LISTZONES-01"]
  affects: ["cmd/dnsscienced", "api/grpc/registry", "internal/admin"]
tech_stack:
  added: []
  patterns: ["post-construction setter", "interface extension", "fallback path"]
key_files:
  modified:
    - api/grpc/registry/register.go
    - internal/admin/service.go
    - cmd/dnsscienced/main.go
    - cmd/dnsscience-grpc/main.go
decisions:
  - "ConnRegistry wired via post-construction SetConnRegistry setter (chicken-and-egg: Register closure runs inside grpcserver.New before connReg is returned)"
  - "buildZoneInfo extracted as shared helper used by both reloadMgr and srv fallback paths"
  - "cmd/dnsscience-grpc passes nil logger to RegisterAll (no audit logger needed in standalone binary)"
metrics:
  duration: "~15 minutes"
  completed: "2026-05-18"
  tasks_completed: 2
  files_modified: 4
---

# Phase 09 Plan 02: Wire logger/rrlLimiter/connReg/zones into admin.Service Summary

**One-liner:** Closed 4 production nil-injection gaps in admin.Service by wiring real logger, rrlLimiter, connRegistry, and zone enumeration fallback via RegisterAll signature extension and post-construction setter.

## What Was Done

### Task 1: Extend RegisterAll + AdminSrvAdapter + ListZones fallback

**api/grpc/registry/register.go:**
- Added `logging` import
- Extended `RegisterAll` signature: added `logger *logging.Logger` parameter, changed return type to `*admin.Service`
- Changed `nil` for logger to `logger` in `admin.NewService` call (ADMIN-LOG-02)
- Changed `nil` for rrlLimiter to `srv.GetRRL()` in `admin.NewService` call (ADMIN-RRL-02)
- Added `return adminSvc` at end of function

**internal/admin/service.go:**
- Added `GetZoneNames() []string` to `AdminSrvAdapter` interface
- Added `SetConnRegistry(reg *grpcserver.ConnRegistry)` setter method after `NewService` (ADMIN-CONN-01)
- Replaced `ListZones` with fallback version: tries `reloadMgr` first, falls back to `srv.GetZoneNames()` + `srv.GetZone()` when `reloadMgr` is nil (ADMIN-LISTZONES-01)
- Extracted `buildZoneInfo` helper shared by both code paths

### Task 2: Wire in main.go

**cmd/dnsscienced/main.go:**
- Declared `var adminSvc *admin.Service` before `grpcDeps` block to capture RegisterAll return
- Updated RegisterAll call to assign return: `adminSvc = registry.RegisterAll(..., adminLogger)`
- Replaced `_ = connReg` with post-construction wiring: `adminSvc.SetConnRegistry(connReg)`

## Requirements Satisfied

| Requirement | Description | How Closed |
|-------------|-------------|------------|
| ADMIN-LOG-02 | SetQueryLogging RPC wired to real logger | logger passed from main.go via RegisterAll |
| ADMIN-RRL-02 | SetRateLimit RPC wired to real rrlLimiter | srv.GetRRL() passed in admin.NewService |
| ADMIN-CONN-01 | ListConnections uses real ConnRegistry | SetConnRegistry called post-construction |
| ADMIN-LISTZONES-01 | ListZones enumerates zones via srv fallback | srv.GetZoneNames() fallback in ListZones |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking Build] Fixed cmd/dnsscience-grpc/main.go call site**
- **Found during:** Task 2 full build verification
- **Issue:** `cmd/dnsscience-grpc/main.go` called `registry.RegisterAll` with 6 arguments after signature was extended to require 7
- **Fix:** Added `nil` as the logger argument (standalone binary has no audit logger)
- **Files modified:** `cmd/dnsscience-grpc/main.go`
- **Commit:** 20ddc7d

## Verification Results

```
go build ./...          PASS (zero errors)
go test ./internal/admin/...    PASS
go test ./api/grpc/...          PASS
go test ./cmd/dnsscienced/...   PASS
All non-engine/resolver tests   PASS
```

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Task 1 | 445fbf3 | feat(admin): extend RegisterAll signature + AdminSrvAdapter + ListZones fallback |
| Task 2 | 20ddc7d | feat(admin): wire logger/connReg into main.go + fix dnsscience-grpc call site |

## Self-Check: PASSED
- api/grpc/registry/register.go exists and contains `srv.GetRRL()` and `*admin.Service` return type
- internal/admin/service.go contains `func (s *Service) SetConnRegistry`
- cmd/dnsscienced/main.go contains `adminSvc.SetConnRegistry(connReg)`
- go build ./... passes with zero errors
- All tests pass
