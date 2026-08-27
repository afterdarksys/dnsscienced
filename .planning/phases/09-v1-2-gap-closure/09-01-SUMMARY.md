---
phase: 09-v1-2-gap-closure
plan: "01"
subsystem: server/grpc-adapter
status: COMPLETE
tags: [server, rrl, zones, grpc, adapter, interface]
dependency_graph:
  requires: []
  provides:
    - server.Server.GetRRL()
    - server.Server.GetZoneNames()
    - SrvAdapter.GetRRL()
    - SrvAdapter.GetZoneNames()
  affects:
    - api/grpc/services/management.go
    - api/grpc/registry/register.go
    - cmd/dnsscienced/main.go
tech_stack:
  added: []
  patterns:
    - accessor delegation through SrvAdapter interface
key_files:
  created: []
  modified:
    - internal/server/server.go
    - api/grpc/services/management.go
    - api/grpc/registry/register.go
    - cmd/dnsscienced/main.go
decisions:
  - GetRRL returns nil when RRL disabled (safe zero value)
  - GetZoneNames iterates cfg.Zones map; order is non-deterministic (callers sort if needed)
metrics:
  duration: "~3 minutes"
  completed: "2026-05-18"
  tasks_completed: 2
  files_modified: 4
---

# Phase 09 Plan 01: Server Accessors + SrvAdapter Extension Summary

Added `GetRRL()` and `GetZoneNames()` accessors to `server.Server` and extended the
`SrvAdapter` interface and all three implementations so Plan 02 can inject real values
into `admin.NewService`.

## What Was Done

### Task 1: Add GetRRL() and GetZoneNames() to server.Server

Added two new public methods to `internal/server/server.go`:

- `GetRRL() *rrl.Limiter` — placed after `GetTsigKeyRing()` (line ~446); returns `s.rrl` which is nil when RRL is disabled in config.
- `GetZoneNames() []string` — placed after `GetZone()` (line ~921); iterates `s.cfg.Zones` map and returns all origin strings as a slice.

No new imports were needed; `rrl` was already imported and `[]string` is a builtin.

Commit: `aadfd59`

### Task 2: Extend SrvAdapter interface + all implementations

Three files updated:

1. `api/grpc/services/management.go` — added `GetRRL() *rrl.Limiter` and `GetZoneNames() []string` to the `SrvAdapter` interface; added `rrl` package import.

2. `api/grpc/registry/register.go` — added `NoopSrvAdapter` implementations returning `nil`/`nil`; added `rrl` package import.

3. `cmd/dnsscienced/main.go` — added `serverSrvAdapter` implementations that delegate to `a.s.GetRRL()` and `a.s.GetZoneNames()`; added `rrl` package import.

Commit: `ebd8260`

## Verification Results

```
$ go build ./internal/server/...
(no output — success)

$ go build ./...
(no output — success)

$ go test ./internal/server/... ./api/grpc/services/... ./api/grpc/registry/...
ok  	github.com/afterdarksys/dnsscienced/internal/server	0.446s
ok  	github.com/afterdarksys/dnsscienced/api/grpc/services	0.759s
?   	github.com/afterdarksys/dnsscienced/api/grpc/registry	[no test files]
```

## Must-Haves Checklist

- [x] `server.Server` has `GetRRL() *rrl.Limiter` method
- [x] `server.Server` has `GetZoneNames() []string` method
- [x] `SrvAdapter` interface in `api/grpc/services/management.go` includes `GetRRL()` and `GetZoneNames()`
- [x] `serverSrvAdapter` in `cmd/dnsscienced/main.go` implements both methods
- [x] `NoopSrvAdapter` in `api/grpc/registry/register.go` implements both methods with nil/empty returns
- [x] `go build ./...` passes with zero errors

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None - no stub patterns introduced. `GetRRL()` returning nil when disabled is correct behavior (nil-guarded at call sites).

## Threat Flags

None - no new network endpoints, auth paths, or trust boundary surfaces introduced beyond what the threat model anticipated (T-09-01: accepted, same surface as existing accessors, protected by mTLS+Bearer auth).

## Self-Check: PASSED

- internal/server/server.go: FOUND (GetRRL and GetZoneNames methods present)
- api/grpc/services/management.go: FOUND (GetRRL, GetZoneNames in SrvAdapter interface)
- cmd/dnsscienced/main.go: FOUND (serverSrvAdapter.GetRRL and serverSrvAdapter.GetZoneNames)
- api/grpc/registry/register.go: FOUND (NoopSrvAdapter.GetRRL and NoopSrvAdapter.GetZoneNames)
- Commit aadfd59: FOUND
- Commit ebd8260: FOUND
