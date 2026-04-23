---
phase: 02-grpc-admin
plan: 01
subsystem: api
tags: [grpc, protobuf, codegen, firewall]

# Dependency graph
requires: []
provides:
  - FirewallAdminService proto definition with 4 RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore)
  - Generated Go stubs: FirewallAdminServiceServer/Client interfaces in admin_grpc.pb.go
  - Generated Go message types: FirewallStatsResponse, FirewallLoadScriptRequest, FirewallInjectScoreRequest (with oneof) in admin.pb.go
affects:
  - 02-02 (implements FirewallAdminServiceServer)
  - 02-03 (registers service on gRPC server)
  - 02-04 (tests use generated types)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Append new gRPC services to existing admin.proto without modifying existing service blocks"
    - "Run generate.sh with $HOME/go/bin in PATH for protoc plugins"

key-files:
  created: []
  modified:
    - api/grpc/proto/admin.proto
    - api/grpc/proto/pb/admin.pb.go
    - api/grpc/proto/pb/admin_grpc.pb.go

key-decisions:
  - "generate.sh requires $HOME/go/bin in PATH for protoc-gen-go and protoc-gen-go-grpc plugins"
  - "management.proto uses pb/mgmt go_package; generate.sh *.proto glob generates stray management.pb.go in pb/ — must delete after regeneration"

patterns-established:
  - "FirewallAdminService appended after all existing AdminService content — additive pattern preserved"

requirements-completed:
  - GRPC-05

# Metrics
duration: 3min
completed: 2026-04-23
---

# Phase 02 Plan 01: Proto Definition and Codegen Summary

**FirewallAdminService proto definition with 4 RPCs and 8 messages appended to admin.proto; Go stubs regenerated with FirewallAdminServiceServer interface and all Firewall* message types**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-04-23T17:47:16Z
- **Completed:** 2026-04-23T17:49:38Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Appended FirewallAdminService with 4 RPCs to admin.proto without touching existing AdminService
- Regenerated admin.pb.go and admin_grpc.pb.go with complete Firewall* type set
- Project compiles cleanly (`go build ./...` exits 0)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add FirewallAdminService to admin.proto** - `d6c2d6d` (feat)
2. **Task 2: Run generate.sh to regenerate Go stubs** - `50e7aa2` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `api/grpc/proto/admin.proto` - FirewallAdminService block with 4 RPCs and 8 messages appended
- `api/grpc/proto/pb/admin.pb.go` - Regenerated: adds FirewallStatsResponse, FirewallLoadScriptRequest, FirewallRemoveScriptRequest, FirewallInjectScoreRequest (oneof domain/ip), FirewallInjectScoreResponse
- `api/grpc/proto/pb/admin_grpc.pb.go` - Regenerated: adds FirewallAdminServiceServer/Client interfaces and RegisterFirewallAdminServiceServer

## Decisions Made
- `generate.sh` uses `*.proto` glob which also regenerates management.proto; the management.proto has `go_package = ".../pb/mgmt"` but `paths=source_relative` causes it to land in `pb/` with `package mgmt`, conflicting with the `package pb` files. Stray `management.pb.go` and `management_grpc.pb.go` were deleted from `pb/` — the correct versions already exist in `pb/mgmt/`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Removed stray management.pb.go generated to wrong directory**
- **Found during:** Task 2 (run generate.sh)
- **Issue:** `generate.sh` uses `*.proto` glob; management.proto's `go_package` points to `pb/mgmt` but `paths=source_relative` deposits output in `pb/` with `package mgmt`, causing a Go package conflict that broke `go build ./...`
- **Fix:** Deleted the stray `pb/management.pb.go` and `pb/management_grpc.pb.go`; the correct files already existed in `pb/mgmt/` from a prior build
- **Files modified:** removed pb/management.pb.go, pb/management_grpc.pb.go (untracked, not committed)
- **Verification:** `go build ./...` exits 0 after removal
- **Committed in:** 50e7aa2 (Task 2 commit — files were never staged)

---

**Total deviations:** 1 auto-fixed (1 blocking — go build conflict from stray generated files)
**Impact on plan:** Necessary fix; no scope change. Upstream issue is management.proto's go_package vs generate.sh's source_relative flag.

## Issues Encountered
- `protoc-gen-go` and `protoc-gen-go-grpc` plugins not in shell PATH during `generate.sh` — resolved by adding `$HOME/go/bin` to PATH before invoking the script. Tools were already installed.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All generated types and interfaces are in place; Wave 2 plans (02-02, 02-03, 02-04) can import from `api/grpc/proto/pb` and implement `FirewallAdminServiceServer`
- Note: when regenerating protos in future, delete `pb/management.pb.go` and `pb/management_grpc.pb.go` after running generate.sh (or fix generate.sh to exclude management.proto)

---
*Phase: 02-grpc-admin*
*Completed: 2026-04-23*
