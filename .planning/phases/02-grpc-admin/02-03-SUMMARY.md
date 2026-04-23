---
phase: 02-grpc-admin
plan: "03"
subsystem: grpc-firewall-service
tags: [grpc, firewall, service, tdd]
dependency_graph:
  requires:
    - 02-01 (FirewallAdminServiceServer interface, Firewall* message types)
    - 02-02 (LoadSource, RemoveScript on *Firewall; ThreatIntelEngine accessor)
  provides:
    - FirewallService implementing FirewallAdminServiceServer (all 4 RPCs)
    - Unit tests covering happy path and validation for all 4 RPCs
  affects:
    - 02-04 (registers FirewallService on gRPC admin server)
tech_stack:
  added: []
  patterns:
    - "Thin delegation wrapper: service layer holds no business logic, just validates input and calls fw.*"
    - "oneof target dispatch: switch req.Target.(type) for domain vs IP scoring"
key_files:
  created:
    - api/grpc/services/firewall.go
    - api/grpc/services/firewall_test.go
  modified: []
decisions:
  - "TotalNxdomain (not TotalNXDomain) is the correct proto-generated field name — confirmed via grep before writing implementation"
  - "firewalld.Config{Enabled: true} is the correct constructor field — confirmed via config.go grep"
metrics:
  duration: "~2 minutes"
  completed: "2026-04-23T17:58:43Z"
  tasks_completed: 2
  files_modified: 2
---

# Phase 02 Plan 03: FirewallService Implementation Summary

**FirewallService struct with all 4 gRPC admin RPCs implemented as thin delegation wrappers, with table-driven unit tests covering 13 subtests across 4 test functions — all passing.**

## Performance

- **Duration:** ~2 minutes
- **Started:** 2026-04-23T17:57:16Z
- **Completed:** 2026-04-23T17:58:43Z
- **Tasks:** 2
- **Files created:** 2

## Accomplishments

- Created `api/grpc/services/firewall.go` with `FirewallService` implementing `pb.FirewallAdminServiceServer`
- FirewallStats maps all 5 counter fields (TotalQueries, TotalBlocked, TotalNxdomain, TotalDropped, TotalRedirected)
- LoadScript validates script_id and body non-empty; delegates to fw.LoadSource(); returns InvalidArgument with "compile script:" prefix on Starlark syntax errors
- RemoveScript validates script_id non-empty; delegates to fw.RemoveScript(); silently succeeds if script not loaded
- InjectScore dispatches oneof target to AddDomainScore or AddIPScore with empty-string validation on each branch
- Created `api/grpc/services/firewall_test.go` with 4 test functions and 13 subtests; all pass

## Task Commits

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create firewall.go — FirewallService implementation | 2158927 | api/grpc/services/firewall.go |
| 2 | Create firewall_test.go — unit tests for all 4 RPCs | daec1e3 | api/grpc/services/firewall_test.go |

## Files Created

- `api/grpc/services/firewall.go` — FirewallService struct, NewFirewallService constructor, FirewallStats/LoadScript/RemoveScript/InjectScore handlers
- `api/grpc/services/firewall_test.go` — newTestFirewall helper + 4 table-driven test functions

## Decisions Made

- `TotalNxdomain` (lowercase 'd') is the correct proto-generated field name for the `total_nxdomain` proto field — confirmed by grepping admin.pb.go before implementation. The generated getter is `GetTotalNxdomain()`.
- `firewalld.Config{Enabled: true}` is the correct constructor call for test firewall instances — confirmed via config.go.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None. The threat register items T-02-03 and T-02-04 have been fully mitigated:
- T-02-03: LoadScript validates script_id and body non-empty before delegating; Starlark compile errors return codes.InvalidArgument
- T-02-04: InjectScore validates domain/ip non-empty; dispatches to correct AddDomainScore/AddIPScore method

## Self-Check: PASSED

- `/Users/ryan/development/dnsscienced/api/grpc/services/firewall.go` exists and contains:
  - `type FirewallService struct`
  - `pb.UnimplementedFirewallAdminServiceServer`
  - `func NewFirewallService(fw *firewalld.Firewall)`
  - `func (s *FirewallService) FirewallStats`
  - `func (s *FirewallService) LoadScript`
  - `func (s *FirewallService) RemoveScript`
  - `func (s *FirewallService) InjectScore`
  - `s.fw.LoadSource(req.ScriptId, req.Body)`
  - `codes.InvalidArgument`
- `/Users/ryan/development/dnsscienced/api/grpc/services/firewall_test.go` exists and contains:
  - `TestFirewallService_Stats`
  - `TestFirewallService_LoadScript`
  - `TestFirewallService_RemoveScript`
  - `TestFirewallService_InjectScore`
- Commit 2158927 exists (Task 1)
- Commit daec1e3 exists (Task 2)
- `go build ./api/grpc/services/...` exits 0
- `go test ./api/grpc/services/ -run TestFirewallService` exits 0 (13 subtests pass)
