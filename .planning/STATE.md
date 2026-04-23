# State

## Current Position

Phase: 2 — gRPC Admin
Plan: 01 complete (02-01-PLAN.md)
Status: In progress — ready for Plan 02
Last activity: 2026-04-23 — 02-01 executed (proto definition + codegen)

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23)

**Core value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.
**Current focus:** v1.1 — dnsfirewalld Completion

## Accumulated Context

- v1.0 shipped cleanly; 19 tests green; binary builds as `dnsscienced-linux`
- HTTP admin handler lives in `internal/firewalld/admin.go` — interim, stays as fallback
- Proto codegen: run `generate.sh` after any `.proto` changes
- ThreatIntelConfig.FeedURL field exists in config.go but is unused
- QueryContext.CustomerID exists in struct but never populated
- Forwarder currently takes a single upstream target from rule/Starlark
- Starlark `on_query(q, score)` signature — q is dict, score 0-100 int
- Phase 2 Plan 01 complete: FirewallAdminService appended to admin.proto; Go stubs regenerated (admin.pb.go, admin_grpc.pb.go); go build ./... passes
- generate.sh requires $HOME/go/bin in PATH for protoc plugins; also generates stray management.pb.go in pb/ — delete after codegen (correct files are in pb/mgmt/)
- FirewallAdminServiceServer interface and all Firewall* message types now available in api/grpc/proto/pb for Wave 2 plans
