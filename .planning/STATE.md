# State

## Current Position

Phase: 3 — Live Threat Feed
Plan: —
Status: Context gathered — ready for planning
Last activity: 2026-04-23 — Phase 3 context captured (discuss-phase complete)

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
- Phase 2 Plan 02 complete: LoadSource(id, src) on *Firewall; GetFirewall() accessor chain wired through SrvAdapter to serverSrvAdapter and NoopSrvAdapter; go build ./... passes
- NoopSrvAdapter.GetFirewall() returns nil — nil guard required at call site in Plan 04 RegisterAll
- firewalld import added to api/grpc/services/management.go and api/grpc/registry/register.go
- Phase 2 Plan 03 complete: FirewallService struct implements FirewallAdminServiceServer; all 4 RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore) implemented with validation and delegation; 13 unit tests passing
- TotalNxdomain (lowercase d) is the correct proto-generated field name for total_nxdomain
- api/grpc/services/firewall.go and firewall_test.go created; go test ./api/grpc/services/ -run TestFirewallService exits 0
- Phase 2 Plan 04 complete: RegisterAll in api/grpc/registry/register.go now conditionally registers FirewallAdminService via nil-guard on srv.GetFirewall(); go build ./... passes; Phase 2 gRPC Admin feature is end-to-end complete
- Nil-guard pattern: if fw := srv.GetFirewall(); fw != nil — FirewallAdminService not registered when firewall.enabled is false in config.yaml (T-02-07 mitigation)
- Pre-existing test failures (not introduced by Phase 2): internal/dnssec build error, internal/engine/TestResolver_Resolve (live DNS), internal/resolver/TestFindGlue (formatting)
