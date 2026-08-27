---
phase: 02-grpc-admin
plan: "04"
subsystem: grpc-registry
tags: [grpc, firewall, registry, wiring]
dependency_graph:
  requires:
    - 02-01 (pb.RegisterFirewallAdminServiceServer generated in admin_grpc.pb.go)
    - 02-02 (srv.GetFirewall() accessor on SrvAdapter; NoopSrvAdapter.GetFirewall() returning nil)
    - 02-03 (services.NewFirewallService constructor)
  provides:
    - Conditional FirewallAdminService registration in RegisterAll
    - Phase 2 gRPC admin feature complete end-to-end
  affects:
    - cmd/dnsscienced (RegisterAll is called at server startup)
tech_stack:
  added: []
  patterns:
    - "Nil-guard pattern: if fw := srv.GetFirewall(); fw != nil — ensures service is not registered when firewall disabled in config"
key_files:
  created: []
  modified:
    - api/grpc/registry/register.go
decisions:
  - "Nil-guard on GetFirewall() is the correct elevation-of-privilege mitigation (T-02-07) — FirewallAdminService surface is gated on firewall being enabled"
metrics:
  duration: "~3 minutes"
  completed: "2026-04-23T18:05:27Z"
  tasks_completed: 1
  files_modified: 1
---

# Phase 02 Plan 04: gRPC Registry Wiring Summary

**Conditional FirewallAdminService registration in RegisterAll via nil-guard on srv.GetFirewall() — final connection point for the Phase 2 gRPC admin feature.**

## Performance

- **Duration:** ~3 minutes
- **Started:** 2026-04-23T18:02:00Z
- **Completed:** 2026-04-23T18:05:27Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Added nil-guard block to `RegisterAll` in `api/grpc/registry/register.go` immediately after ManagementService registration
- `if fw := srv.GetFirewall(); fw != nil` gates `pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(fw))` — skips silently when firewall is disabled
- Confirmed `firewalld` import and `NoopSrvAdapter.GetFirewall()` were already present from Plan 02
- `go build ./...` exits 0
- All `api/grpc/services` tests pass (13 FirewallService subtests + existing tests)

## Task Commits

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Wire FirewallAdminService into RegisterAll with nil-guard | f552283 | api/grpc/registry/register.go |

## Files Modified

- `api/grpc/registry/register.go` — 6-line nil-guard block added after ManagementService registration

## Decisions Made

- The nil-guard `if fw := srv.GetFirewall(); fw != nil` is both the correct conditional registration pattern and the mitigation for T-02-07 (Elevation of Privilege) — FirewallAdminService is only exposed when the operator has explicitly enabled the firewall in config.yaml.

## Deviations from Plan

None — plan executed exactly as written. The `firewalld` import and `NoopSrvAdapter.GetFirewall()` were already present from Plan 02 as expected; no remedial additions needed.

## Pre-existing Test Failures (out of scope)

The following test failures exist in the repository prior to this plan and are unrelated to registry wiring:
- `internal/dnssec` — uint16-to-string conversion build error (pre-existing)
- `internal/engine/TestResolver_Resolve` — live DNS resolver returns real results vs. hardcoded mock (pre-existing, network-dependent)
- `internal/resolver/TestFindGlue` — output formatting mismatch (pre-existing)

These are documented in `deferred-items.md` scope boundary; not introduced by this plan.

## Known Stubs

None.

## Threat Flags

None. T-02-07 (Elevation of Privilege) is mitigated by the nil-guard: FirewallAdminService is not registered when `srv.GetFirewall()` returns nil. The existing API key interceptor in `grpc/server/server.go` authenticates all admin gRPC RPCs — no new auth surface added.

## Self-Check: PASSED

- `api/grpc/registry/register.go` contains `RegisterFirewallAdminServiceServer` — confirmed
- `api/grpc/registry/register.go` contains `if fw := srv.GetFirewall(); fw != nil` — confirmed
- `api/grpc/registry/register.go` contains `services.NewFirewallService(fw)` — confirmed
- `api/grpc/registry/register.go` contains `GetFirewall() *firewalld.Firewall` (NoopSrvAdapter) — confirmed
- `api/grpc/registry/register.go` imports `github.com/afterdarksys/dnsscienced/internal/firewalld` — confirmed
- Commit f552283 exists — confirmed
- `go build ./...` exits 0 — confirmed
- `go test ./api/grpc/services/ -run TestFirewallService` exits 0 (13 subtests pass) — confirmed
