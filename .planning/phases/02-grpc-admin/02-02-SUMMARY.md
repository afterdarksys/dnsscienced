---
phase: 02-grpc-admin
plan: "02"
subsystem: firewall-adapter
tags: [grpc, firewall, adapter, interface]
dependency_graph:
  requires: []
  provides: [LoadSource-on-Firewall, GetFirewall-accessor-chain]
  affects: [api/grpc/services, api/grpc/registry, cmd/dnsscienced]
tech_stack:
  added: []
  patterns: [adapter-delegation, interface-extension]
key_files:
  created: []
  modified:
    - internal/firewalld/firewalld.go
    - internal/server/server.go
    - api/grpc/services/management.go
    - api/grpc/registry/register.go
    - cmd/dnsscienced/main.go
decisions:
  - "firewalld import added to management.go and register.go to satisfy interface type constraint"
  - "serverSrvAdapter.GetFirewall() uses one-liner delegation pattern consistent with other adapter methods"
  - "NoopSrvAdapter.GetFirewall() returns nil — nil guard required at call site (Plan 04)"
metrics:
  duration: "~5 minutes"
  completed: "2026-04-23T17:54:15Z"
  tasks_completed: 2
  files_modified: 5
---

# Phase 02 Plan 02: Thread GetFirewall() Accessor Chain Summary

JWT-style additive wiring of *firewalld.Firewall through LoadSource() on Firewall, GetFirewall() on Server, SrvAdapter interface extension, and both concrete adapter implementations.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add LoadSource() to *Firewall and GetFirewall() to *Server | 3ef6efc | internal/firewalld/firewalld.go, internal/server/server.go |
| 2 | Extend SrvAdapter interface and implement in serverSrvAdapter + NoopSrvAdapter | 7d0dd34 | api/grpc/services/management.go, api/grpc/registry/register.go, cmd/dnsscienced/main.go |

## What Was Built

Four small additive Go changes that thread `*firewalld.Firewall` from the server through the adapter chain to the gRPC registry:

1. **`Firewall.LoadSource(id, src string) error`** — delegates to `fw.starlark.Load(id, src)`, enabling gRPC handlers to load policy scripts from string bodies without touching the filesystem.

2. **`Server.GetFirewall() *firewalld.Firewall`** — simple accessor returning `s.firewall`; returns nil when firewall is disabled in config.

3. **`SrvAdapter.GetFirewall() *firewalld.Firewall`** — added to the interface in `api/grpc/services/management.go` along with the `firewalld` package import. Wave 2 Plan 04 (RegisterAll) uses this to conditionally register FirewallAdminService.

4. **`serverSrvAdapter.GetFirewall()`** and **`NoopSrvAdapter.GetFirewall()`** — concrete implementations. The real adapter delegates to `a.s.GetFirewall()`; the noop returns nil.

No existing behaviour was altered. All changes are purely additive.

## Verification

- `go build ./internal/firewalld/...` — passes
- `go build ./internal/server/...` — passes
- `go build ./api/grpc/...` — passes
- `go build ./cmd/dnsscienced/...` — passes
- `go build ./...` — passes (full project)

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — no placeholder data or hardcoded values introduced.

## Threat Flags

None — GetFirewall() accessor is process-internal only; not exposed externally. Nil guard at call site deferred to Plan 04 as noted in threat register T-02-02.

## Self-Check: PASSED

- internal/firewalld/firewalld.go: contains `func (fw *Firewall) LoadSource`
- internal/server/server.go: contains `func (s *Server) GetFirewall`
- api/grpc/services/management.go: SrvAdapter interface contains `GetFirewall() *firewalld.Firewall`
- cmd/dnsscienced/main.go: contains `func (a *serverSrvAdapter) GetFirewall`
- api/grpc/registry/register.go: NoopSrvAdapter contains `GetFirewall() *firewalld.Firewall` returning nil
- Commits 3ef6efc and 7d0dd34 exist in git log
