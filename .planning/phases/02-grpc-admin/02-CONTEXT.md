# Phase 2: gRPC Admin - Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Expose the existing DNS firewall management operations (stats, script load/remove, score injection) over gRPC in addition to the existing HTTP admin. This is an **additive** change — HTTP admin stays in place as fallback. No new firewall capabilities are added; this phase is purely about exposing the existing `*firewalld.Firewall` methods via RPC.

Scope: 4 RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore), proto definitions, generated stubs, service implementation, registry wiring, and unit tests.

</domain>

<decisions>
## Implementation Decisions

### Proto Structure
- **D-01:** Add a new `FirewallAdminService` service block to the existing `api/grpc/proto/admin.proto` file (do NOT extend the existing `AdminService`). One file, one codegen run, clean separation from DNS/cache/zone RPCs.

### LoadScript RPC Design
- **D-02:** `LoadScript` request carries the Starlark script **body as a string** (not a file path). The client sends the script content directly — no server filesystem access required by the caller.
- **D-03:** The caller supplies a required `script_id` string field in the `LoadScript` request. The same `script_id` is passed to `RemoveScript` to unload. IDs are not auto-generated.

### Service Implementation Location
- **D-04:** Implement `FirewallAdminService` handlers in **`api/grpc/services/firewall.go`** — consistent with the existing service pattern (`management.go`, `dns.go`, `cache.go`, etc.). Do NOT create a new `internal/admin/` package.
  - The service struct takes a `*firewalld.Firewall` and implements the generated `FirewallAdminServiceServer` interface.
  - Handlers delegate directly to `fw.Stats()`, `fw.LoadScript()`, `fw.RemoveScript()`, `fw.ThreatIntelEngine().AddDomainScore()`, `fw.ThreatIntelEngine().AddIPScore()`.

### gRPC Server Wiring
- **D-05:** Register `FirewallAdminService` on the **same existing admin gRPC server** (same port as `loadedCfg.Admin.Listen`). No new server, no new port, no new config keys.
- **D-06:** Thread the `*firewalld.Firewall` instance to the registry by adding `GetFirewall() *firewalld.Firewall` to the `SrvAdapter` interface (in `api/grpc/services/`). The `serverSrvAdapter` in `cmd/dnsscienced/main.go` implements this by calling `s.s.GetFirewall()` (or returning nil if firewall is disabled). `RegisterAll` reads `srv.GetFirewall()` and skips registration when nil.

### Claude's Discretion
- InjectScore field structure (combined domain+IP message vs. separate messages) — Claude should follow the pattern that best mirrors the existing `ThreatIntel` API
- Error responses — use standard gRPC status codes (codes.NotFound, codes.InvalidArgument, etc.)
- How LoadScript writes the body to the Starlark engine (temp file or direct string loading — whichever the StarlarkEngine supports without changes)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Firewall Core
- `internal/firewalld/firewalld.go` — Firewall struct, Stats(), LoadScript(), RemoveScript(), ThreatIntelEngine(); Stats type definition
- `internal/firewalld/admin.go` — Existing HTTP admin handler; shows the firewall operations and their HTTP semantics
- `internal/firewalld/config.go` — FirewallConfig struct; how firewall is configured
- `internal/firewalld/starlark.go` — StarlarkEngine.LoadFile(), Remove() — what LoadScript/RemoveScript delegate to
- `internal/firewalld/threat_intel.go` — ThreatIntel.AddDomainScore(), AddIPScore() — what InjectScore delegates to

### gRPC Infrastructure
- `api/grpc/proto/admin.proto` — Existing AdminService definition; add FirewallAdminService as a second service block here
- `api/grpc/services/management.go` — Canonical example of a gRPC service implementation in this codebase
- `api/grpc/registry/register.go` — RegisterAll(); extend SrvIface/SrvAdapter here and add firewall service registration
- `api/grpc/server/server.go` — gRPC server setup (TLS, API key interceptors)

### Startup Wiring
- `cmd/dnsscienced/main.go` — serverSrvAdapter definition; must add GetFirewall() implementation here

### Generate
- `generate.sh` — Run after any .proto changes to regenerate Go stubs

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `api/grpc/server/server.go`: `server.New(cfg, deps)` — existing gRPC server factory; no changes needed
- `api/grpc/services/management.go`: `ManagementService` — the canonical template for a new service struct (embed `Unimplemented*Server`, inject deps via constructor, implement methods with `context.Context`)
- `api/grpc/registry/register.go`: `RegisterAll()` + `SrvIface` — extend to wire in the new service
- `internal/firewalld/firewalld.go`: All 4 operations already implemented on `*Firewall`; gRPC handlers are thin delegation wrappers

### Established Patterns
- Service implementations embed `pb.Unimplemented*ServiceServer` for forward compatibility
- Constructors are `NewXxxService(deps...)` returning the concrete type
- gRPC status errors use `status.Error(codes.XYZ, "message")` and `status.Errorf`
- Tests use table-driven patterns (see `internal/firewalld/firewalld_test.go`)

### Integration Points
- `registry.RegisterAll` is the single registration point — add `pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(srv.GetFirewall()))` here
- `SrvAdapter` interface (in `api/grpc/services/`) needs `GetFirewall() *firewalld.Firewall`
- `serverSrvAdapter` in `cmd/dnsscienced/main.go` must implement the new method
- `internal/server.Server` already holds `*firewalld.Firewall` as a field — add a `GetFirewall()` accessor method

</code_context>

<specifics>
## Specific Ideas

- `grpcurl` is the stated test tool in the ROADMAP success criteria — handlers must work correctly with standard protobuf request/response (no streaming required for these 4 RPCs)
- All 4 RPCs are unary (no streaming): FirewallStats, LoadScript, RemoveScript, InjectScore
- LoadScript body approach: if `StarlarkEngine.LoadFile(path)` is the only entry point, the handler should write the body to a temp file and call LoadFile, then track the mapping from script_id → temp path. Alternatively, a `LoadSource(id, source string)` method can be added to StarlarkEngine — Claude's discretion which is cleaner.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 02-grpc-admin*
*Context gathered: 2026-04-23*
