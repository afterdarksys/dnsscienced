# Phase 2: gRPC Admin - Research

**Researched:** 2026-04-23
**Domain:** gRPC service implementation, protobuf codegen, Go interface extension
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Add `FirewallAdminService` as a new service block in the existing `api/grpc/proto/admin.proto`. Do NOT extend `AdminService`. One file, one codegen run.
- **D-02:** `LoadScript` request carries the Starlark script body as a string (not a file path). No server filesystem access by the caller.
- **D-03:** Caller supplies a required `script_id` string field in `LoadScript` request. Same `script_id` used in `RemoveScript`. IDs are not auto-generated.
- **D-04:** Handlers live in `api/grpc/services/firewall.go`. Service struct takes `*firewalld.Firewall` and implements generated `FirewallAdminServiceServer` interface. No `internal/admin/` package.
- **D-05:** Register `FirewallAdminService` on the existing admin gRPC server (same port as `loadedCfg.Admin.Listen`). No new server, no new port, no new config keys.
- **D-06:** Thread `*firewalld.Firewall` to the registry by adding `GetFirewall() *firewalld.Firewall` to the `SrvAdapter` interface (in `api/grpc/services/`). `serverSrvAdapter` in `cmd/dnsscienced/main.go` implements it by calling `s.s.GetFirewall()`. `RegisterAll` reads `srv.GetFirewall()` and skips registration when nil.

### Claude's Discretion

- InjectScore field structure (combined domain+IP message vs. separate messages) — follow the pattern that best mirrors the existing `ThreatIntel` API.
- Error responses — use standard gRPC status codes (codes.NotFound, codes.InvalidArgument, etc.).
- How LoadScript writes the body to the Starlark engine (temp file or direct string loading — whichever StarlarkEngine supports without changes).

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| GRPC-01 | Operator can call FirewallStats via gRPC and receive current counters | `fw.Stats()` returns `firewalld.Stats` with 5 `uint64` fields — map directly to proto `uint64` fields |
| GRPC-02 | Operator can call LoadScript via gRPC to add or replace a Starlark script | `StarlarkEngine.Load(id, src string)` exists and handles string input directly — no temp file needed |
| GRPC-03 | Operator can call RemoveScript via gRPC to unload a named script | `fw.RemoveScript(id)` delegates to `StarlarkEngine.Remove(id)` |
| GRPC-04 | Operator can call InjectScore via gRPC to add a domain or IP threat score | `fw.ThreatIntelEngine().AddDomainScore(domain, score)` and `.AddIPScore(ip, score)` are the delegation targets |
| GRPC-05 | gRPC admin RPCs are defined in admin.proto and implemented in `api/grpc/services/firewall.go` (NOTE: REQUIREMENTS.md says `internal/admin/` but CONTEXT.md D-04 overrides this to `api/grpc/services/firewall.go`) | Pattern established by `management.go` in same package |
</phase_requirements>

---

## Summary

Phase 2 adds a `FirewallAdminService` gRPC service exposing four unary RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore) backed by the existing `*firewalld.Firewall` instance. The change is purely additive — the HTTP admin handler in `internal/firewalld/admin.go` stays untouched.

The codebase has all necessary building blocks in place. `StarlarkEngine` already has a `Load(id, src string)` method (D-02 discretion resolved: no temp file needed — direct string loading works). `ThreatIntel` exposes both `AddDomainScore` and `AddIPScore` with clean signatures. The existing `ManagementService` in `management.go` provides the exact structural template for the new service.

The primary wiring challenge is threading `*firewalld.Firewall` from `internal/server.Server` through the `SrvAdapter` interface to `RegisterAll`. `server.Server` holds a `firewall` field but currently has no `GetFirewall()` accessor — that method must be added. The `serverSrvAdapter` in `main.go` must then implement the new interface method. `RegisterAll` conditionally registers the service only when `srv.GetFirewall() != nil` (firewall disabled in config means nil).

**Primary recommendation:** Implement in a single logical sequence — proto definition, codegen, service struct, accessor chain, registry wiring, tests. Each step has no ambiguity; the pattern is fully specified by existing code.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Proto definition | API layer (`api/grpc/proto/`) | — | Follows all other service protos in this codebase |
| Code generation | Build-time tooling | — | `generate.sh` in proto dir runs protoc |
| RPC handler logic | API service layer (`api/grpc/services/`) | — | Thin delegation only — no business logic |
| Firewall state mutations | `internal/firewalld` | — | All state owned by `*Firewall`; gRPC handlers are pass-through |
| Service registration | `api/grpc/registry/register.go` | — | Single registration point for all services |
| Dependency wiring | `cmd/dnsscienced/main.go` | `internal/server.Server` | Adapter pattern used for all existing services |

---

## Standard Stack

### Core (already in go.mod — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `google.golang.org/grpc` | v1.78.0 | gRPC server/client framework | Already in use; all services use it |
| `google.golang.org/protobuf` | v1.36.11 | Protobuf runtime | Already in use for all proto messages |
| `google.golang.org/grpc/codes` | (part of grpc) | Standard gRPC status codes | Pattern established in `management.go` |
| `google.golang.org/grpc/status` | (part of grpc) | Error construction | Pattern established in `management.go` |

**No new dependencies required.** [VERIFIED: go.mod in codebase]

### Tooling

| Tool | Version | Purpose | Status |
|------|---------|---------|--------|
| `protoc` | libprotoc 33.4 | Proto compiler | Available at `/usr/local/bin/protoc` |
| `protoc-gen-go` | — | Go proto plugin | Available at `~/go/bin/protoc-gen-go` |
| `protoc-gen-go-grpc` | — | Go gRPC plugin | Available at `~/go/bin/protoc-gen-go-grpc` |

[VERIFIED: `command -v protoc`, `ls ~/go/bin/protoc-gen-go*`]

---

## Architecture Patterns

### System Architecture Diagram

```
grpcurl / operator client
        |
        | (gRPC unary RPC, same admin port)
        v
[grpc/server/server.go] — TLS + API key interceptor
        |
        v
[api/grpc/services/firewall.go] — FirewallService
  FirewallStats()   ─────────────► fw.Stats()
  LoadScript()      ─────────────► fw.starlark.Load(id, src)
  RemoveScript()    ─────────────► fw.RemoveScript(id) ─► starlark.Remove(id)
  InjectScore()     ─────────────► fw.ThreatIntelEngine().AddDomainScore()
                                                        .AddIPScore()
        ^
        | (registered via)
[api/grpc/registry/register.go] — RegisterAll()
        ^
        | (srv.GetFirewall() != nil)
[cmd/dnsscienced/main.go] — serverSrvAdapter.GetFirewall()
        ^
        |
[internal/server/server.go] — Server.GetFirewall() returns s.firewall
        ^
        |
[internal/firewalld/firewalld.go] — *Firewall (live instance)
```

### Recommended File Changes

```
api/grpc/proto/
└── admin.proto              # ADD FirewallAdminService + 8 messages

api/grpc/proto/pb/
└── admin.pb.go              # REGENERATED (protoc output)
└── admin_grpc.pb.go         # REGENERATED (protoc output)

api/grpc/services/
├── management.go            # UNCHANGED (template reference only)
├── firewall.go              # CREATE NEW — FirewallService implementation

api/grpc/registry/
└── register.go              # EXTEND SrvIface alias + add registration block

internal/server/
└── server.go                # ADD GetFirewall() *firewalld.Firewall accessor

cmd/dnsscienced/
└── main.go                  # ADD GetFirewall() to serverSrvAdapter
```

### Pattern 1: Service Struct (from management.go)

```go
// Source: api/grpc/services/management.go — ManagementService pattern
type FirewallService struct {
    pb.UnimplementedFirewallAdminServiceServer
    fw *firewalld.Firewall
}

func NewFirewallService(fw *firewalld.Firewall) *FirewallService {
    return &FirewallService{fw: fw}
}

func (s *FirewallService) FirewallStats(ctx context.Context, _ *pb.FirewallStatsRequest) (*pb.FirewallStatsResponse, error) {
    stats := s.fw.Stats()
    return &pb.FirewallStatsResponse{
        TotalQueries:    stats.TotalQueries,
        TotalBlocked:    stats.TotalBlocked,
        TotalNXDomain:   stats.TotalNXDomain,
        TotalDropped:    stats.TotalDropped,
        TotalRedirected: stats.TotalRedirected,
    }, nil
}
```

[VERIFIED: pattern from api/grpc/services/management.go]

### Pattern 2: gRPC Status Errors (from management.go)

```go
// Source: api/grpc/services/management.go
return nil, status.Error(codes.InvalidArgument, "script_id is required")
return nil, status.Errorf(codes.Internal, "load script: %v", err)
```

[VERIFIED: pattern from api/grpc/services/management.go]

### Pattern 3: SrvAdapter Interface Extension (from register.go)

The `SrvIface` type alias in `register.go` points to `services.SrvAdapter` defined in `management.go`:

```go
// Current in api/grpc/services/management.go
type SrvAdapter interface {
    GetZone(origin string) *zone.Zone
    AddZone(z *zone.Zone) error
    RemoveZone(origin string)
    GetStats() SrvStats
}

// Extended for Phase 2 — add this method:
    GetFirewall() *firewalld.Firewall
```

[VERIFIED: api/grpc/registry/register.go, api/grpc/services/management.go]

### Pattern 4: Conditional Registration (from register.go)

```go
// In RegisterAll — guard against nil firewall (disabled in config)
if fw := srv.GetFirewall(); fw != nil {
    pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(fw))
}
```

[VERIFIED: register.go pattern — RegisterAll already skips nil-safe checks for zone/cache managers]

### Pattern 5: StarlarkEngine.Load() — Direct String Loading

`StarlarkEngine` exposes both `LoadFile(path string)` and `Load(id, src string)`. D-02 specifies the client sends script body as a string. The `Load(id, src)` method handles this directly:

```go
// Source: internal/firewalld/starlark.go lines 67-81
func (se *StarlarkEngine) Load(id, src string) error {
    // compiles src with id as the script identifier
}
```

The `LoadScript` RPC handler should call `fw.starlark.Load(req.ScriptId, req.Body)` — but `starlark` is an unexported field. The handler must go through `fw.LoadScript()`. However, `fw.LoadScript(path string)` only takes a path. **Resolution needed:** Either add `fw.LoadSource(id, src string)` on `*Firewall`, or call `fw.starlark.Load(id, src)` directly (requires exporting StarlarkEngine method — already exported as `Load`). Best approach: add `LoadSource(id, src string) error` to `*Firewall` that delegates to `fw.starlark.Load(id, src)`. This is consistent with `fw.LoadScript` for file-based loading. [VERIFIED: firewalld.go, starlark.go]

### Pattern 6: InjectScore — Combined vs. Separate Messages

The `ThreatIntel` API has `AddDomainScore(domain string, score int)` and `AddIPScore(ip string, score int)`. The HTTP admin uses separate endpoints (`/intel/domain`, `/intel/ip`). Following the existing API shape, InjectScore should use a single proto message with a `oneof` or type discriminator:

```proto
message FirewallInjectScoreRequest {
  oneof target {
    string domain = 1;
    string ip     = 2;
  }
  int32 score = 3;
}
```

This mirrors the HTTP API's `{"domain":"evil.com","score":80}` vs. `{"ip":"1.2.3.4","score":90}` and lets the handler branch on the oneof. [VERIFIED: internal/firewalld/admin.go, threat_intel.go]

### Anti-Patterns to Avoid

- **Extending AdminService:** D-01 explicitly forbids this. The new service must be `FirewallAdminService`.
- **Using `fw.LoadScript(path)` for gRPC:** This takes a file path — the gRPC handler receives script body. Use `fw.LoadSource(id, src)` (new method on Firewall) or call `fw.starlark.Load(id, src)` through a new public `Firewall` method.
- **Importing `internal/firewalld` from `api/grpc/registry`:** The import cycle is avoided by using the adapter pattern. `SrvAdapter.GetFirewall()` returns `*firewalld.Firewall`, which is fine since `registry` already imports `services` which can import `firewalld`.
- **Skipping `Unimplemented*Server` embedding:** All existing services embed this for forward compatibility.
- **Non-nil firewall check missing:** `RegisterAll` must guard — if firewall is disabled in config, `srv.GetFirewall()` returns nil.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| gRPC error codes | Custom error types | `status.Error(codes.XYZ, msg)` | Standard gRPC error propagation |
| Proto message serialization | Manual encoding | protoc-generated types | Already generated, type-safe |
| Concurrent state access | Custom locking in handler | Delegate to firewalld methods | `*Firewall` methods are already concurrent-safe (atomic counters, sync.RWMutex) |
| Script compilation | Custom Starlark parser | `StarlarkEngine.Load()` | Already handles compilation and concurrent script map |

---

## Runtime State Inventory

This phase is additive code/config only — no renames, no data migration, no stored state changes.

| Category | Items Found | Action Required |
|----------|-------------|-----------------|
| Stored data | None | — |
| Live service config | None | — |
| OS-registered state | None | — |
| Secrets/env vars | None | — |
| Build artifacts | None — `go build` from source | — |

---

## Common Pitfalls

### Pitfall 1: `Firewall.LoadScript` only takes a path

**What goes wrong:** Handler calls `fw.LoadScript(req.ScriptId)` thinking it accepts body, but the method signature is `LoadScript(path string)` — it reads from filesystem.
**Why it happens:** The existing `LoadScript` method was designed for file-path-based hot reload.
**How to avoid:** Add `LoadSource(id, src string) error` to `*Firewall` that calls `fw.starlark.Load(id, src)`. The gRPC handler uses `LoadSource`; file-based reload keeps using `LoadScript`.
**Warning signs:** If the handler works when script_id == a valid file path but not when it's an arbitrary name.

### Pitfall 2: Import cycle via firewalld in registry

**What goes wrong:** Adding `GetFirewall() *firewalld.Firewall` to the interface in `registry` package would require `registry` to import `internal/firewalld`, which may create a cycle.
**Why it happens:** `registry` already imports `services`. The method should be defined in `services.SrvAdapter` (in `api/grpc/services/management.go`), not in `registry`. `registry` uses `SrvIface = services.SrvAdapter`, so the method propagates automatically.
**How to avoid:** Add `GetFirewall()` to `SrvAdapter` in `services/management.go`, not in `register.go`.

### Pitfall 3: Proto go_package for FirewallAdminService

**What goes wrong:** If `admin.proto` uses `go_package = "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"`, generated stubs land in `pb/` alongside existing `admin.pb.go`. This is correct. However if someone adds a new `option go_package` for a sub-package, the import paths in `register.go` break.
**How to avoid:** Keep `go_package` unchanged. The new `FirewallAdminService` stubs will be in the same `pb` package as `AdminService`.
[VERIFIED: admin.proto line 5]

### Pitfall 4: `NoopSrvAdapter` in register.go needs updating

**What goes wrong:** `NoopSrvAdapter` in `register.go` must implement all methods of `SrvIface`. When `GetFirewall()` is added to `SrvAdapter`, `NoopSrvAdapter` must also implement it (returning nil).
**How to avoid:** Update `NoopSrvAdapter` simultaneously with the interface extension.
[VERIFIED: api/grpc/registry/register.go lines 21-27]

### Pitfall 5: generate.sh processes all .proto files

**What goes wrong:** `generate.sh` runs `protoc` on all `*.proto` files in the proto directory. All generated files in `pb/` will be regenerated. If `admin.proto` already has `AdminService` stubs, they will be regenerated alongside the new `FirewallAdminService` stubs — this is expected behavior, not an error.
**How to avoid:** Run `./generate.sh` from `api/grpc/proto/` after editing `admin.proto`. Check that `pb/admin.pb.go` and `pb/admin_grpc.pb.go` both update.
[VERIFIED: api/grpc/proto/generate.sh]

---

## Code Examples

### FirewallStats Response Construction

```go
// Source: firewalld.go Stats() return type verified
// firewalld.Stats fields: TotalQueries, TotalBlocked, TotalNXDomain, TotalDropped, TotalRedirected (all uint64)
stats := s.fw.Stats()
return &pb.FirewallStatsResponse{
    TotalQueries:    stats.TotalQueries,
    TotalBlocked:    stats.TotalBlocked,
    TotalNXDomain:   stats.TotalNXDomain,
    TotalDropped:    stats.TotalDropped,
    TotalRedirected: stats.TotalRedirected,
}, nil
```

### LoadScript with Body String

```go
// fw.LoadSource is the new method to add on *Firewall
// Delegates to: fw.starlark.Load(id, src)
func (s *FirewallService) LoadScript(ctx context.Context, req *pb.FirewallLoadScriptRequest) (*pb.FirewallLoadScriptResponse, error) {
    if req.ScriptId == "" {
        return nil, status.Error(codes.InvalidArgument, "script_id is required")
    }
    if req.Body == "" {
        return nil, status.Error(codes.InvalidArgument, "body is required")
    }
    if err := s.fw.LoadSource(req.ScriptId, req.Body); err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "compile script: %v", err)
    }
    return &pb.FirewallLoadScriptResponse{ScriptId: req.ScriptId}, nil
}
```

### InjectScore with oneof

```go
func (s *FirewallService) InjectScore(ctx context.Context, req *pb.FirewallInjectScoreRequest) (*pb.FirewallInjectScoreResponse, error) {
    ti := s.fw.ThreatIntelEngine()
    switch t := req.Target.(type) {
    case *pb.FirewallInjectScoreRequest_Domain:
        if t.Domain == "" {
            return nil, status.Error(codes.InvalidArgument, "domain is required")
        }
        ti.AddDomainScore(t.Domain, int(req.Score))
    case *pb.FirewallInjectScoreRequest_Ip:
        if t.Ip == "" {
            return nil, status.Error(codes.InvalidArgument, "ip is required")
        }
        ti.AddIPScore(t.Ip, int(req.Score))
    default:
        return nil, status.Error(codes.InvalidArgument, "target must be domain or ip")
    }
    return &pb.FirewallInjectScoreResponse{}, nil
}
```

### Proto Definition for FirewallAdminService

```proto
// Add to api/grpc/proto/admin.proto after existing AdminService block

service FirewallAdminService {
  rpc FirewallStats(FirewallStatsRequest)     returns (FirewallStatsResponse);
  rpc LoadScript(FirewallLoadScriptRequest)   returns (FirewallLoadScriptResponse);
  rpc RemoveScript(FirewallRemoveScriptRequest) returns (FirewallRemoveScriptResponse);
  rpc InjectScore(FirewallInjectScoreRequest) returns (FirewallInjectScoreResponse);
}

message FirewallStatsRequest {}

message FirewallStatsResponse {
  uint64 total_queries    = 1;
  uint64 total_blocked    = 2;
  uint64 total_nxdomain   = 3;
  uint64 total_dropped    = 4;
  uint64 total_redirected = 5;
}

message FirewallLoadScriptRequest {
  string script_id = 1;
  string body      = 2;
}

message FirewallLoadScriptResponse {
  string script_id = 1;
}

message FirewallRemoveScriptRequest {
  string script_id = 1;
}

message FirewallRemoveScriptResponse {}

message FirewallInjectScoreRequest {
  oneof target {
    string domain = 1;
    string ip     = 2;
  }
  int32 score = 3;
}

message FirewallInjectScoreResponse {}
```

[VERIFIED: field names match firewalld.Stats struct fields; ThreatIntel.AddDomainScore/AddIPScore signatures verified]

---

## State of the Art

| Old Approach | Current Approach | Notes |
|--------------|------------------|-------|
| `fw.LoadScript(path)` (file-based) | `fw.LoadSource(id, src)` (body-based) | New method needed; delegates to existing `StarlarkEngine.Load()` |
| HTTP admin as sole management interface | HTTP (fallback) + gRPC (primary) | Additive — HTTP stays |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `StarlarkEngine.Load(id, src)` is sufficient to support the gRPC body-string approach without new Starlark infrastructure | Code Examples | Low — `Load()` was verified to exist and accept `(id, src string)` in starlark.go |
| A2 | `NoopSrvAdapter` in register.go is only used by standalone gRPC binaries (comment says so) and not by any active test | Pitfalls | Low — verified in register.go comment; no active tests import registry |

**All other claims were verified against source files in this session.**

---

## Open Questions (RESOLVED)

1. **`LoadSource` naming on `*Firewall`**
   - RESOLVED: Use `LoadSource(id, src string) error` — unambiguous contrast with `LoadScript(path)`. Implemented in Plan 02-02.

2. **`FirewallRemoveScriptResponse` empty message vs `google.protobuf.Empty`**
   - RESOLVED: Use `message FirewallRemoveScriptResponse {}` (named empty message) for consistency with other response messages in the file. Implemented in Plan 02-01.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `protoc` | Proto codegen | Yes | libprotoc 33.4 | — |
| `protoc-gen-go` | Proto codegen | Yes | ~/go/bin/ | — |
| `protoc-gen-go-grpc` | gRPC stub codegen | Yes | ~/go/bin/ | — |
| `grpcurl` | Manual end-to-end testing | Unknown | — | `go test` covers functional behavior |

[VERIFIED: tool checks via bash]

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `testing` (stdlib) + `github.com/stretchr/testify` v1.11.1 |
| Config file | none — standard `go test` |
| Quick run command | `go test ./api/grpc/services/... ./internal/firewalld/...` |
| Full suite command | `go test ./internal/firewalld/... ./api/grpc/...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| GRPC-01 | FirewallStats returns correct counter values | unit | `go test ./api/grpc/services/ -run TestFirewallService_Stats` | No — Wave 0 |
| GRPC-02 | LoadScript compiles and activates a script | unit | `go test ./api/grpc/services/ -run TestFirewallService_LoadScript` | No — Wave 0 |
| GRPC-03 | RemoveScript unloads named script | unit | `go test ./api/grpc/services/ -run TestFirewallService_RemoveScript` | No — Wave 0 |
| GRPC-04 | InjectScore updates domain/IP scores | unit | `go test ./api/grpc/services/ -run TestFirewallService_InjectScore` | No — Wave 0 |
| GRPC-05 | FirewallAdminService registered when firewall enabled; skipped when nil | unit | `go test ./api/grpc/registry/ -run TestRegisterAll` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./api/grpc/services/ -run TestFirewallService`
- **Per wave merge:** `go test ./internal/firewalld/... ./api/grpc/...`
- **Phase gate:** Full suite above green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `api/grpc/services/firewall_test.go` — covers GRPC-01 through GRPC-04
- [ ] `api/grpc/registry/register_test.go` — covers GRPC-05 (conditional registration)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes | API key interceptor already in `grpc/server/server.go` — applies to all RPCs including new ones |
| V3 Session Management | No | gRPC stateless RPCs |
| V4 Access Control | Partial | API key is coarse-grained (all-or-nothing for admin gRPC) — acceptable for v1.1 |
| V5 Input Validation | Yes | `script_id` and `body` required checks; score range validation optional (ThreatIntel does no clamping at injection) |
| V6 Cryptography | No | No crypto operations |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious Starlark script via LoadScript | Tampering | `StarlarkEngine.Load()` compiles at load time — compilation errors return `codes.InvalidArgument`; runtime sandbox is Starlark's own execution model |
| Score injection to disable firewall (score=0 for all domains) | Tampering | API key protection on the gRPC server covers this |
| Large script body in LoadScript | DoS | Starlark compilation is fast; no explicit size limit needed for v1.1 (operator-only API) |

---

## Sources

### Primary (HIGH confidence)

- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/firewalld.go] — `Firewall.Stats()`, `LoadScript()`, `RemoveScript()`, `ThreatIntelEngine()`, `Stats` struct fields
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/starlark.go] — `StarlarkEngine.Load(id, src)` signature; `LoadFile(path)` reads file then calls `Load`
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/threat_intel.go] — `AddDomainScore(domain string, score int)`, `AddIPScore(ip string, score int)`
- [VERIFIED: /Users/ryan/development/dnsscienced/api/grpc/proto/admin.proto] — existing `AdminService`, `go_package` setting, import style
- [VERIFIED: /Users/ryan/development/dnsscienced/api/grpc/services/management.go] — struct/constructor/handler pattern; `SrvAdapter` interface definition
- [VERIFIED: /Users/ryan/development/dnsscienced/api/grpc/registry/register.go] — `RegisterAll`, `SrvIface`, `NoopSrvAdapter`
- [VERIFIED: /Users/ryan/development/dnsscienced/cmd/dnsscienced/main.go] — `serverSrvAdapter` pattern; gRPC server startup
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/admin.go] — HTTP admin endpoints and their semantics
- [VERIFIED: /Users/ryan/development/dnsscienced/api/grpc/server/server.go] — API key interceptor, `New(cfg, deps)` signature
- [VERIFIED: /Users/ryan/development/dnsscienced/api/grpc/proto/generate.sh] — codegen command and output location
- [VERIFIED: go.mod] — `google.golang.org/grpc v1.78.0`, `google.golang.org/protobuf v1.36.11`

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all libraries already in go.mod
- Architecture: HIGH — patterns fully specified by existing service implementations
- Pitfalls: HIGH — derived from direct code inspection of interface/adapter chain

**Research date:** 2026-04-23
**Valid until:** 2026-05-23 (stable Go module dependencies)
