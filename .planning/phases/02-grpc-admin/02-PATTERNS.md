# Phase 2: gRPC Admin - Pattern Map

**Mapped:** 2026-04-23
**Files analyzed:** 7 new/modified files
**Analogs found:** 6 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `api/grpc/proto/admin.proto` | config (proto schema) | request-response | `api/grpc/proto/admin.proto` (self — extend) | exact |
| `api/grpc/proto/pb/admin.pb.go` | generated | — | `api/grpc/proto/pb/admin.pb.go` (regenerated) | exact |
| `api/grpc/proto/pb/admin_grpc.pb.go` | generated | — | `api/grpc/proto/pb/admin_grpc.pb.go` (regenerated) | exact |
| `api/grpc/services/firewall.go` | service | request-response | `api/grpc/services/management.go` | exact |
| `api/grpc/services/firewall_test.go` | test | — | `internal/firewalld/firewalld_test.go` | role-match |
| `api/grpc/registry/register.go` | config (wiring) | request-response | `api/grpc/registry/register.go` (self — extend) | exact |
| `internal/server/server.go` | service | — | `internal/server/server.go` (self — extend accessor) | exact |
| `cmd/dnsscienced/main.go` | config (wiring) | — | `cmd/dnsscienced/main.go` (self — extend adapter) | exact |
| `internal/firewalld/firewalld.go` | service | — | `internal/firewalld/firewalld.go` (self — add method) | exact |

---

## Pattern Assignments

### `api/grpc/proto/admin.proto` (extend existing file)

**Analog:** `api/grpc/proto/admin.proto` lines 1-10 (header) and lines 11-50 (service block)

**Header pattern** (lines 1-10) — keep unchanged, no new `go_package` option:
```proto
syntax = "proto3";

package dnsscience.v1;

option go_package = "github.com/dnsscience/dnsscienced/api/grpc/proto/pb";

import "google/protobuf/empty.proto";
import "google/protobuf/timestamp.proto";
```

**Service block pattern** (modeled on AdminService lines 11-50) — add as a second service block after line 348:
```proto
service FirewallAdminService {
  rpc FirewallStats(FirewallStatsRequest)       returns (FirewallStatsResponse);
  rpc LoadScript(FirewallLoadScriptRequest)     returns (FirewallLoadScriptResponse);
  rpc RemoveScript(FirewallRemoveScriptRequest) returns (FirewallRemoveScriptResponse);
  rpc InjectScore(FirewallInjectScoreRequest)   returns (FirewallInjectScoreResponse);
}
```

**Message pattern** (modeled on AdminFlushCacheResponse lines 68-71 and AdminMetricsResponse lines 190-199 for uint64 stats):
```proto
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

---

### `api/grpc/services/firewall.go` (CREATE NEW — service, request-response)

**Analog:** `api/grpc/services/management.go`

**Imports pattern** (lines 1-20 of management.go — trim to firewall needs):
```go
package services

import (
    "context"

    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
    "github.com/dnsscience/dnsscienced/internal/firewalld"
)
```

**Struct and constructor pattern** (management.go lines 42-61):
```go
// FirewallService implements pb.FirewallAdminServiceServer.
// It delegates all operations to the live *firewalld.Firewall instance.
type FirewallService struct {
    pb.UnimplementedFirewallAdminServiceServer
    fw *firewalld.Firewall
}

// NewFirewallService constructs a FirewallService.
func NewFirewallService(fw *firewalld.Firewall) *FirewallService {
    return &FirewallService{fw: fw}
}
```

**Core handler pattern** (modeled on management.go GetZone lines 235-250 for simple delegation + validation + status error):
```go
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

**Error handling pattern** (management.go lines 70-76 — required field validation, then status.Errorf for downstream errors):
```go
// Required-field validation:
if req.ScriptId == "" {
    return nil, status.Error(codes.InvalidArgument, "script_id is required")
}
// Downstream error wrapping:
if err := s.fw.LoadSource(req.ScriptId, req.Body); err != nil {
    return nil, status.Errorf(codes.InvalidArgument, "compile script: %v", err)
}
```

**oneof switch pattern** (no direct analog in management.go — use Go proto oneof dispatch):
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

---

### `api/grpc/registry/register.go` (EXTEND existing file)

**Analog:** `api/grpc/registry/register.go` (self)

**NoopSrvAdapter pattern** (lines 21-27) — add one method returning nil:
```go
// Current NoopSrvAdapter (lines 21-27):
type NoopSrvAdapter struct{}

func (NoopSrvAdapter) GetZone(_ string) *zone.Zone        { return nil }
func (NoopSrvAdapter) AddZone(_ *zone.Zone) error         { return nil }
func (NoopSrvAdapter) RemoveZone(_ string)                {}
func (NoopSrvAdapter) GetStats() services.SrvStats        { return services.SrvStats{} }

// ADD this method:
func (NoopSrvAdapter) GetFirewall() *firewalld.Firewall   { return nil }
```

**Imports extension** — add firewalld import alongside existing imports (lines 1-14):
```go
"github.com/dnsscience/dnsscienced/internal/firewalld"
```

**RegisterAll conditional registration pattern** (modeled on lines 61-68, nil-safe guard):
```go
// ADD after the existing mgmtpb.RegisterManagementServiceServer call (line 68):
if fw := srv.GetFirewall(); fw != nil {
    pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(fw))
}
```

---

### `api/grpc/services/management.go` — SrvAdapter interface (EXTEND)

**Analog:** `api/grpc/services/management.go` lines 22-29

**Current interface** (lines 22-29):
```go
type SrvAdapter interface {
    GetZone(origin string) *zone.Zone
    AddZone(z *zone.Zone) error
    RemoveZone(origin string)
    GetStats() SrvStats
}
```

**Extended interface** — add one method:
```go
type SrvAdapter interface {
    GetZone(origin string) *zone.Zone
    AddZone(z *zone.Zone) error
    RemoveZone(origin string)
    GetStats() SrvStats
    GetFirewall() *firewalld.Firewall   // ADD
}
```

Also add the firewalld import at the top of management.go:
```go
"github.com/dnsscience/dnsscienced/internal/firewalld"
```

---

### `internal/server/server.go` — GetFirewall() accessor (EXTEND)

**Analog:** `internal/server/server.go` — existing field at line 119 (`firewall *firewalld.Firewall`)

**Pattern:** Add a public accessor method after the `Shutdown()` method block (around line 310). No existing `GetFirewall` exists — model after the implied accessor pattern (the field is private; public getters follow Go idiom of returning the field value):
```go
// GetFirewall returns the live firewall instance, or nil if firewall is disabled.
func (s *Server) GetFirewall() *firewalld.Firewall {
    return s.firewall
}
```

---

### `cmd/dnsscienced/main.go` — serverSrvAdapter.GetFirewall() (EXTEND)

**Analog:** `cmd/dnsscienced/main.go` lines 28-48 — `serverSrvAdapter` method set

**Current adapter methods** (lines 32-48):
```go
func (a *serverSrvAdapter) GetZone(origin string) *zone.Zone { return a.s.GetZone(origin) }
func (a *serverSrvAdapter) AddZone(z *zone.Zone) error       { return a.s.AddZone(z) }
func (a *serverSrvAdapter) RemoveZone(origin string)         { a.s.RemoveZone(origin) }
func (a *serverSrvAdapter) GetStats() services.SrvStats { ... }
```

**New method to add** (same one-liner delegation pattern):
```go
func (a *serverSrvAdapter) GetFirewall() *firewalld.Firewall { return a.s.GetFirewall() }
```

Also add the firewalld import in main.go imports block:
```go
"github.com/dnsscience/dnsscienced/internal/firewalld"
```

---

### `internal/firewalld/firewalld.go` — LoadSource() method (EXTEND)

**Analog:** `internal/firewalld/firewalld.go` lines 269-272 (LoadScript):
```go
// LoadScript hot-reloads a Starlark policy script by path.
func (fw *Firewall) LoadScript(path string) error {
    return fw.starlark.LoadFile(path)
}
```

**New method** — parallel to LoadScript but delegates to starlark.Load(id, src) instead of LoadFile:
```go
// LoadSource compiles and registers a Starlark policy script from src string.
// id is the caller-supplied unique script identifier.
func (fw *Firewall) LoadSource(id, src string) error {
    return fw.starlark.Load(id, src)
}
```

---

### `api/grpc/services/firewall_test.go` (CREATE NEW — test)

**Analog:** `internal/firewalld/firewalld_test.go`

**Package and imports pattern** (lines 1-10):
```go
package services

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
    "github.com/dnsscience/dnsscienced/internal/firewalld"
)
```

**Table-driven test pattern** (firewalld_test.go lines 26-57):
```go
func TestFirewallService_LoadScript(t *testing.T) {
    tests := []struct {
        name    string
        req     *pb.FirewallLoadScriptRequest
        wantErr bool
        errCode codes.Code
    }{
        {
            name:    "missing script_id",
            req:     &pb.FirewallLoadScriptRequest{Body: "def on_query(q, score): pass"},
            wantErr: true,
            errCode: codes.InvalidArgument,
        },
        {
            name:    "missing body",
            req:     &pb.FirewallLoadScriptRequest{ScriptId: "test"},
            wantErr: true,
            errCode: codes.InvalidArgument,
        },
        {
            name: "valid script",
            req:  &pb.FirewallLoadScriptRequest{ScriptId: "test", Body: "def on_query(q, score): pass"},
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            fw := newTestFirewall(t)
            svc := NewFirewallService(fw)
            _, err := svc.LoadScript(context.Background(), tt.req)
            if tt.wantErr {
                require.Error(t, err)
                assert.Equal(t, tt.errCode, status.Code(err))
            } else {
                require.NoError(t, err)
            }
        })
    }
}
```

**Test helper** — construct a minimal firewall for service tests:
```go
func newTestFirewall(t *testing.T) *firewalld.Firewall {
    t.Helper()
    fw, err := firewalld.New(firewalld.Config{Enabled: true})
    require.NoError(t, err)
    return fw
}
```

---

## Shared Patterns

### gRPC Status Error Construction
**Source:** `api/grpc/services/management.go` lines 70-76 and lines 177-178
**Apply to:** All handlers in `api/grpc/services/firewall.go`
```go
// Required field missing:
return nil, status.Error(codes.InvalidArgument, "field_name is required")
// Downstream error:
return nil, status.Errorf(codes.InvalidArgument, "operation: %v", err)
// Not found:
return nil, status.Errorf(codes.NotFound, "resource %s not found", id)
// Internal error:
return nil, status.Errorf(codes.Internal, "internal operation: %v", err)
```

### Unimplemented Server Embedding
**Source:** `api/grpc/services/management.go` line 46
**Apply to:** `FirewallService` struct
```go
// ALL service structs embed the generated Unimplemented*Server for forward compatibility:
pb.UnimplementedFirewallAdminServiceServer
```

### Nil-Safe Conditional Registration
**Source:** `api/grpc/registry/register.go` lines 37-68 (general registration pattern)
**Apply to:** firewall registration block in `RegisterAll`
```go
// Optional services guarded by nil check — firewall may be disabled in config:
if fw := srv.GetFirewall(); fw != nil {
    pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(fw))
}
```

### Adapter Interface Extension
**Source:** `cmd/dnsscienced/main.go` lines 28-48 (`serverSrvAdapter`)
**Apply to:** Any new method added to `services.SrvAdapter`
- Interface method added to `services.SrvAdapter` in `management.go`
- `NoopSrvAdapter` in `register.go` gets a nil-returning stub
- `serverSrvAdapter` in `main.go` gets a one-liner delegation to `a.s.Method()`
- `internal/server.Server` gets the underlying method that `serverSrvAdapter` delegates to

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `api/grpc/proto/pb/admin.pb.go` | generated | — | Output of `protoc`; not hand-written. Run `./generate.sh` from `api/grpc/proto/` after editing `admin.proto`. |
| `api/grpc/proto/pb/admin_grpc.pb.go` | generated | — | Same as above. |

---

## Metadata

**Analog search scope:** `api/grpc/`, `internal/firewalld/`, `internal/server/`, `cmd/dnsscienced/`
**Files scanned:** 9 source files read directly
**Pattern extraction date:** 2026-04-23
