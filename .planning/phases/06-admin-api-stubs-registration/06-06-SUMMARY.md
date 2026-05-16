---
phase: 06-admin-api-stubs-registration
plan: "06"
subsystem: admin-api
tags: [tsig, grpc, admin, key-management, rfc2845]
dependency_graph:
  requires: [06-05]
  provides: [TSIG-key-management-RPCs, mutable-KeyRing]
  affects: [internal/tsig, internal/admin, api/grpc/proto/pb, api/grpc/registry, api/grpc/services, cmd/dnsscienced]
tech_stack:
  added: []
  patterns:
    - "shared-map pattern: KeyRing.secrets is the same map reference assigned to dns.Server.TsigSecret; mutations via Add/Remove are visible to miekg/dns on the next request without server restart"
    - "RWMutex pattern: read methods acquire RLock, mutations acquire Lock; Algorithms() returns a copy for safe iteration"
key_files:
  created: []
  modified:
    - internal/tsig/tsig.go
    - internal/tsig/tsig_test.go
    - api/grpc/proto/admin.proto
    - api/grpc/proto/pb/admin.pb.go
    - api/grpc/proto/pb/admin_grpc.pb.go
    - internal/admin/service.go
    - api/grpc/registry/register.go
    - api/grpc/services/management.go
    - cmd/dnsscienced/main.go
decisions:
  - "Shared map reference: TsigSecretMap() returns kr.secrets directly (not a copy) so dns.Server.TsigSecret sees Add/Remove mutations without re-assignment"
  - "ListTsigKeys returns name+algorithm only; secret field intentionally omitted from TsigKeyInfo proto (T-06-20 mitigated)"
  - "GetTsigKeyRing() added to both AdminSrvAdapter and services.SrvAdapter to thread the key ring from server to admin gRPC layer without import cycles"
  - "NoopSrvAdapter.GetTsigKeyRing() returns nil; admin.Service nil-guards tsigKeyRing at each RPC handler"
metrics:
  duration: "~15 minutes"
  completed: "2026-05-16"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 9
---

# Phase 06 Plan 06: TSIG Key Management RPCs Summary

TSIG runtime key management via gRPC admin API — KeyRing made mutable with sync.RWMutex; AddTsigKey, RemoveTsigKey, ListTsigKeys RPCs wired end-to-end.

## What Was Built

### Task 1: Mutable KeyRing with Thread-Safe Add/Remove

Refactored `internal/tsig/tsig.go` to support runtime key mutation:

- Added `sync.RWMutex` to `KeyRing`; all read methods acquire `RLock`, mutations acquire write `Lock`
- Added `secrets map[string]string` as a shared internal map: this exact map reference is returned by `TsigSecretMap()` and assigned to `dns.Server.TsigSecret` at server creation — mutations via `Add`/`Remove` propagate to the DNS server on next request without restart
- `Add(KeyConfig)`: validates algorithm and base64 secret, rejects duplicates, inserts into both `kr.keys` and `kr.secrets` under write lock
- `Remove(name string) bool`: normalizes name to FQDN, deletes from both maps under write lock, returns false if not found
- `Algorithms() map[string]string`: returns a copied map of name→algorithm for safe ListTsigKeys iteration
- Added 3 new tests: `TestTSIG_KeyRing_Add`, `TestTSIG_KeyRing_Remove`, `TestTSIG_KeyRing_SharedMap` — 12 total tests pass with `-race`

### Task 2: TSIG RPCs in admin.proto + admin.Service

**Proto changes** (`api/grpc/proto/admin.proto`):
- Added `rpc AddTsigKey`, `rpc RemoveTsigKey`, `rpc ListTsigKeys` to `AdminService`
- Added messages: `AdminAddTsigKeyRequest/Response`, `AdminRemoveTsigKeyRequest/Response`, `AdminListTsigKeysResponse`, `TsigKeyInfo`
- `TsigKeyInfo` intentionally omits `secret` field (T-06-20 mitigation)
- Regenerated `admin.pb.go` and `admin_grpc.pb.go`

**Interface changes**:
- `AdminSrvAdapter` (in `internal/admin/service.go`): added `GetTsigKeyRing() *tsig.KeyRing`
- `services.SrvAdapter` (in `api/grpc/services/management.go`): same addition (this is aliased as `SrvIface` in registry)

**admin.Service**:
- Added `tsigKeyRing *tsig.KeyRing` field; `NewService` now takes `tsigKeyRing` as final param
- `AddTsigKey`: validates name+secret non-empty, calls `kr.Add()`, returns `FailedPrecondition` if ring is nil
- `RemoveTsigKey`: calls `kr.Remove()`, returns `NotFound` if key doesn't exist
- `ListTsigKeys`: returns all name+algorithm pairs; nil ring returns empty response (not an error)

**Wiring**:
- `serverSrvAdapter.GetTsigKeyRing()` in `main.go` delegates to `s.s.GetTsigKeyRing()`
- `NoopSrvAdapter.GetTsigKeyRing()` returns nil in registry
- `registry.RegisterAll` passes `srv.GetTsigKeyRing()` as final arg to `admin.NewService`

## Deviations from Plan

None — plan executed exactly as written.

## Threat Model Coverage

| Threat ID | Status |
|-----------|--------|
| T-06-20 Information Disclosure (ListTsigKeys) | Mitigated: TsigKeyInfo has no secret field |
| T-06-21 Tampering (weak algorithm) | Mitigated: ValidateAlgorithm in KeyRing.Add rejects hmac-md5/sha1 |
| T-06-22 EoP (unauthorized AddTsigKey) | Mitigated: API key interceptor on gRPC server (pre-existing) |
| T-06-23 Spoofing (RemoveTsigKey removes active key) | Accepted: operator responsibility |

## Known Stubs

None — all RPCs are fully implemented.

## Self-Check: PASSED

- internal/tsig/tsig.go: FOUND
- internal/admin/service.go: FOUND
- api/grpc/proto/admin.proto: FOUND
- Commit 746abdb (Task 1): FOUND
- Commit 17c99e4 (Task 2): FOUND
