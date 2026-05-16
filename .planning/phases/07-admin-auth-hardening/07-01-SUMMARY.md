---
phase: 07
plan: "01"
subsystem: admin-auth
tags: [config, grpc, api-keys, tls, atomic]
dependency_graph:
  requires: []
  provides: [config.APIKey, grpcserver.Config.TLSClientCAs, atomicKeySet]
  affects: [api/grpc/server, internal/config, cmd/dnsscience-grpc]
tech_stack:
  added: [sync/atomic]
  patterns: [atomic-value-hot-swap, dual-index-map]
key_files:
  created: []
  modified:
    - internal/config/config.go
    - api/grpc/server/server.go
    - cmd/dnsscience-grpc/main.go
    - api/grpc/server/server_auth_test.go
decisions:
  - "APIKey struct exported from config.go with ID+Secret yaml tags per D-04"
  - "atomicKeySet uses dual keyIndex (secretToID + idSet) for O(1) auth + audit per D-05"
  - "Lookup returns (id, ok) — never the secret; idSet is unexported (T-07-01-02 mitigated)"
  - "apiKeyUnary/StreamInterceptors updated to []config.APIKey (blocking compile fix)"
  - "cmd/dnsscience-grpc/main.go synthesizes IDs (key-N, cli-N) from legacy []string config"
metrics:
  duration: "4m"
  completed: "2026-05-16"
  tasks_completed: 2
  files_changed: 4
requirements_satisfied: [ADMIN-AUTH-01, ADMIN-AUTH-02]
---

# Phase 07 Plan 01: APIKey Struct and atomicKeySet Foundation Summary

**One-liner:** Named APIKey struct (ID+Secret) replaces plain strings in config and grpc server Config; lock-free atomicKeySet with dual secretToID+idSet indexes enables O(1) auth and audit per D-04/D-05.

## Tasks Completed

| # | Task | Commit | Result |
|---|------|--------|--------|
| 1 (RED) | Failing tests for APIKey struct, TLSClientCAs, atomicKeySet | 1d9a3e4 | FAIL (expected) |
| 1+2 (GREEN) | APIKey struct + TLS fields + atomicKeySet implementation | cfb7e32 | PASS |

## What Was Built

### internal/config/config.go
- New `APIKey` struct exported with `ID string \`yaml:"id"\`` and `Secret string \`yaml:"secret"\``
- `AdminConfig.APIKeys` changed from `[]string` to `[]APIKey`
- `AdminConfig` gains `TLSCertFile`, `TLSKeyFile`, `TLSClientCAs` yaml-tagged fields

### api/grpc/server/server.go
- `Config.TLSClientCAs string` added
- `Config.APIKeys` changed from `[]string` to `[]config.APIKey`
- New `keyIndex` struct with `secretToID map[string]string` and `idSet map[string]struct{}`
- New `atomicKeySet` type wrapping `atomic.Value` storing `keyIndex`
- Methods: `newAtomicKeySet`, `Store`, `Lookup(secret) (id, ok)`, `IDExists(id) bool`, `Len() int`
- Existing `apiKeyUnary/StreamInterceptor` signatures updated to `[]config.APIKey`

### cmd/dnsscience-grpc/main.go (Rule 3 fix)
- Imports `internal/config` and `strings`
- `eAPIKeys` changed from `[]string` to `[]config.APIKey`
- CLI `--api-keys` flag: comma-separated secrets get synthesized IDs `cli-N`
- Config file legacy `[]string` api_keys: synthesized IDs `key-N`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated apiKeyUnaryInterceptor/apiKeyStreamInterceptor signatures**
- **Found during:** Task 1 GREEN implementation
- **Issue:** Changing `Config.APIKeys []string` to `[]config.APIKey` caused compile errors in the existing interceptors which still accepted `[]string`
- **Fix:** Updated both interceptors to accept `[]config.APIKey`; each key's `.Secret` field is used to populate the lookup map
- **Files modified:** `api/grpc/server/server.go`
- **Commit:** cfb7e32

**2. [Rule 3 - Blocking] Updated cmd/dnsscience-grpc/main.go to use []config.APIKey**
- **Found during:** Task 1 GREEN — `go build ./...` found `cmd/dnsscience-grpc/main.go:64` using `[]string` for `server.Config.APIKeys`
- **Fix:** Converted `eAPIKeys` to `[]config.APIKey`; synthesized sequential IDs from legacy string-based config for backwards compatibility
- **Files modified:** `cmd/dnsscience-grpc/main.go`
- **Commit:** cfb7e32

### TDD Notes
Both tasks share a single test file (`server_auth_test.go`). Since `TestAtomicKeySet` references `newAtomicKeySet` and `TestConfig_HasTLSClientCAs` references `config.APIKey`, both tasks' tests were written together in the RED commit. Implementation (GREEN) was committed as a single commit covering Tasks 1 and 2.

## Threat Surface Scan

No new network endpoints or auth paths introduced. The `atomicKeySet.Lookup` returns only the key ID (never the secret), satisfying T-07-01-02. The `keyIndex` struct is unexported. No threats beyond the plan's threat model were detected.

## Self-Check: PASSED

- `internal/config/config.go` exists and contains `type APIKey struct`: confirmed
- `api/grpc/server/server.go` exists and contains `atomicKeySet`: confirmed
- RED commit 1d9a3e4: confirmed in git log
- GREEN commit cfb7e32: confirmed in git log
- `go build ./...` passes: confirmed
- Tests pass: `TestAtomicKeySet`, `TestAtomicKeyReload`, `TestConfig_HasTLSClientCAs` all PASS
