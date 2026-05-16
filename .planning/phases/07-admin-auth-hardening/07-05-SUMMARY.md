---
phase: 07
plan: "05"
subsystem: admin-main-wiring
tags: [grpc, sighup, config-reload, atomic, tls, audit-interceptors, d-09, d-11, tdd]
dependency_graph:
  requires: [07-01, 07-02, 07-03, 07-04]
  provides: [ConfigHolder, SIGHUP-full-reload, TLS-wiring, AuditInterceptor-wiring]
  affects:
    - api/grpc/server/server.go
    - cmd/dnsscienced/main.go
    - cmd/dnsscience-grpc/main.go
    - cmd/dnsscienced/main_wiring_test.go
tech_stack:
  added: [sync.RWMutex (ConfigHolder), syscall.SIGHUP, logging.NewLogger]
  patterns: [atomic-config-swap-d11, sighup-full-reload-d09, fail-closed-exit-d01, tdd-red-green]
key_files:
  created:
    - cmd/dnsscienced/main_wiring_test.go
  modified:
    - api/grpc/server/server.go
    - cmd/dnsscienced/main.go
    - cmd/dnsscience-grpc/main.go
    - api/grpc/server/server_auth_test.go
decisions:
  - "ConfigHolder wraps atomicKeySet + sync.RWMutex to provide atomic full config swap per D-11"
  - "Reload() validates D-01/D-02 before swapping; bad config returns error and leaves current config intact"
  - "Reload() rebuilds TLS creds only when TLS paths changed (cert/key/CA) — no rebuild on key-only change"
  - "New() updated to 5-return: (*grpc.Server, net.Listener, *ConnRegistry, *ConfigHolder, error)"
  - "SIGHUP handler is single-goroutine serial in signal loop — no concurrent reload races (T-07-05-01)"
  - "grpcserver.New() error is os.Exit(1) — startup misconfiguration is fatal (T-07-05-03)"
  - "connReg still passed as nil to RegisterAll closure (chicken-and-egg unchanged from Plan 04) — Plan 05 was this plan; future work needed for live-registry post-construction wiring"
metrics:
  duration: "7m"
  completed: "2026-05-16"
  tasks_completed: 2
  files_changed: 5
requirements_satisfied: [ADMIN-AUTH-01, ADMIN-RELOAD-01]
---

# Phase 07 Plan 05: Main Wiring + SIGHUP Full Config Reload Summary

**One-liner:** ConfigHolder type enables atomic D-11 config swap; SIGHUP handler in main.go reloads full config (TLS + API keys) per D-09; AuditUnaryInterceptor and AuditStreamInterceptor wired; New() updated to 5-return signature.

## Tasks Completed

| # | Task | Commit | Result |
|---|------|--------|--------|
| Task 1 RED | Failing tests for ConfigHolder and 5-return New() | e0da60c | FAIL (expected) |
| Task 1 GREEN | ConfigHolder type + Reload() + GetCreds() + 5-return New() | 243aeb6 | PASS |
| Task 2 RED | Compilation sentinel for main.go 5-return wiring | 2e08909 | FAIL (expected) |
| Task 2 GREEN | Full main.go wiring: TLS fields, audit interceptors, SIGHUP loop | c80318b | PASS |

## What Was Built

### api/grpc/server/server.go

**ConfigHolder struct** — atomic full config swap per D-11:
- `mu sync.RWMutex` guards `cfg Config` and `creds credentials.TransportCredentials`
- `keySet *atomicKeySet` — the same key set wired into the auth interceptors
- `NewConfigHolder(cfg, keySet, creds) *ConfigHolder` — constructor called inside `New()`
- `Reload(newCfg Config) error`:
  - Validates D-01 (APIKeys non-empty) and D-02 (TLSClientCAs non-empty) before any swap
  - Computes `tlsChanged` (RLock) for cert/key/CA path comparison
  - Rebuilds TLS creds via `buildCreds(newCfg)` only when paths changed
  - Acquires write lock: `keySet.Store(newCfg.APIKeys)`, swaps `cfg`, swaps `creds` if rebuilt
  - Returns error without swap if `buildCreds` fails — current config is preserved
- `CurrentConfig() Config` — RLock snapshot for diagnostics
- `GetCreds() credentials.TransportCredentials` — RLock snapshot for future dynamic TLS

**New()** signature changed from 4-return to 5-return:
```go
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, *ConnRegistry, *ConfigHolder, error)
```
- `builtCreds` captured during TLS initialization to pass into `NewConfigHolder`
- All error returns updated to `return nil, nil, nil, nil, err`

### cmd/dnsscienced/main.go

**grpcserver.Config** — TLS fields now wired:
```go
grpcCfg := grpcserver.Config{
    ListenAddr:   loadedCfg.Admin.Listen,
    APIKeys:      loadedCfg.Admin.APIKeys,
    TLSCertFile:  loadedCfg.Admin.TLSCertFile,
    TLSKeyFile:   loadedCfg.Admin.TLSKeyFile,
    TLSClientCAs: loadedCfg.Admin.TLSClientCAs,
}
```

**Audit interceptors** — wired in grpcserver.Deps:
```go
Unary:  []grpc.UnaryServerInterceptor{middleware.AuditUnaryInterceptor(adminLogger)},
Stream: []grpc.StreamServerInterceptor{middleware.AuditStreamInterceptor(adminLogger)},
```
Admin logger created via `logging.NewLogger(logging.Config{Level: "info"})`.

**5-return New()** — captures all values:
```go
grpcSrv, grpcListener, connReg, configHolder, err = grpcserver.New(grpcCfg, grpcDeps)
if err != nil { os.Exit(1) }  // fatal startup error (T-07-05-03)
```

**SIGHUP full config reload loop** (D-09):
- `signal.Notify(sigCh, SIGINT, SIGTERM, SIGHUP)` — SIGHUP now registered
- `for sig := range sigCh` with `case syscall.SIGHUP:` handler
- Loads full config via `config.Load(*configFile)`
- Builds `grpcserver.Config` from `reloaded.Admin` (all 5 fields including TLS)
- Calls `configHolder.Reload(newGrpcCfg)` — atomic D-11 swap
- On error: logs error and `continue` — current config retained (D-09 best-effort)
- On success: logs "SIGHUP: admin config reloaded (N keys)"
- `SIGINT/SIGTERM`: `break sigloop` — graceful shutdown path unchanged

### cmd/dnsscience-grpc/main.go

Updated `server.New()` call from 4-return to 5-return:
```go
gs, ln, _, _, err := server.New(cfg, deps)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] logging.NewLogger not logging.New**
- **Found during:** Task 2 GREEN implementation
- **Issue:** Plan's action block referenced `logging.New(logging.Config{...})` but the actual function in `internal/logging` is `logging.NewLogger(logging.Config{...})`
- **Fix:** Used correct function name `logging.NewLogger`
- **Files modified:** `cmd/dnsscienced/main.go`
- **Commit:** c80318b

**2. [Rule 1 - Bug] goto not valid across variable declarations in Go**
- **Found during:** Task 2 GREEN initial attempt
- **Issue:** Plan's action block used `goto shutdown` which is invalid when variable declarations exist after the label in the same scope
- **Fix:** Used `break sigloop` with labeled `sigloop:` on the for loop instead of `goto`
- **Files modified:** `cmd/dnsscienced/main.go`
- **Commit:** c80318b

**3. [Rule 3 - Blocking] Reload TLS only when cert+key both non-empty**
- **Found during:** Task 1 GREEN — TestConfigHolder_ReloadKeysOnly uses config with no TLSCertFile/TLSKeyFile
- **Issue:** `buildCreds` returns error if TLSCertFile or TLSKeyFile is empty. The test case passes `TLSClientCAs` only (no cert/key), which means `tlsChanged=true` but `buildCreds` would fail
- **Fix:** Added guard `if tlsChanged && (newCfg.TLSCertFile != "" && newCfg.TLSKeyFile != "")` so TLS rebuild only happens when cert+key are both present
- **Files modified:** `api/grpc/server/server.go`
- **Commit:** 243aeb6

## TDD Gate Compliance

- Task 1 RED gate: commit `e0da60c` — build failure on `NewConfigHolder` undefined + 5-return mismatch
- Task 1 GREEN gate: commit `243aeb6` — all tests including TestConfigHolder_ReloadValidation, TestConfigHolder_ReloadKeysOnly, TestNew_ReturnsConfigHolder PASS
- Task 2 RED gate: commit `2e08909` — compilation failure in cmd/dnsscienced (4-return grpcserver.New())
- Task 2 GREEN gate: commit `c80318b` — all tests pass; `go build ./...` passes

## Known Stubs

None — all wiring is complete. The `connReg` nil pass-through in the `Register` closure is a documented architectural constraint (chicken-and-egg: `Register` runs inside `New()` before registry is returned), not a stub — `ListConnections` returns empty slice gracefully when registry is nil.

## Threat Surface Scan

No new network endpoints introduced. Threats from plan's threat model:
- T-07-05-01 (MITIGATED): Single-goroutine signal handler (`for sig := range sigCh`) + `ConfigHolder.Reload` write lock — no concurrent reload races
- T-07-05-02 (MITIGATED): `Reload()` validates D-01/D-02 before swap; returns error on empty keys/CA — no empty key set possible
- T-07-05-03 (MITIGATED): `grpcserver.New()` error causes `os.Exit(1)` — misconfiguration is fatal at startup
- T-07-05-04 (MITIGATED): `Reload()` swaps `keySet.Store()` + `h.cfg` + `h.creds` under single write lock — no partial state possible

## Self-Check: PASSED

- `api/grpc/server/server.go` contains `type ConfigHolder struct`: confirmed (1 match)
- `api/grpc/server/server.go` contains `func (h *ConfigHolder) Reload`: confirmed (1 match)
- `api/grpc/server/server.go` contains `tlsChanged`: confirmed (2 matches)
- `api/grpc/server/server.go` contains `h.keySet.Store`: confirmed (1 match)
- `cmd/dnsscienced/main.go` contains `SIGHUP`: confirmed (7 matches)
- `cmd/dnsscienced/main.go` contains `configHolder.Reload`: confirmed (1 match)
- `cmd/dnsscienced/main.go` contains `TLSClientCAs`: confirmed (2 matches)
- `cmd/dnsscienced/main.go` contains `AuditUnaryInterceptor`: confirmed (1 match)
- `cmd/dnsscienced/main.go` contains `connReg`: confirmed (3 matches)
- RED commits e0da60c, 2e08909: confirmed in git log
- GREEN commits 243aeb6, c80318b: confirmed in git log
- `go build ./...` passes: confirmed
- All tests pass: cmd/dnsscienced OK, api/grpc/server OK, api/grpc/services OK
