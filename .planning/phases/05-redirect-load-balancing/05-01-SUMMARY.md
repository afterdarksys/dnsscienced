---
phase: 05-redirect-load-balancing
plan: "01"
subsystem: firewalld
tags: [upstream-pool, round-robin, redirect, load-balancing, config]
dependency_graph:
  requires: []
  provides: [UpstreamPool, RedirectConfig, pool-field-on-Firewall]
  affects: [internal/firewalld/forwarder.go, internal/firewalld/config.go, internal/firewalld/firewalld.go]
tech_stack:
  added: [sync/atomic.Uint64 for lock-free round-robin]
  patterns: [atomic round-robin counter, fail-fast validation in New(), SERVFAIL on pool empty]
key_files:
  created: [internal/firewalld/forwarder_test.go]
  modified:
    - internal/firewalld/forwarder.go
    - internal/firewalld/config.go
    - internal/firewalld/firewalld.go
decisions:
  - "D-13: empty pool returns error from Next(); Check() synthesizes SERVFAIL inline and logs at error level — never forwards to empty string"
  - "starlark.pool wiring deferred to Plan 02 (StarlarkEngine does not yet have pool field)"
  - "TDD used for Task 1: RED commit a2b86a8, GREEN commit 4a5dc2a"
metrics:
  duration: "101s"
  completed: "2026-04-23"
  tasks_completed: 2
  files_changed: 4
---

# Phase 5 Plan 01: UpstreamPool + RedirectConfig — Wave 1 Foundation Summary

**One-liner:** Atomic round-robin UpstreamPool with SERVFAIL-on-empty guard wired into Firewall.New() and Firewall.Check() via RedirectConfig.

## What Was Built

### UpstreamPool (internal/firewalld/forwarder.go)

`UpstreamPool` struct with `atomic.Uint64` counter for lock-free round-robin selection across configured upstream DNS targets. `newUpstreamPool()` constructor accepts nil/empty slices (valid — `Next()` returns an error). `Next()` uses `(counter.Add(1) - 1) % len(upstreams)` for zero-indexed round-robin.

### RedirectConfig (internal/firewalld/config.go)

`RedirectConfig` struct with `Upstreams []string` (yaml:"upstreams"). Added `Redirect RedirectConfig` field to `Config` struct (yaml:"redirect"). No non-zero default — empty slice is valid and signals "pool not configured."

### Firewall wiring (internal/firewalld/firewalld.go)

Three changes:
1. `pool *UpstreamPool` field added to `Firewall` struct (after `forwarder`)
2. `New()` initializes pool from `cfg.Redirect.Upstreams` and validates: any redirect rule with no `redirect_server` and an empty pool triggers a `fmt.Errorf` fail-fast at startup
3. `Check()` static rule block: when `policy.Evaluate()` returns `VerdictRedirect` with empty `Server`, calls `fw.pool.Next()`; on error synthesizes SERVFAIL inline with error-level log (T-05-03 mitigation)

## TDD Gate Compliance

| Gate | Commit | Description |
|------|--------|-------------|
| RED  | a2b86a8 | `test(05-01)`: 5 failing tests for UpstreamPool and RedirectConfig |
| GREEN | 4a5dc2a | `feat(05-01)`: implementation making all tests pass |

## Deviations from Plan

### Deferred: starlark.pool assignment

The plan notes that `starlark.pool = pool` should be deferred to Plan 02 because `StarlarkEngine` does not yet have a `pool` field. This was applied as written — the assignment is omitted here and will be added in Plan 02 when `StarlarkEngine.pool` is introduced.

No other deviations.

## Verification Results

```
go build ./internal/firewalld/...       exit 0
go test ./internal/firewalld/... -short  ok (31+ tests pass)
grep type UpstreamPool struct             forwarder.go:63
grep type RedirectConfig struct           config.go:135
grep pool.*UpstreamPool                  firewalld.go:92
grep pool.Next()                         firewalld.go:200
```

## Threat Surface Scan

All changes are within the existing `internal/firewalld` package. No new network endpoints, auth paths, or file access patterns introduced. Threat model T-05-03 (empty pool DoS) is mitigated by the SERVFAIL path in `Check()`.

## Self-Check: PASSED

- internal/firewalld/forwarder.go — FOUND, contains UpstreamPool struct
- internal/firewalld/config.go — FOUND, contains RedirectConfig struct and Redirect field
- internal/firewalld/firewalld.go — FOUND, contains pool field, newUpstreamPool call, fw.pool.Next() call
- internal/firewalld/forwarder_test.go — FOUND, 5 tests
- Commits a2b86a8, 4a5dc2a, 59733ac — all present in git log
