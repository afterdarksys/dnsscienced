---
phase: 05-redirect-load-balancing
plan: "02"
subsystem: firewalld
tags: [starlark, redirect, upstream-pool, round-robin, tdd, redir-03, redir-04]
dependency_graph:
  requires: [05-01]
  provides: [StarlarkEngine.pool, redirect-builtin-pool, compileRule-relaxed]
  affects:
    - internal/firewalld/starlark.go
    - internal/firewalld/policy.go
    - internal/firewalld/firewalld.go
    - internal/firewalld/firewalld_test.go
tech_stack:
  added: []
  patterns: [kwarg-scan-before-UnpackArgs for deprecated-arg detection, TDD RED/GREEN cycle]
key_files:
  created: []
  modified:
    - internal/firewalld/starlark.go
    - internal/firewalld/policy.go
    - internal/firewalld/firewalld.go
    - internal/firewalld/firewalld_test.go
decisions:
  - "D-02: redirect builtin scans kwargs for 'server' before UnpackArgs to produce hard error at eval time"
  - "D-04: se.pool.Next() called inside redirect builtin closure; pool closed over via se *StarlarkEngine receiver"
  - "D-07: compileRule redirect case removes empty-redirect_server guard; pool provides target at runtime"
  - "D-10/A1: starlark.pool = pool wired in New() after fw struct literal"
  - "Deviation: TestUpstreamPool_RoundRobin and TestUpstreamPool_SingleUpstream already existed in forwarder_test.go (Plan 01); not duplicated — would cause redeclared symbol build failure"
metrics:
  duration: "247s"
  completed: "2026-04-23"
  tasks_completed: 2
  files_changed: 4
---

# Phase 5 Plan 02: Starlark Redirect Pool Wiring + Integration Tests Summary

**One-liner:** Starlark redirect() builtin updated to call pool.Next() with hard error on deprecated server= kwarg; compileRule relaxed to allow pool-driven static redirect rules; 7 new integration tests verify REDIR-03 and REDIR-04 end-to-end.

## What Was Built

### StarlarkEngine.pool field (internal/firewalld/starlark.go)

Added `pool *UpstreamPool` field to `StarlarkEngine` struct. The pool is set post-construction via `starlark.pool = pool` in `firewalld.go New()` after the fw struct literal.

### Updated redirect builtin (internal/firewalld/starlark.go)

Replaced the old `redirect(server=..., reason?=...)` builtin with a new implementation:

1. **Deprecated-arg detection:** Iterates `kwargs` before `UnpackArgs` — if any key is `"server"`, returns a hard error: `"firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams"` (T-05-06 mitigation, D-02).
2. **Pool selection:** Calls `se.pool.Next()` to get the upstream target. If the pool is empty, returns `fmt.Errorf("firewall.redirect: %w", err)` — `runOne` logs and returns VerdictAllow (T-05-08 mitigation).
3. **reason? kwarg:** Still accepted; defaults to "starlark policy" (D-03).
4. Sets `Decision{Verdict: VerdictRedirect, Server: poolServer, Reason: r}`.

### compileRule relaxation (internal/firewalld/policy.go)

Removed the `if r.RedirectServer == ""` guard from the redirect case. Empty `redirect_server` is now valid — the global pool provides the target at runtime via `fw.pool.Next()` in `Check()` (already wired in Plan 01, D-07).

### firewalld.go pool wiring (internal/firewalld/firewalld.go)

Added `starlark.pool = pool` after the `fw` struct literal in `New()`. This was deferred from Plan 01 because `StarlarkEngine` did not yet have the `pool` field.

### Integration tests (internal/firewalld/firewalld_test.go)

7 new test functions:

| Function | Covers |
|----------|--------|
| `TestRedirect_PoolBehavior_RED` | TDD RED gate (now GREEN) — redirect() no-args uses pool |
| `TestUpstreamPool_Empty` | assert-style empty pool error (RoundRobin/Single exist in forwarder_test.go) |
| `TestStarlarkRedirect_UsesPool` | REDIR-03: redirect() uses pool, reason? preserved |
| `TestStarlarkRedirect_ServerArgRejected` | REDIR-03: server= kwarg causes error, 9.9.9.9 never used |
| `TestStaticRedirectRule_UsesPool` | REDIR-04: static rule with no redirect_server uses pool |
| `TestStaticRedirectRule_PerRuleOverride` | REDIR-04: redirect_server set bypasses pool |
| `TestNew_EmptyPoolWithPoolRedirectRule` | New() fail-fast when pool empty + no redirect_server |

## TDD Gate Compliance

| Gate | Commit | Description |
|------|--------|-------------|
| RED  | 8acd016 | `test(05-02)`: TestRedirect_PoolBehavior_RED — fails with old server= required builtin |
| GREEN | 9116c4a | `feat(05-02)`: implementation — pool field, updated redirect builtin, compileRule relaxed, starlark.pool wired |

## Deviations from Plan

### Auto-fixed: Duplicate test function names

**Rule 1 - Bug:** Plan's Task 2 called for `TestUpstreamPool_RoundRobin` and `TestUpstreamPool_SingleUpstream` in `firewalld_test.go`. These function names already existed in `forwarder_test.go` (Plan 01 artifact). Adding duplicates would cause a `redeclared in this block` build failure.

- **Fix:** Omitted the two duplicates from `firewalld_test.go`; they are already present (and passing) in `forwarder_test.go`. The plan's acceptance criteria (`TestUpstreamPool_RoundRobin` exists in the package) is satisfied by `forwarder_test.go`.
- **Files modified:** `internal/firewalld/firewalld_test.go` (omission only)

### Auto-fixed: RED test missing ThreatIntel.BlockThreshold

**Rule 1 - Bug:** The initial RED test config omitted `ThreatIntel: ThreatIntelConfig{BlockThreshold: 100}`. With BlockThreshold=0, threat-intel blocked all queries (score 0 >= threshold 0) before the Starlark stage ran, making the redirect verdict unreachable. Added BlockThreshold: 100 to let queries flow to stage 4 (Starlark). Applied same fix to all Task 2 integration tests.

## Verification Results

```
go build ./internal/firewalld/...                                    exit 0
go test ./internal/firewalld/... -count=1 -race                      ok (43 tests pass)
grep pool.*UpstreamPool internal/firewalld/starlark.go               starlark.go:37
grep "server arg removed" internal/firewalld/starlark.go             starlark.go:262
grep "se.pool.Next()" internal/firewalld/starlark.go                 starlark.go:271
grep "redirect action requires redirect_server" policy.go            (no output — guard removed)
grep "starlark.pool = pool" internal/firewalld/firewalld.go          firewalld.go:166
```

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced. All changes are within `internal/firewalld`. Threat model mitigations T-05-06, T-05-07, T-05-08, T-05-09 implemented as designed.

## Self-Check: PASSED

- internal/firewalld/starlark.go — FOUND, contains `pool *UpstreamPool`, `server arg removed`, `se.pool.Next()`
- internal/firewalld/policy.go — FOUND, redirect guard removed, `cr.verdict = VerdictRedirect` present
- internal/firewalld/firewalld.go — FOUND, `starlark.pool = pool` at line 166
- internal/firewalld/firewalld_test.go — FOUND, all 7 new test functions present
- Commits 8acd016, 9116c4a, c02c646 — all present in git log
