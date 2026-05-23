---
phase: 14-v1.3-gap-closure
plan: "01"
subsystem: resolver/config
tags: [config-fix, resolver, yaml, test-fix, requirements]
dependency_graph:
  requires: []
  provides: [resolver-feature-flags-enabled, yaml-config-correct, TestGetTTL-passing]
  affects: [internal/server/server.go, internal/resolver/recursive_test.go, config.example.yaml, config.production.yaml, .planning/REQUIREMENTS.md]
tech_stack:
  added: []
  patterns: [resolver.DefaultConfig()-composition, server-level-override-pattern]
key_files:
  created: []
  modified:
    - internal/server/server.go
    - config.example.yaml
    - config.production.yaml
    - internal/resolver/recursive_test.go
    - .planning/REQUIREMENTS.md
decisions:
  - "Use two-step pattern: rcfg := resolver.DefaultConfig() then override 5 server-level fields before returning Config literal"
  - "YAML key is stale_max_ttl (not stale_ttl) — matches struct tag at resolver.Config:86; stale_ttl would be silently ignored by yaml.v3"
metrics:
  duration: "~8 minutes"
  completed: "2026-05-23T17:34:51Z"
  tasks: 3
  files_changed: 5
---

# Phase 14 Plan 01: v1.3 Config Fixes and Test Fix Summary

Three v1.3 audit blockers resolved: resolver feature flags (QNAME minimization, Aggressive NSEC, Serve Stale) are now enabled in all config-file deployments; TestGetTTL passes with RFC 2308-compliant expected value 300; REQUIREMENTS.md traceability reflects actual Phase 10/11 implementation status.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Fix server.DefaultConfig() and YAML config files | 7597f54 | server.go, config.example.yaml, config.production.yaml |
| 2 | Fix TestGetTTL expected value | dfd9ae2 | internal/resolver/recursive_test.go |
| 3 | Update REQUIREMENTS.md checkboxes and traceability | 0addc52 | .planning/REQUIREMENTS.md |

## Changes Made

### Task 1: server.DefaultConfig() and YAML config files

**server.go (D-01):** Replaced inline `resolver.Config{...}` struct literal in `DefaultConfig()` with a two-step pattern:
```go
rcfg := resolver.DefaultConfig()
rcfg.CacheConfig = cache.Config{ShardCount: 256, MaxEntries: 100000}
rcfg.Workers = 1000
rcfg.QueryTimeout = 5 * time.Second
rcfg.MaxIterations = 20
// then: RecursiveConfig: rcfg
```
This preserves 5 server-level overrides while inheriting `QNAMEMinimization:true`, `AggressiveNSEC:true`, `ServeStale:true`, `StaleTTL:24h` from `resolver.DefaultConfig()`.

**config.example.yaml / config.production.yaml (D-02):** Replaced `enable_qname_min: true` (wrong key, silently ignored by yaml.v3) with four correct keys matching struct tags: `qname_minimization`, `aggressive_nsec`, `serve_stale`, `stale_max_ttl`.

### Task 2: TestGetTTL fix (D-04)

Changed `expected: 3600` to `expected: 300` in the "no answers - default" test case. Phase 11 WR-01 changed `getTTL()` to return 300 for RFC 2308 section 5 compliance but the test expectation was not updated.

### Task 3: REQUIREMENTS.md traceability (D-08)

- RRTYPE-01/02: `[ ]` → `[x]`, Phase 14 Pending → Phase 10 Complete (already implemented via miekg/dns native support in Phase 10)
- RESOLVE-01/02/03: `[ ]` → `[x]`, Phase 14 Pending → Phase 11 Complete (implemented Phase 11; config wiring gap resolved by Task 1)
- Coverage: 9 satisfied → 18 satisfied; Pending: 5 → 0

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are config/doc fixes and a test correction.

## Known Stubs

None — no stubs introduced by this plan.

## Verification Results

- `go build ./...` passes
- `go test ./internal/resolver/... -run TestGetTTL -count=1` passes
- `go test ./internal/resolver/... -run TestQNAMEMin -count=1` passes
- `grep 'resolver.DefaultConfig()' internal/server/server.go` matches (1 hit)
- `grep 'enable_qname_min' config.example.yaml config.production.yaml` returns 0 matches
- `grep 'qname_minimization: true' config.example.yaml config.production.yaml` returns 2 matches
- `grep '\[ \]' .planning/REQUIREMENTS.md` returns 0 matches (all v1.3 boxes checked)

## Self-Check: PASSED

- internal/server/server.go: FOUND
- config.example.yaml: FOUND
- config.production.yaml: FOUND
- internal/resolver/recursive_test.go: FOUND
- .planning/REQUIREMENTS.md: FOUND
- commit 7597f54: FOUND
- commit dfd9ae2: FOUND
- commit 0addc52: FOUND
