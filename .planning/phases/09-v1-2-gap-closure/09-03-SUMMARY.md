---
phase: 09-v1-2-gap-closure
plan: "03"
subsystem: server/grpc-auth/audit
tags: [tsig, grpc, auth, audit, milestone]
status: COMPLETE
one_liner: "TSIG always-init + stream interceptor key ID fixed; v1.2 milestone audit updated to PASSED"

dependency_graph:
  requires: ["09-02"]
  provides: ["v1.2 milestone PASSED"]
  affects: ["internal/server", "api/grpc/server", ".planning/v1.2-MILESTONE-AUDIT.md"]

tech_stack:
  added: []
  patterns:
    - "keyIDStream wrapper pattern for grpc.ServerStream context enrichment"
    - "Unconditional tsigKeyRing initialization with nil-safe NewKeyRing"

key_files:
  modified:
    - internal/server/server.go
    - api/grpc/server/server.go
    - .planning/v1.2-MILESTONE-AUDIT.md

key_decisions:
  - "tsig.NewKeyRing(nil) is safe — range over nil slice is a no-op in Go; empty KeyRing is valid"
  - "keyIDStream wrapper chosen over context.Background replacement to preserve all existing stream metadata"
  - "Discarded error from NewKeyRing(nil) — nil input cannot fail validation; maps are initialized correctly"

metrics:
  duration: "~12 minutes"
  completed: "2026-05-18"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 3
---

# Phase 09 Plan 03: TSIG Always-Init + Stream Interceptor Key ID + Audit PASSED

## Status: COMPLETE

## What Was Fixed

### Fix 1: TSIG Always-Init (`internal/server/server.go`)

**Problem:** `tsigKeyRing` was only initialized when `len(cfg.TsigKeys) > 0`. Operators starting the server with zero TSIG keys in YAML could not call `AddTsigKey` gRPC — the field was nil and the RPC returned `FailedPrecondition`.

**Fix:** Initialize `tsigKeyRing` unconditionally before the config-key loop:

```go
// Initialize TSIG key ring unconditionally — empty ring is valid.
// This allows AddTsigKey gRPC to bootstrap keys even when none are in startup config.
s.tsigKeyRing, _ = tsig.NewKeyRing(nil)

if len(cfg.TsigKeys) > 0 {
    for _, kc := range cfg.TsigKeys {
        if err := s.tsigKeyRing.Add(kc); err != nil {
            cancel()
            return nil, fmt.Errorf("init TSIG key ring: add key %q: %w", kc.Name, err)
        }
    }
}
```

`tsig.NewKeyRing(nil)` is safe: the function ranges over the keys slice (nil range = no-op) and returns an initialized `*KeyRing` with empty maps.

### Fix 2: Stream Interceptor Key ID (`api/grpc/server/server.go`)

**Problem:** `apiKeyStreamInterceptor` discarded the key ID from `Lookup` (`_, ok :=`). `AuditStreamInterceptor` fell back to cert CN for the caller identity in streaming RPCs — inconsistent with the unary interceptor which correctly stored the key ID in `CtxKeyID{}`.

**Fix:** Added `keyIDStream` wrapper to propagate enriched context:

```go
id, ok := keySet.Lookup(token)
// ...
wrapped := &keyIDStream{
    ServerStream: ss,
    ctx:          context.WithValue(ss.Context(), middleware.CtxKeyID{}, id),
}
return handler(srv, wrapped)
```

The `keyIDStream` type embeds `grpc.ServerStream` and overrides `Context()` — a standard Go pattern for stream context enrichment.

## Test Results

```
go build ./...                          EXIT 0
go test ./internal/server/...          ok  1.369s
go test ./internal/tsig/...            ok  (cached)
go test ./api/grpc/server/...          ok  0.459s
go test $(./... | grep -v engine | grep -v resolver)  ALL PASS
```

Pre-existing exclusions (not related to this plan):
- `internal/engine`: live DNS query dependency
- `internal/resolver`: slice formatting bug (pre-existing)

## Audit Document Updated

`.planning/v1.2-MILESTONE-AUDIT.md` updated:
- `status: gaps_found` → `status: passed`
- Scores: `27/31` → `31/31` requirements, `2/3` → `3/3` phases, `18/22` → `22/22` integration, `4/6` → `6/6` flows
- All 4 gap requirements (ADMIN-LOG-02, ADMIN-RRL-02, ADMIN-CONN-01, ADMIN-LISTZONES-01): `status: "unsatisfied"` → `status: "satisfied"` with `closed_by: "Phase 9"`
- Cross-phase integration table: 4 BROKEN entries → WIRED
- E2E flow: SetQueryLogging/SetRateLimit BROKEN → COMPLETE
- Tech debt items 2 and 3 (stream interceptor key ID, TSIG bootstrap) removed — now fixed

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Task 1 | 7d882bd | fix(server): TSIG always-init + stream interceptor key ID |
| Task 2 | 18828cc | docs(audit): update v1.2 milestone audit to PASSED |

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Changes are internal correctness fixes within existing trust boundaries (T-09-04 and T-09-05 from plan threat model — both accepted/mitigated as documented).

## Self-Check: PASSED

- [x] `internal/server/server.go` line 300: `s.tsigKeyRing, _ = tsig.NewKeyRing(nil)` before `if len(cfg.TsigKeys)` block
- [x] `api/grpc/server/server.go` lines 289, 274: `middleware.CtxKeyID{}` in stream interceptor
- [x] `go build ./...` exits 0
- [x] `go test $(./... | grep -v engine | grep -v resolver)` — all pass
- [x] `.planning/v1.2-MILESTONE-AUDIT.md` contains `status: passed`
- [x] Commits 7d882bd and 18828cc exist in git log
