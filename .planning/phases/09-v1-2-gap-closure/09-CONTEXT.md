# Phase 9: v1.2 Gap Closure — Admin API Wiring — Context

**Gathered:** 2026-05-17
**Status:** Ready for planning
**Mode:** Gap closure (--gaps) — derived from v1.2 milestone audit

<domain>
## Phase Boundary

Close the 4 production wiring gaps found by the v1.2 milestone audit. All subsystems were built in Phase 6 but the injection wiring into admin.Service was deferred to Phase 7; Phase 7 never completed it.

The 4 gaps (all in api/grpc/registry/register.go + cmd/dnsscienced/main.go):
1. `logger` nil → SetQueryLogging/GetQueryLoggingStatus always returns codes.Unimplemented
2. `rrlLimiter` nil → SetRateLimit/GetRateLimitStatus always returns codes.Unimplemented
3. `connReg` discarded (`_ = connReg`) → ListConnections always returns empty
4. `reloadMgr` nil → ListZones always returns empty

Also fix two tech-debt items from the audit:
5. TSIG bootstrap: tsigKeyRing only initialized when len(cfg.TsigKeys)>0 → AddTsigKey fails from empty config
6. Stream interceptor: apiKeyStreamInterceptor discards key ID → audit log shows cert CN instead of key ID

</domain>

<decisions>
## Implementation Decisions

### Logger accessor
- Add `GetLogger() *logging.Logger` to `internal/server/server.go` (Server struct already has `logger zerolog.Logger` but NOT `*logging.Logger`)
- WAIT: check if server.Server has a `*logging.Logger` field or only `zerolog.Logger`. Read the file first.
- The `logging.Logger` type wraps zerolog — it's in `internal/logging`. Check what Server stores.
- If Server only stores `zerolog.Logger`, the accessor must be added at the cmd level (serverSrvAdapter in main.go gets the logging.Logger from NewLogger return value).

### RRL accessor
- Add `GetRRL() *rrl.Limiter` to `internal/server/server.go` — Server has `rrl *rrl.Limiter` field (verified in Phase 6 SUMMARY)
- Expose via `services.SrvAdapter` interface in `api/grpc/services/management.go`
- Wire in `serverSrvAdapter` in `cmd/dnsscienced/main.go`

### ConnRegistry wiring
- Add `SetConnRegistry(reg *grpcserver.ConnRegistry)` setter to `internal/admin/service.go`
- After `grpcserver.New()` returns `connReg`, call `adminSvc.SetConnRegistry(connReg)` in `main.go`
- Remove `_ = connReg` line
- `adminSvc` is accessible because `RegisterAll` returns the registered service or we store the reference before RegisterAll

### ListZones fix
- Add `GetZoneNames() []string` to `server.Server` — iterates internal zone map
- admin.Service.ListZones: when reloadMgr is nil, fall back to calling `s.srv.GetZoneNames()` + `s.srv.GetZone(name)` for Serial/SourceFile data
- Alternatively: expose a `ListZonesInfo()` method on server.Server that returns the full AdminZoneInfo slice

### TSIG always-init
- In `server.New()`, initialize `tsigKeyRing = tsig.NewKeyRing()` unconditionally (before the `if len(cfg.TsigKeys) > 0` block)
- The if-block then populates keys into the always-non-nil ring

### Stream interceptor key ID
- In `apiKeyStreamInterceptor`, change `_, ok := keySet.Lookup(token)` to `id, ok := keySet.Lookup(token)`
- After auth passes, inject: `wrapped = &wrappedStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), middleware.CtxKeyID{}, id)}`
- Or simpler: store `ctx = context.WithValue(ss.Context(), middleware.CtxKeyID{}, id)` and use a stream wrapper

### Claude's Discretion
- Whether to use accessor pattern or direct struct field exposure
- Whether ListZones fallback calls GetZoneNames individually or uses a combined ListZonesInfo method
- Order of plans within waves

</decisions>

<code_context>
## Existing Code Insights

From audit and VERIFICATION files:
- `internal/admin/service.go`: has `logger`, `rrlLimiter`, `connRegistry`, `reloadMgr` fields — all nil in production
- `api/grpc/registry/register.go:74-81`: passes nil for reloadMgr, logger, rrlLimiter; line 76=logger, 81=rrlLimiter
- `cmd/dnsscienced/main.go:255`: RegisterAll call — 5th arg is nil (connRegistry), 6th is dsyncNotifier
- `cmd/dnsscienced/main.go:267`: `_ = connReg` — discards ConnRegistry from grpcserver.New()
- `api/grpc/services/management.go`: SrvAdapter interface — needs GetLogger/GetRRL added
- `internal/server/server.go:299`: `if len(cfg.TsigKeys) > 0` — TSIG init gate
- `api/grpc/server/server.go`: apiKeyStreamInterceptor — discards key ID

</code_context>

<specifics>
## Specific Ideas

- All 4 wiring gaps can be fixed in a single well-scoped pass
- Admin service already has all the field slots — only injection is missing
- Keep changes minimal: don't refactor admin.Service internals, just wire the nil fields
- Pre-existing tests must continue to pass (admin service tests wire fields directly in test setup)

</specifics>

<deferred>
## Deferred Ideas

- GetMetrics latency percentiles (AvgLatencyMs/P99LatencyMs = 0.0) — requires EMA/histogram tracking infrastructure; out of scope for gap closure
- SetWebhook per-zone wiring for DSYNC — out of scope
- scheduleDelegationCheck stub — out of scope

</deferred>

---
*Phase: 09-v1-2-gap-closure*
*Context gathered: 2026-05-17 via gap closure mode*
