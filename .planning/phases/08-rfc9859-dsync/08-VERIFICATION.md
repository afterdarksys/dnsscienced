---
phase: 08-rfc9859-dsync
verified: 2026-05-17T06:00:00Z
status: passed
score: 25/25 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 22/25
  gaps_closed:
    - "DSYNCAdminService is registered on the admin gRPC server — DSYNCNotifier now instantiated in server.New(); main.go passes it to RegisterAll; conditional registration fires"
    - "server.go creates DSYNCMetrics and calls SetMetrics on both handler and notifier — SetMetrics now called on s.dsyncNotifier as well as s.dsyncHandler"
  gaps_remaining: []
  regressions: []
---

# Phase 8: RFC 9859 DSYNC Re-Verification Report

**Phase Goal:** Implement RFC 9859: DSYNC record type (type 66), inbound NOTIFY(CDS/CSYNC) handler, outbound notification sender, rate limiting, and zone-level DSYNC record serving.
**Verified:** 2026-05-17T06:00:00Z
**Status:** passed
**Re-verification:** Yes — after gap closure via Plan 07 (DSYNCNotifier + DSYNCAdminService wiring)

## Gap Closure Summary

The previous verification (2026-05-17T01:30:00Z, score 22/25) identified two blockers and one warning:

- **BLOCKER 1 (CLOSED):** DSYNCNotifier never instantiated in production. Plan 07 added `dsyncNotifier *dsync.DSYNCNotifier` field to Server struct, instantiates it via `dsync.NewDSYNCNotifier(cfg.UDPAddr, 60*time.Second, zerolog.Nop())` inside `if cfg.DSYNC.Enabled`, and exposes it via `GetDSYNCNotifier()` accessor.
- **BLOCKER 2 (CLOSED):** DSYNCAdminService never registered. Plan 07 updated `main.go` to pass `srv.GetDSYNCNotifier()` as the 6th argument to `registry.RegisterAll`. The conditional registration in `register.go` now fires when DSYNC is enabled.
- **WARNING 3 (CONFIRMED DEFERRED):** SetWebhook not called in server.go. Plan 07 explicitly acknowledges this deferral with a comment: per-zone webhook wiring requires zone iteration over `ZoneDSYNCConfig.WebhookURL` which is not implemented at the server initialization layer. Webhook infrastructure is fully implemented and tested (4 tests pass). The ROADMAP Phase 8 scope does not list webhook wiring as a success criterion.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | DSYNC type 66 wire codec encodes and round-trips a DSYNCRecord correctly | VERIFIED | dsync.go TypeDSYNC=66, EncodeDSYNC/DecodeDSYNC; all 5 codec tests pass |
| 2 | DecodeDSYNC rejects rdata shorter than 6 bytes with a clear error | VERIFIED | `if len(raw) < 6 { return ..., "dsync rdata too short" }` in dsync.go |
| 3 | NotifyLimiter allows requests within burst and blocks excess per source IP | VERIFIED | ratelimit.go uses x/time/rate per-IP visitor map; Allow/Blocks tests pass |
| 4 | NotifyLimiter evicts stale visitor entries via background sweep | VERIFIED | sweepStale() with 10-min TTL, 5-min ticker; TestRateLimiterEviction passes |
| 5 | NotifyLimiter.Close() stops the background goroutine without leaking | VERIFIED | sync.Once in Close(); TestRateLimiterClose passes; all tests use defer limiter.Close() |
| 6 | NOTIFY from ACL-rejected source receives dns.RcodeRefused | VERIFIED | handler.go ACL check first; TestHandleInbound_ACLReject passes |
| 7 | NOTIFY from rate-limited source receives dns.RcodeRefused | VERIFIED | handler.go rate limiter second; TestHandleInbound_RateLimited passes |
| 8 | NOTIFY from allowed, non-rate-limited source receives dns.RcodeSuccess | VERIFIED | handler.go sets RcodeSuccess after both checks pass; tests pass |
| 9 | scheduleDelegationCheck is a stub that only logs | VERIFIED | scheduleDelegationCheck() logs only; no delegation engine — per plan intent |
| 10 | _dsync discovery queries candidate labels and returns all DSYNC records in answer | VERIFIED | discovery.go DiscoverDSYNC label traversal + queryDSYNC; TestDiscoverDSYNC_* pass |
| 11 | Outbound NOTIFY carries the correct qtype (TypeCDS or TypeCSYNC) not TypeSOA | VERIFIED | sender.go: SetNotify then `m.Question[0].Qtype = qtype` override; qtype tests pass |
| 12 | Handler struct has zerolog.Logger field for structured logging | VERIFIED | handler.go Handler struct has `log zerolog.Logger` field |
| 13 | AllowAll stub ACL satisfies Allower interface so Plan 05 can swap it | VERIFIED | allowAll struct + AllowAllACL() in handler.go; SourceACL also satisfies interface |
| 14 | handleDNS dispatches OpcodeNotify (4) to dsync.Handler before reaching authoritative or recursive path | VERIFIED | server.go OpcodeNotify branch; TestHandleDNSNotifyOpcode_Enabled passes |
| 15 | Server without DSYNC configured responds NOTIMPL to NOTIFY messages | VERIFIED | server.go: RcodeNotImplemented when dsyncHandler==nil; TestHandleDNSNotifyOpcode_Disabled passes |
| 16 | Server with DSYNC enabled acknowledges NOTIFY(CDS) with NOERROR | VERIFIED | Integration test TestHandleDNSNotifyOpcode_Enabled passes |
| 17 | Config structs ZoneDSYNCConfig and DSYNCConfig are parseable from YAML | VERIFIED | ZoneDSYNCConfig in config.go; DSYNCConfig in server.go — both have yaml tags |
| 18 | Zone file with TYPE66 record in BIND format loads and is accessible via GetRecords(TypeDSYNC) | VERIFIED | parser_dsync_test.go TestDSYNCZoneFile_BIND passes; RFC3597 fallback works |
| 19 | go build ./... exits 0 — the entire project compiles with the new dsync package | VERIFIED | Full build exits 0 with no output |
| 20 | SourceACL implements the Allower interface from Plan 02 | VERIFIED | source_acl.go has `var _ Allower = (*SourceACL)(nil)` compile-time assertion |
| 21 | Inbound NOTIFY from allowed IP proceeds past ACL; from blocked IP gets REFUSED | VERIFIED | SourceACL CIDR allowlist; empty allowlist accepts all (D-05); TestSourceACL_* pass |
| 22 | Prometheus counters use prometheus.NewCounterVec with correct names | VERIFIED | metrics.go uses prometheus.NewCounterVec; counter names: dnsscienced_dsync_notify_inbound_total, dnsscienced_dsync_notify_outbound_total, dnsscienced_dsync_webhook_total |
| 23 | DSYNCAdminService is registered on the admin gRPC server | VERIFIED | server.go creates DSYNCNotifier + accessor; main.go passes it to RegisterAll (line 255 confirmed `srv.GetDSYNCNotifier()`); register.go conditional fires |
| 24 | server.go creates DSYNCMetrics and calls SetMetrics on both handler and notifier | VERIFIED | server.go line 260: `s.dsyncHandler.SetMetrics(dsyncMetrics)`; line 266: `s.dsyncNotifier.SetMetrics(dsyncMetrics)` — both present |
| 25 | SendDSYNCNotify RPC accepts zone_name and qtype, enqueues via DSYNCNotifier.Notify; returns error if zone_name is empty | VERIFIED | dsync.go validates zone_name (required) and qtype (CDS/CSYNC only); 5 RPC tests pass |

**Score:** 25/25 truths verified

### Deferred Items

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | SetWebhook called on dsyncHandler for per-zone webhook URLs | Future phase | Plan 07 task 1 documents: "Per-zone webhook wiring requires zone iteration which is not implemented yet. For now, SetWebhook is called only if a future global webhook_url is added to DSYNCConfig." Not a ROADMAP Phase 8 success criterion. |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/dsync/dsync.go` | TypeDSYNC=66, DSYNCRecord, EncodeDSYNC, DecodeDSYNC, ParseRFC3597 | VERIFIED | All exports present and tested |
| `internal/dsync/ratelimit.go` | Per-source-IP token bucket rate limiter | VERIFIED | NotifyLimiter with background eviction and sync.Once Close |
| `internal/dsync/handler.go` | Handler struct, Allower interface, HandleInbound, metrics/webhook fields | VERIFIED | All required exports present; webhook field exists via SetWebhook setter |
| `internal/dsync/discovery.go` | DiscoverDSYNC function | VERIFIED | _dsync label traversal working |
| `internal/dsync/sender.go` | DSYNCNotifier, sendNotify | VERIFIED | Present, tested, and now instantiated in production via server.go |
| `internal/dsync/source_acl.go` | SourceACL implementing Allower | VERIFIED | Compile-time interface check present |
| `internal/dsync/webhook.go` | WebhookClient with Fire() | VERIFIED | json/base64 formats, timeout, no-op on empty URL |
| `internal/dsync/metrics.go` | DSYNCMetrics with 3 CounterVec | VERIFIED | Counters registered with correct names |
| `internal/dsync/metrics_test.go` | TestMetricsIncrement | VERIFIED | Counter increment verified via HandleInbound mock |
| `internal/config/config.go` | ZoneDSYNCConfig with all fields | VERIFIED | WebhookURL, AllowedSources, RateLimitPerMin, PropagationDelay present |
| `internal/server/server.go` | dsyncHandler, dsyncNotifier fields; OpcodeNotify dispatch; SetMetrics on both; GetDSYNCNotifier accessor | VERIFIED | All wiring confirmed; dsyncNotifier field at line 146; NewDSYNCNotifier at line 265; SetMetrics at lines 260+266; accessor at line 427 |
| `internal/server/notify_test.go` | Tests for NOTIFY dispatch | VERIFIED | 3 tests pass |
| `internal/server/dsync_wiring_test.go` | TestDSYNCNotifierWiring, TestDSYNCNotifierNilWhenDisabled, TestDSYNCHandlerAndNotifierShareMetrics | VERIFIED | All 3 wiring tests pass |
| `internal/zone/parser_dsync_test.go` | Tests for TYPE66 zone loading | VERIFIED | 2 tests pass |
| `api/grpc/proto/admin.proto` | DSYNCAdminService + SendDSYNCNotify | VERIFIED | Appended to proto; generated code present |
| `api/grpc/services/dsync.go` | DSYNCService implementing DSYNCAdminServiceServer | VERIFIED | Strict CDS/CSYNC validation; 5 tests pass |
| `api/grpc/registry/register.go` | RegisterDSYNCAdminServiceServer (conditional) | VERIFIED | Registration fires when dsyncNotifier non-nil (passed from main.go) |
| `cmd/dnsscienced/main.go` | srv.GetDSYNCNotifier() passed to RegisterAll | VERIFIED | Line 255 confirmed: `registry.RegisterAll(s, &serverSrvAdapter{srv}, loadedCfg.ZonesDir, compileBin, nil, srv.GetDSYNCNotifier())` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| internal/dsync/dsync.go | github.com/miekg/dns | dns.PackDomainName/UnpackDomainName | WIRED | Present in EncodeDSYNC/DecodeDSYNC |
| internal/dsync/ratelimit.go | golang.org/x/time/rate | rate.NewLimiter | WIRED | Confirmed in ratelimit.go |
| internal/dsync/handler.go | internal/dsync/ratelimit.go | NotifyLimiter.Allow(clientIP) | WIRED | limiter.Allow called in HandleInbound |
| internal/dsync/handler.go | Allower interface | acl.Check method | WIRED | Check() called before rate limit |
| internal/dsync/sender.go | github.com/miekg/dns | SetNotify + Question[0].Qtype | WIRED | SetNotify then Qtype override confirmed |
| internal/dsync/discovery.go | github.com/miekg/dns | ExchangeContext | WIRED | dns.Client.ExchangeContext in queryDSYNC |
| internal/server/server.go | internal/dsync/handler.go | s.dsyncHandler.HandleInbound | WIRED | OpcodeNotify branch in handleDNS |
| internal/server/server.go | internal/dsync/sender.go | dsync.NewDSYNCNotifier | WIRED | Confirmed at line 265 of server.go |
| internal/dsync/handler.go | internal/dsync/metrics.go | NotifyInbound.WithLabelValues | WIRED | 3 call sites in HandleInbound |
| internal/dsync/sender.go | internal/dsync/metrics.go | NotifyOutbound.WithLabelValues | WIRED | 2 call sites inside worker() |
| api/grpc/services/dsync.go | internal/dsync/sender.go | DSYNCNotifier.Notify | WIRED | Notifier passed via NewDSYNCService; Notify called in SendDSYNCNotify |
| api/grpc/registry/register.go | api/grpc/services/dsync.go | RegisterDSYNCAdminServiceServer | WIRED | Conditional registration; main.go now passes dsyncNotifier |
| internal/server/server.go | internal/dsync/metrics.go | SetMetrics on handler + notifier | WIRED | Lines 260+266: handler.SetMetrics + notifier.SetMetrics with same instance |
| cmd/dnsscienced/main.go | api/grpc/registry/register.go | srv.GetDSYNCNotifier() as 6th arg | WIRED | Confirmed at line 255 |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|-------------------|--------|
| handler.go HandleInbound | clientIP, r.Question | dns.ResponseWriter (inbound) | Yes | FLOWING — ACL + rate limit + reply chain working |
| discovery.go DiscoverDSYNC | records []DSYNCRecord | dns.Client.ExchangeContext | Yes | FLOWING |
| sender.go worker | ev (notifyEvent) | events channel from DSYNCNotifier.Notify | Yes | FLOWING — notifier now instantiated in production; channel populated via gRPC RPC |
| metrics.go counters | label values | HandleInbound + worker() | Inbound: FLOWING; Outbound: FLOWING | FLOWING — both handler and notifier now wired |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| DSYNC codec round-trip | go test ./internal/dsync/... -run TestDSYNCCodec | PASS | PASS |
| Rate limiter allows/blocks | go test ./internal/dsync/... -run TestNotifyRateLimiter | PASS | PASS |
| NOTIFY opcode dispatch enabled | go test ./internal/server/... -run TestHandleDNSNotifyOpcode_Enabled | PASS | PASS |
| NOTIFY opcode dispatch disabled | go test ./internal/server/... -run TestHandleDNSNotifyOpcode_Disabled | PASS | PASS |
| Zone file TYPE66 loading | go test ./internal/zone/... -run TestDSYNCZoneFile | PASS | PASS |
| gRPC SendDSYNCNotify RPC | go test ./api/grpc/services/... -run TestSendDSYNCNotify | PASS | PASS |
| Metrics counter increment | go test ./internal/dsync/... -run TestMetrics | PASS | PASS |
| DSYNCNotifier wiring (non-nil when enabled) | go test ./internal/server/... -run TestDSYNCNotifierWiring | PASS | PASS |
| DSYNCNotifier nil when disabled | go test ./internal/server/... -run TestDSYNCNotifierNilWhenDisabled | PASS | PASS |
| Shared metrics wiring | go test ./internal/server/... -run TestDSYNCHandlerAndNotifierShareMetrics | PASS | PASS |
| Full project build | go build ./... | exit 0 | PASS |
| SourceACL CIDR matching | go test ./internal/dsync/... -run TestSourceACL | PASS | PASS |
| Webhook fire-and-forget | go test ./internal/dsync/... -run TestWebhookClient | PASS | PASS |

### Pre-Existing Test Failures (Not Regressions from Phase 08)

Two test failures exist in the codebase that are NOT introduced by Phase 08:

- `internal/engine: TestResolver_Resolve` — expects hardcoded IP `1.2.3.4` but gets live DNS result `104.20.23.154`; test makes real DNS calls. Last modified in Phase 5-6 commits.
- `internal/resolver: TestFindGlue` — IPv6 glue address formatting test. Last modified in commit `b50bf31` (Phase 5-6 era).

Neither package was touched by any Phase 08 commit. These are pre-existing, unrelated to DSYNC.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| internal/dsync/handler.go | scheduleDelegationCheck | Stub: log only | Info | Intentional per plan — documented as expected stub behavior |
| internal/server/server.go | ~269 | SetWebhook not called — per-zone webhook deferred | Info | Intentional deferral documented in Plan 07 with comment; webhook infrastructure tested |

### Human Verification Required

None. All verification was completed programmatically.

## Gaps Summary

No gaps remain. The two blockers from the previous verification (DSYNCNotifier never instantiated, DSYNCAdminService never registered) are fully closed by Plan 07. The webhook WARNING was confirmed as an intentional deferral documented in Plan 07.

Phase 08 goal achieved: DSYNC type 66 codec, inbound NOTIFY handler with ACL+rate limiting, outbound notification sender (now wired in production binary), _dsync discovery, zone file TYPE66 support, Prometheus metrics, and SendDSYNCNotify Admin RPC are all implemented, tested, and wired into the running binary.

---

_Verified: 2026-05-17T06:00:00Z_
_Verifier: Claude (gsd-verifier)_
