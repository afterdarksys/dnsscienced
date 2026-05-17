---
phase: 08-rfc9859-dsync
verified: 2026-05-17T01:30:00Z
status: gaps_found
score: 22/25 must-haves verified
overrides_applied: 0
re_verification: false
gaps:
  - truth: "DSYNCAdminService is registered on the admin gRPC server"
    status: failed
    reason: "Registration code exists in register.go (conditionally gated on dsyncNotifier arg) but main.go calls RegisterAll without a dsyncNotifier, so the service is never registered in the running binary. No DSYNCNotifier is ever instantiated in production code (server.go or main.go)."
    artifacts:
      - path: "cmd/dnsscienced/main.go"
        issue: "RegisterAll called at line 255 without dsyncNotifier argument — DSYNCAdminService never registered"
      - path: "internal/server/server.go"
        issue: "No DSYNCNotifier field on Server struct; no NewDSYNCNotifier call in New() — outbound sender dead code"
    missing:
      - "Add dsyncNotifier *dsync.DSYNCNotifier field to Server struct"
      - "Instantiate DSYNCNotifier in server.New() when cfg.DSYNC.Enabled, wire SetMetrics on it"
      - "Expose dsyncNotifier via accessor or pass it through gRPC wiring in main.go"
      - "Pass dsyncNotifier to RegisterAll in main.go so DSYNCAdminService gets registered"
  - truth: "server.go creates DSYNCMetrics and calls SetMetrics on both handler and notifier"
    status: partial
    reason: "server.go creates DSYNCMetrics and calls SetMetrics on the handler correctly, but there is no notifier to call SetMetrics on (DSYNCNotifier never instantiated in server.go). The notifier's outbound metrics are never wired."
    artifacts:
      - path: "internal/server/server.go"
        issue: "SetMetrics called on dsyncHandler (line 259) but no dsyncNotifier exists in server scope to call SetMetrics on"
    missing:
      - "After DSYNCNotifier is created in server.New(), call s.dsyncNotifier.SetMetrics(dsyncMetrics)"
  - truth: "Webhook delivery is fire-and-forget: 5s timeout, no retry, failure logged — configured per-zone via SetWebhook after NewHandler"
    status: partial
    reason: "WebhookClient and SetWebhook are fully implemented and tested. However, server.go does not call SetWebhook on the handler after construction, so webhook delivery is never active in the running binary. Plan 05 SUMMARY acknowledged this explicitly."
    artifacts:
      - path: "internal/server/server.go"
        issue: "SetWebhook not called after NewHandler — webhook is implemented but not wired"
    missing:
      - "In server.New() DSYNC init block, construct WebhookClient from zone config and call s.dsyncHandler.SetWebhook(wc)"
---

# Phase 8: RFC 9859 DSYNC Verification Report

**Phase Goal:** Implement RFC 9859 DSYNC NOTIFY support (TYPE66 codec, inbound handler, discovery, outbound sender, SourceACL, webhook, metrics, Admin RPC)
**Verified:** 2026-05-17T01:30:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | DSYNC type 66 wire codec encodes and round-trips a DSYNCRecord correctly | VERIFIED | dsync.go TypeDSYNC=66, EncodeDSYNC/DecodeDSYNC verified; all 5 codec tests pass |
| 2 | DecodeDSYNC rejects rdata shorter than 6 bytes with a clear error | VERIFIED | `if len(raw) < 6 { return ..., "dsync rdata too short" }` in dsync.go; TestDSYNCDecodeTooShort passes |
| 3 | NotifyLimiter allows requests within burst and blocks excess per source IP | VERIFIED | ratelimit.go uses x/time/rate per-IP visitor map; TestNotifyRateLimiter_Allows and _Blocks pass |
| 4 | NotifyLimiter evicts stale visitor entries via background sweep | VERIFIED | sweepStale() with 10min TTL, 5min ticker; TestRateLimiterEviction passes using ForceLastSeen/SweepStaleForTest |
| 5 | NotifyLimiter.Close() stops the background goroutine without leaking | VERIFIED | sync.Once in Close(); TestRateLimiterClose passes; all ratelimit tests use defer limiter.Close() |
| 6 | NOTIFY from ACL-rejected source receives dns.RcodeRefused | VERIFIED | handler.go checks ACL first (lines 113-119); TestHandleInbound_ACLReject passes |
| 7 | NOTIFY from rate-limited source receives dns.RcodeRefused | VERIFIED | handler.go checks limiter second (lines 121-127); TestHandleInbound_RateLimited passes |
| 8 | NOTIFY from allowed, non-rate-limited source receives dns.RcodeSuccess | VERIFIED | handler.go sets RcodeSuccess after both checks pass; TestHandleInbound_Success_CDS/CSYNC pass |
| 9 | scheduleDelegationCheck is a stub that only logs | VERIFIED | scheduleDelegationCheck() logs only, no delegation engine; per plan intent |
| 10 | _dsync discovery queries candidate labels and returns all DSYNC records in answer | VERIFIED | discovery.go DiscoverDSYNC with label traversal + queryDSYNC; all TestDiscoverDSYNC_* pass |
| 11 | Outbound NOTIFY carries the correct qtype (TypeCDS or TypeCSYNC) not TypeSOA | VERIFIED | sender.go: SetNotify then `m.Question[0].Qtype = qtype` override; TestSendNotifyQtype_CDS/CSYNC pass |
| 12 | Handler struct has zerolog.Logger field for structured logging | VERIFIED | handler.go Handler struct has `log zerolog.Logger` field |
| 13 | AllowAll stub ACL satisfies Allower interface so Plan 05 can swap it | VERIFIED | allowAll struct + AllowAllACL() in handler.go; SourceACL also satisfies interface |
| 14 | handleDNS dispatches OpcodeNotify (4) to dsync.Handler before reaching authoritative or recursive path | VERIFIED | server.go line 431: `if r.Opcode == dns.OpcodeNotify` branch; TestHandleDNSNotifyOpcode_Enabled passes |
| 15 | Server without DSYNC configured responds NOTIMPL to NOTIFY messages | VERIFIED | server.go line 437: `m.Rcode = dns.RcodeNotImplemented` when dsyncHandler==nil; TestHandleDNSNotifyOpcode_Disabled passes |
| 16 | Server with DSYNC enabled acknowledges NOTIFY(CDS) with NOERROR | VERIFIED | Integration tested; TestHandleDNSNotifyOpcode_Enabled passes |
| 17 | Config structs ZoneDSYNCConfig and DSYNCConfig are parseable from YAML | VERIFIED | ZoneDSYNCConfig in config.go (NotifyParent, PropagationDelay, WebhookURL, AllowedSources, RateLimitPerMin); DSYNCConfig in server.go (Enabled, RateLimitPerMin, Burst) |
| 18 | Zone file with TYPE66 record in BIND format loads and is accessible via GetRecords(TypeDSYNC) | VERIFIED | parser_dsync_test.go TestDSYNCZoneFile_BIND passes; miekg/dns RFC3597 fallback works for TYPE66 |
| 19 | go build ./... exits 0 — the entire project compiles with the new dsync package | VERIFIED | Full build exits 0 with no output |
| 20 | SourceACL implements the Allower interface from Plan 02 | VERIFIED | source_acl.go has `var _ Allower = (*SourceACL)(nil)` compile-time assertion; TestSourceACL_SatisfiesAllower |
| 21 | Inbound NOTIFY from allowed IP proceeds past ACL; from blocked IP gets REFUSED | VERIFIED | SourceACL CIDR allowlist; empty allowlist accepts all (D-05); all TestSourceACL_* pass |
| 22 | Prometheus counters use prometheus.NewCounterVec with correct names | VERIFIED | metrics.go uses prometheus.NewCounterVec (not sync/atomic); counter names: dnsscienced_dsync_notify_inbound_total, dnsscienced_dsync_notify_outbound_total, dnsscienced_dsync_webhook_total — Note: uses registerOrReuse wrapper around prometheus.Register (not MustRegister) for test safety |
| 23 | DSYNCAdminService is registered on the admin gRPC server | FAILED | Registration code exists in register.go (conditional on dsyncNotifier arg) but main.go calls RegisterAll without a notifier; no DSYNCNotifier is ever instantiated in production code |
| 24 | server.go creates DSYNCMetrics and calls SetMetrics on both handler and notifier | PARTIAL | SetMetrics called on handler (verified); no DSYNCNotifier instantiated in server.go so notifier never gets SetMetrics |
| 25 | SendDSYNCNotify RPC accepts zone_name and qtype, enqueues via DSYNCNotifier.Notify; returns error if zone_name is empty | VERIFIED | dsync.go SendDSYNCNotify validates zone_name (required) and qtype (CDS/CSYNC); 5 RPC tests pass |

**Score:** 22/25 truths verified (2 failed, 1 partial)

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/dsync/dsync.go` | TypeDSYNC constant, DSYNCRecord, EncodeDSYNC, DecodeDSYNC, ParseRFC3597 | VERIFIED | All exports present and tested |
| `internal/dsync/ratelimit.go` | Per-source-IP token bucket rate limiter | VERIFIED | NotifyLimiter with background eviction and sync.Once Close |
| `internal/dsync/dsync_test.go` | Tests for DSYNC-01 and DSYNC-02 | VERIFIED | 5 tests; all pass |
| `internal/dsync/ratelimit_test.go` | Tests for DSYNC-04 and DSYNC-05 | VERIFIED | 5 tests with defer limiter.Close(); all pass |
| `internal/dsync/handler.go` | Handler struct, Allower interface, HandleInbound | VERIFIED | All required exports present |
| `internal/dsync/discovery.go` | DiscoverDSYNC function | VERIFIED | Present; _dsync label traversal working |
| `internal/dsync/sender.go` | DSYNCNotifier, sendNotify | VERIFIED | Present and tested; NOTE: never instantiated in production |
| `internal/dsync/source_acl.go` | SourceACL implementing Allower | VERIFIED | Compile-time interface check present |
| `internal/dsync/webhook.go` | WebhookClient with Fire() | VERIFIED | json/base64 formats, timeout, no-op on empty URL |
| `internal/dsync/metrics.go` | DSYNCMetrics with 3 CounterVec | VERIFIED | Counters registered with correct names |
| `internal/dsync/metrics_test.go` | TestMetricsIncrement | VERIFIED | 3 metrics tests pass |
| `internal/config/config.go` | ZoneDSYNCConfig with all fields | VERIFIED | WebhookURL, AllowedSources, RateLimitPerMin, PropagationDelay present |
| `internal/server/server.go` | dsyncHandler field, OpcodeNotify dispatch, DSYNCMetrics wiring | PARTIAL | dsyncHandler and OpcodeNotify correct; no DSYNCNotifier field or wiring |
| `internal/server/notify_test.go` | Tests for NOTIFY dispatch | VERIFIED | 3 tests pass |
| `internal/zone/parser_dsync_test.go` | Tests for TYPE66 zone loading | VERIFIED | 2 tests pass |
| `api/grpc/proto/admin.proto` | DSYNCAdminService + SendDSYNCNotify | VERIFIED | Appended to proto; generated code present |
| `api/grpc/services/dsync.go` | DSYNCService implementing DSYNCAdminServiceServer | VERIFIED | Strict CDS/CSYNC validation; 5 tests pass |
| `api/grpc/registry/register.go` | RegisterDSYNCAdminServiceServer (conditional) | PARTIAL | Registration code exists but never triggered in production |

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| internal/dsync/dsync.go | github.com/miekg/dns | dns.PackDomainName/UnpackDomainName | WIRED | Present in EncodeDSYNC/DecodeDSYNC |
| internal/dsync/ratelimit.go | golang.org/x/time/rate | rate.NewLimiter | WIRED | Confirmed in ratelimit.go |
| internal/dsync/handler.go | internal/dsync/ratelimit.go | NotifyLimiter.Allow(clientIP) | WIRED | limiter.Allow called in HandleInbound |
| internal/dsync/handler.go | Allower interface | acl.Check method | WIRED | Check() called before rate limit |
| internal/dsync/sender.go | github.com/miekg/dns | SetNotify + Question[0].Qtype | WIRED | SetNotify then Qtype override confirmed |
| internal/dsync/discovery.go | github.com/miekg/dns | ExchangeContext | WIRED | dns.Client.ExchangeContext in queryDSYNC |
| internal/server/server.go | internal/dsync/handler.go | s.dsyncHandler.HandleInbound | WIRED | Line 433 in handleDNS |
| internal/dsync/handler.go | internal/dsync/metrics.go | NotifyInbound.WithLabelValues | WIRED | 3 call sites in HandleInbound |
| internal/dsync/sender.go | internal/dsync/metrics.go | NotifyOutbound.WithLabelValues | WIRED | 2 call sites inside worker(); ORPHANED — sender never instantiated |
| api/grpc/services/dsync.go | internal/dsync/sender.go | DSYNCNotifier.Notify | WIRED (code) | Code correct but notifier never passed in production |
| api/grpc/registry/register.go | api/grpc/services/dsync.go | RegisterDSYNCAdminServiceServer | NOT_WIRED | Conditional registration; main.go never passes dsyncNotifier |
| internal/server/server.go | internal/dsync/metrics.go | SetMetrics (notifier) | NOT_WIRED | No DSYNCNotifier in server.go; SetMetrics only called on handler |

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|-------------------|--------|
| handler.go HandleInbound | clientIP, r.Question | dns.ResponseWriter (inbound) | Yes | FLOWING — ACL + rate limit + reply chain working |
| discovery.go DiscoverDSYNC | records []DSYNCRecord | dns.Client.ExchangeContext | Yes (in tests; live DNS in production) | FLOWING |
| sender.go worker | ev (notifyEvent) | events channel | Yes (code correct) | ORPHANED — channel never populated in production |
| metrics.go counters | label values | HandleInbound + worker | Inbound: flowing; Outbound: orphaned | PARTIAL |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| DSYNC codec round-trip | go test ./internal/dsync/... -run TestDSYNCCodec | PASS | PASS |
| Rate limiter allows/blocks | go test ./internal/dsync/... -run TestNotifyRateLimiter | PASS | PASS |
| NOTIFY opcode dispatch enabled | go test ./internal/server/... -run TestHandleDNSNotifyOpcode_Enabled | PASS | PASS |
| NOTIFY opcode dispatch disabled | go test ./internal/server/... -run TestHandleDNSNotifyOpcode_Disabled | PASS | PASS |
| Zone file TYPE66 loading | go test ./internal/zone/... -run TestDSYNCZoneFile | PASS | PASS |
| gRPC SendDSYNCNotify RPC | go test ./api/grpc/services/... -run TestSendDSYNCNotify | PASS | PASS |
| Metrics counter increment | go test ./internal/dsync/... -run TestMetrics | PASS | PASS |
| Full project build | go build ./... | exit 0 | PASS |
| SourceACL CIDR matching | go test ./internal/dsync/... -run TestSourceACL | PASS | PASS |
| Webhook fire-and-forget | go test ./internal/dsync/... -run TestWebhookClient | PASS | PASS |

## Requirements Coverage

| Requirement | Source Plan | Status | Evidence |
|-------------|------------|--------|---------|
| DSYNC-01 | 08-01 | SATISFIED | TypeDSYNC=66 codec; round-trip tests pass |
| DSYNC-02 | 08-01 | SATISFIED | DecodeDSYNC minimum 6-byte check; TestDSYNCDecodeTooShort passes |
| DSYNC-03 | 08-02, 08-05 | SATISFIED | Allower interface + SourceACL; ACL-first REFUSED; tests pass |
| DSYNC-04 | 08-01 | SATISFIED | NotifyLimiter per-IP token bucket; TestNotifyRateLimiter_Allows/Blocks pass |
| DSYNC-05 | 08-01 | SATISFIED | sweepStale eviction + Close(); TestRateLimiterEviction/Close pass |
| DSYNC-06 | 08-02 | SATISFIED | DiscoverDSYNC _dsync parent label traversal; TestDiscoverDSYNC_* pass |
| DSYNC-07 | 08-02, 08-06 | PARTIAL | Outbound sender code correct; sendNotify Qtype override verified; DSYNCNotifier never instantiated in production — outbound NOTIFY cannot be triggered from running binary |
| DSYNC-08 | 08-03, 08-06 | PARTIAL | Inbound handler + opcode dispatch fully working; Admin RPC code correct and tested; DSYNCAdminService never registered in main binary because main.go omits dsyncNotifier from RegisterAll |
| DSYNC-09 | 08-04 | SATISFIED | Zone file TYPE66 test; TestDSYNCZoneFile_BIND/MultipleRecords pass |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| internal/dsync/handler.go | 139-146 | scheduleDelegationCheck stub (log only) | Info | Intentional per plan — stub is documented and expected |
| internal/dsync/sender.go | — | DSYNCNotifier fully implemented but never instantiated | Warning | Outbound NOTIFY dead code in production binary |
| api/grpc/services/dsync.go | — | SendDSYNCNotify RPC fully implemented but service never registered | Blocker | Admin RPC cannot be reached in running binary |
| cmd/dnsscienced/main.go | 255 | RegisterAll called without dsyncNotifier | Blocker | Omission causes DSYNCAdminService to not be registered |

## Gaps Summary

Three gaps block full goal achievement:

**Gap 1 (BLOCKER): DSYNCNotifier never instantiated in production.**
The outbound sender `DSYNCNotifier` is implemented and tested in `internal/dsync/sender.go` but is never created in `server.go` or `main.go`. The `Server` struct has no `dsyncNotifier` field. This means outbound NOTIFY(CDS/CSYNC) to parent zones via `_dsync` discovery is dead code — a core RFC 9859 requirement is not reachable at runtime.

**Gap 2 (BLOCKER): DSYNCAdminService never registered.**
`register.go` has conditional registration gated on a `dsyncNotifier` argument, but `main.go` calls `RegisterAll` without one (line 255). The `SendDSYNCNotify` Admin RPC is implemented and tested but cannot be reached in the running binary. This is a direct consequence of Gap 1.

**Gap 3 (WARNING): SetWebhook not called in server.go.**
`WebhookClient` and `SetWebhook` are fully implemented. Plan 05 SUMMARY explicitly acknowledged this as a deviation: "Since server.go uses a global DSYNCConfig (not per-zone config), the SetWebhook call was not added to server.go's initialization block." The infrastructure is correct — operators cannot configure webhook delivery without additional wiring code.

The root cause of Gaps 1 and 2 is the same: `DSYNCNotifier` instantiation was not added to `server.New()` or `main.go`. Fixing Gap 1 (add `dsyncNotifier` field + `NewDSYNCNotifier` call in `server.New()`, wire it into `RegisterAll` from `main.go`) automatically closes Gap 2.

---

_Verified: 2026-05-17T01:30:00Z_
_Verifier: Claude (gsd-verifier)_
