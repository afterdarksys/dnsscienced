---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: completed
last_updated: "2026-05-16T14:37:24.296Z"
last_activity: 2026-05-16
progress:
  total_phases: 3
  completed_phases: 1
  total_plans: 16
  completed_plans: 6
  percent: 38
---

# State

## Current Position

Phase: 07
Plan: Not started
Status: Phase 06 complete — 6/6 plans done; ready for Phase 07
Last activity: 2026-05-16

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23)

**Core value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.
**Current focus:** Phase 06 — admin-api-stubs-registration

## Accumulated Context

- v1.0 shipped cleanly; 19 tests green; binary builds as `dnsscienced-linux`
- HTTP admin handler lives in `internal/firewalld/admin.go` — interim, stays as fallback
- Proto codegen: run `generate.sh` after any `.proto` changes
- ThreatIntelConfig.FeedURL field exists in config.go but is unused
- QueryContext.CustomerID exists in struct but never populated
- Forwarder currently takes a single upstream target from rule/Starlark
- Starlark `on_query(q, score)` signature — q is dict, score 0-100 int
- Phase 2 Plan 01 complete: FirewallAdminService appended to admin.proto; Go stubs regenerated (admin.pb.go, admin_grpc.pb.go); go build ./... passes
- generate.sh requires $HOME/go/bin in PATH for protoc plugins; also generates stray management.pb.go in pb/ — delete after codegen (correct files are in pb/mgmt/)
- FirewallAdminServiceServer interface and all Firewall* message types now available in api/grpc/proto/pb for Wave 2 plans
- Phase 2 Plan 02 complete: LoadSource(id, src) on *Firewall; GetFirewall() accessor chain wired through SrvAdapter to serverSrvAdapter and NoopSrvAdapter; go build ./... passes
- NoopSrvAdapter.GetFirewall() returns nil — nil guard required at call site in Plan 04 RegisterAll
- firewalld import added to api/grpc/services/management.go and api/grpc/registry/register.go
- Phase 2 Plan 03 complete: FirewallService struct implements FirewallAdminServiceServer; all 4 RPCs (FirewallStats, LoadScript, RemoveScript, InjectScore) implemented with validation and delegation; 13 unit tests passing
- TotalNxdomain (lowercase d) is the correct proto-generated field name for total_nxdomain
- api/grpc/services/firewall.go and firewall_test.go created; go test ./api/grpc/services/ -run TestFirewallService exits 0
- Phase 2 Plan 04 complete: RegisterAll in api/grpc/registry/register.go now conditionally registers FirewallAdminService via nil-guard on srv.GetFirewall(); go build ./... passes; Phase 2 gRPC Admin feature is end-to-end complete
- Nil-guard pattern: if fw := srv.GetFirewall(); fw != nil — FirewallAdminService not registered when firewall.enabled is false in config.yaml (T-02-07 mitigation)
- Pre-existing test failures (not introduced by Phase 2): internal/dnssec build error, internal/engine/TestResolver_Resolve (live DNS), internal/resolver/TestFindGlue (formatting)
- Phase 3 Plan 01 complete: ThreatIntelConfig extended with 6 feed fields (FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers); DefaultConfig sets PollInterval=5m, Timeout=30s; RemoveIPScore added to *ThreatIntel; go build ./... passes; all firewalld tests pass
- AuthToken doc comment: "Never logged — only presence is logged" — runtime enforcement deferred to feed.go Plan 02 (T-03-01)
- TLSSkipVerify defaults false; operator must explicitly opt in (T-03-02)
- RemoveIPScore: no ToLower — IPs stored in net.IP.String() normalized form at AddIPScore call site
- Phase 3 Plan 02 complete: FeedClient in internal/firewalld/feed.go; StartFeed(ctx, wg) on *Firewall; parseFeed pure function; apply() full-replace semantics; fetchAndApply() error resilience (D-14 — failed fetch leaves prev scores intact); go build ./... passes
- wg typed as interface{ Add(int); Done() } in StartFeed — server passes &s.wg directly in Plan 03
- AuthToken never in log output (T-03-03 mitigated): authDesc computed as "bearer (set)" or "none"; token only in cfg.AuthToken != "" check and req.Header.Set
- CIDR strings stored as-is in prevIPs; AddIPScore/RemoveIPScore accept CIDR strings so round-trip is clean
- Phase 3 Plan 03 complete: s.firewall.StartFeed(s.ctx, &s.wg) wired in server.go New() after firewalld.New() block; feed goroutine tracked in s.wg so Stop() waits for clean exit; go build ./... passes
- feed_test.go created: 6 tests (TestFeedConfig, TestParseFeed_ValidEntries, TestParseFeed_ScoreClamping, TestFeedClient_Apply_FullReplace, TestFeedClient_ErrorHandling, TestFeedClient_Lifecycle); go test -race ./internal/firewalld/... exits 0
- TestThreatIntel_RemoveIPScore is in threat_intel_test.go (Plan 01 artifact) — not duplicated in feed_test.go
- Phase 3 complete: FEED-01 through FEED-04 all delivered; 27 firewalld tests pass; no new test failures
- Phase 4 Plan 01 complete: edns0.go created (edns0CustomerIDCode=65000, edns0MaxCustomerIDLen=64, extractCustomerID helper); qctx.CustomerID = extractCustomerID(r, fw.logger) inserted in firewalld.go Check() before any policy evaluation; 7 new tests added to firewalld_test.go; 31 firewalld tests pass; go build ./... passes
- edns0CustomerIDCode = 65000 (0xFDE8) — private-use range per RFC 6891 §6.1.3.1; do NOT use dns.EDNS0LOCALSTART (65001)
- extractCustomerID: r.IsEdns0() → range opt.Option → type-assert *dns.EDNS0_LOCAL → compare local.Code != edns0CustomerIDCode → 64-byte cap with debug log on oversized
- Integration tests use Config{} struct literal with ThreatIntelConfig.CustomerMeta map — defaultTestConfig() and SetCustomerTrust() do not exist in the package
- Phase 4 complete: CUST-01, CUST-02, CUST-03 delivered; QueryContext.CustomerID populated at intake before all policy/junk/intel evaluation
- Phase 5 Plan 01 complete: UpstreamPool struct with atomic.Uint64 round-robin in forwarder.go; RedirectConfig{Upstreams []string} + Redirect field in config.go; pool *UpstreamPool field + New() init + Check() pool-fill + SERVFAIL-on-empty in firewalld.go; 36 firewalld tests pass (31 pre-existing + 5 new); go build ./... passes
- UpstreamPool.Next() uses (counter.Add(1)-1) % len(upstreams) for 0-indexed round-robin; empty pool returns error (D-13)
- New() validates at startup: redirect rules with no redirect_server and empty pool return fmt.Errorf — fail fast before serving traffic
- starlark.pool = pool wiring deferred to Plan 02 (StarlarkEngine does not yet have pool field)
- TDD used for Plan 01 Task 1: RED commit a2b86a8, GREEN commit 4a5dc2a, Task 2 (auto) commit 59733ac
- Phase 5 Plan 02 complete: StarlarkEngine.pool field added; redirect builtin rejects server= kwarg (hard error D-02) and calls se.pool.Next() (D-04); compileRule redirect guard removed (D-07); starlark.pool = pool wired in New() (D-10/A1); 7 new integration tests; 43 firewalld tests pass; go build ./... passes
- redirect builtin kwarg-scan pattern: range kwargs before UnpackArgs; kv[0].(starlark.String) cast for key comparison
- Integration test pattern: always set ThreatIntel.BlockThreshold: 100 when testing Starlark — default threshold 0 blocks all queries before stage 4
- Duplicate test symbol: TestUpstreamPool_RoundRobin and TestUpstreamPool_SingleUpstream live in forwarder_test.go (Plan 01); not re-declared in firewalld_test.go
- REDIR-01 through REDIR-04 all delivered; Phase 5 (Redirect Load Balancing) complete
- Phase 6 Plan 01 complete: Logger.SetQueryLogEnabled/IsQueryLogEnabled/QueryLogConfig/QueriesLogged added; LogQuery race fixed (holds mu); rrl.Limiter cfgMu + GetConfig/UpdateConfig added; server.Server udpQueries/tcpQueries atomics + Stats.UDPQueries/TCPQueries; go build ./... + go test -race ./internal/logging/... ./internal/rrl/... ./internal/server/... exit 0
- cfg snapshot pattern: Check() takes RLock, copies l.cfg to local var, RUnlocks — avoids holding lock during hot query path; helpers refactored to pkg-level fns accepting Config snapshot
- Pre-existing vet error: internal/protective/engine.go line 410 "return copies lock value" — pre-dates Phase 6, deferred
- Phase 6 Plan 02 complete: pb.RegisterAdminServiceServer called in RegisterAll; admin.Service extended with AdminSrvAdapter/zonesDir/compileBin/rrlLimiter; services.SrvStats gets UDPQueries/TCPQueries; cache accessor chain via resolver.GetCache->server.GetCache->GetShardedCache; nil guards on RefreshZone/ListZones/ReloadZones/GetServerStatus; go build ./... passes
- AdminSrvAdapter interface defined in internal/admin (not services) to avoid import cycle; services.SrvAdapter includes GetAdminStats/GetShardedCache so SrvIface carries both
- NoopSrvAdapter.GetShardedCache() returns nil (safe for test/standalone use — FlushCache nil-guards in Plan 03)
- Phase 6 Plan 03 complete: CreateZone/UpdateZone/DeleteZone/GetZone/ListZones (SourceFile/Compiled/Serial fixed) + CreateRecord/UpdateRecord/DeleteRecord/ListRecords + SetQueryLogging/GetQueryLoggingStatus/SetRateLimit/GetRateLimitStatus all implemented; go build ./... passes
- zone.Zone has no RemoveRecord or ForEachRecord — adminRemoveRecord implemented inline via z.Records map; enumeration uses z.GetAllRecords()
- validateZoneName rejects zone_name containing '/' or '..' before any file I/O (T-06-07 mitigated)
- SetQueryLogging/SetRateLimit return codes.Unimplemented when nil-guarded — Phase 7 wires these; GetQueryLoggingStatus/GetRateLimitStatus return Enabled=false gracefully when nil
- Phase 6 Plan 04 complete: GetMetrics wired to live s.srv.GetAdminStats() (Queries/UDPQueries/TCPQueries/Errors) with nil guard; separate nil guard for s.cache.GetStats() (CacheHits/CacheMisses); ListConnections/KillConnection changed from silent stubs to codes.Unimplemented; 44 firewalld tests pass; go build ./... + go test -race Phase 6 packages exit 0
- GetMetrics nil-guard pattern: if s.srv != nil { srvStats = s.srv.GetAdminStats() }; if s.cache != nil { cacheStats = s.cache.GetStats() } — independent guards satisfy T-06-14
- codes.Unimplemented is the correct gRPC convention for unbuilt features; connection tracking requires transport-layer registry not yet present in miekg/dns or internal/server
- Phase 6 Plan 05 complete: internal/tsig package created (KeyRing, Verify, Sign, ValidateAlgorithm); TsigKeyConfig in config.go; server.Config.TsigKeys + Server.tsigKeyRing; TsigSecret wired on all dns.Server instances; 9 TSIG unit tests pass; go build ./... passes
- tsig.KeyConfig in server.Config uses yaml:"-" — populated by main.go after config load to allow config.TsigKeyConfig→tsig.KeyConfig conversion without import cycle
- GetTsigKeyRing() accessor on Server exposed for Phase 8 AXFR/IXFR signing
- ValidateAlgorithm rejects hmac-md5/sha1; only sha256/384/512 accepted (T-06-17 mitigated)
- TSIG secret never logged; KeyRing has no String/Log method (T-06-16 mitigated)
- miekg/dns auto-verifies TSIG on incoming messages when dns.Server.TsigSecret is populated (T-06-15/T-06-18 mitigated)
- Phase 6 Plan 06 complete: KeyRing.Add/Remove added with sync.RWMutex; TsigSecretMap() returns shared internal map (dns.Server.TsigSecret sees mutations without restart); AddTsigKey/RemoveTsigKey/ListTsigKeys RPCs in admin.proto + admin.Service; GetTsigKeyRing() added to AdminSrvAdapter + services.SrvAdapter + serverSrvAdapter + NoopSrvAdapter; go build ./... + go test -race ./internal/tsig/... exit 0
- Shared map pattern: KeyRing.secrets is assigned to dns.Server.TsigSecret at server creation; Add/Remove mutate this same map under write lock — miekg/dns reads TsigSecret on each TSIG message so changes are immediately visible
- ListTsigKeys returns name+algorithm only; secret intentionally omitted from TsigKeyInfo (T-06-20 mitigated)
