---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: executing
last_updated: "2026-05-17T09:17:51.843Z"
last_activity: 2026-05-17
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 20
  completed_plans: 20
  percent: 100
---

# State

## Current Position

Phase: 08 (rfc9859-dsync) — EXECUTING
Plan: 2 of 7
Status: Ready to execute
Last activity: 2026-05-17

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23)

**Core value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.
**Current focus:** Phase 08 — rfc9859-dsync

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
- Phase 7 Plan 00 complete: 12 stub test functions created across 3 test files (server_auth_test.go, audit_test.go, service_conn_test.go); all compile and skip; go test ./api/grpc/... ./internal/admin/... exits 0
- server_auth_test.go placed in package server (white-box) for Plan 06 unexported access; service_conn_test.go in package admin_test to avoid import cycle
- Stub-first TDD: t.Skip() stubs registered so Plans 01-06 can use go test -run TestFunctionName in verify blocks before implementation exists
- Phase 7 Plan 01 complete: APIKey struct exported from config.go (ID+Secret yaml tags per D-04); AdminConfig.APIKeys []APIKey + TLS fields; grpcserver.Config.TLSClientCAs + APIKeys []config.APIKey; atomicKeySet with dual keyIndex (secretToID+idSet) per D-05; Lookup(secret)->(id,ok) + IDExists(id) + Len(); go build ./... passes; TestAtomicKeySet + TestAtomicKeyReload + TestConfig_HasTLSClientCAs all PASS
- APIKey.Secret never returned by Lookup — only the id (T-07-01-02 mitigated); keyIndex unexported
- cmd/dnsscience-grpc synthesizes IDs (key-N, cli-N) from legacy []string api-keys config for backwards compat
- Phase 7 Plan 02 complete: buildCreds() replaces credentials.NewServerTLSFromFile; MinVersion:tls.VersionTLS13; mTLS via RequireAndVerifyClientCert+CA pool when TLSClientCAs set; New() fails closed if TLSClientCAs empty (D-02) OR APIKeys empty (D-01); interceptors use atomicKeySet.Lookup() — no bypass; middleware.CtxKeyID{} added; go build ./... passes; 6 new tests PASS
- extractBearer() replaces fmt.Sscanf in authorize() — Sscanf would truncate tokens at spaces; authorize() removed
- AND auth policy: Bearer token ALWAYS required even when mTLS active (D-01: cert proves machine, key proves operator intent)
- Phase 7 Plan 03 complete: callerIdentity(ctx) reads named key id from CtxKeyID context (D-08); falls back to cert CN then "unknown"; remoteAddr(ctx) extracts peer.Addr.String() with nil guard (T-07-03-03); AuditUnaryInterceptor and AuditStreamInterceptor emit all D-07 fields: caller, method, code, latency_ms, remote_addr, timestamp (RFC3339); 9 tests pass; go build ./... passes
- callerIdentity returns "key:"+id (named id per D-08, not hash); never logs raw secret; CtxKeyID was pre-existing from Plan 02 deviation
- Phase 7 Plan 04 complete: ConnRegistry implements grpc stats.Handler; TagConn assigns UUID stored in ctx + registry; HandleConn removes on ConnEnd; EnrichConn updates KeyID+CertCN (D-12) called by auth interceptor (Plan 05); New() returns 4 values (*grpc.Server, net.Listener, *ConnRegistry, error); ListConnections wired to connRegistry.List() with grpcserver.SplitHostPort; KillConnection returns success=false + API limitation message; go build ./... passes; all tests pass
- grpcserver.New() 4-return signature: srv, lis, registry, err := grpcserver.New(cfg, deps); Plan 05 will extend to 5-return with ConfigHolder
- ConnIDFromContext exported for auth interceptor to call registry.EnrichConn(connID, keyID, certCN) in Plan 05
- Chicken-and-egg: connRegistry passed as nil to RegisterAll (Register runs inside New() before registry returned); Plan 05 restructures to pass live registry post-construction
- Phase 7 Plan 05 complete: ConfigHolder type with sync.RWMutex added to server.go; New() updated to 5-return with ConfigHolder; main.go wires TLSCertFile/TLSKeyFile/TLSClientCAs, AuditUnaryInterceptor/AuditStreamInterceptor; SIGHUP loop calls configHolder.Reload() with full config (D-09/D-11); grpcserver.New() error is os.Exit(1); go build ./... passes; all tests pass
- ConfigHolder.Reload() validates D-01/D-02 before swapping; bad config leaves current intact; TLS creds rebuilt only when cert/key/CA paths changed (guard: TLSCertFile+TLSKeyFile both non-empty)
- logging.NewLogger is the correct function name (not logging.New); break sigloop used instead of goto (Go goto restriction across declarations)
- Phase 7 Plan 06 complete: Phase 7 test suite written; all 7 requirements have concrete passing assertions (AUTH-01 through AUTH-04, AUDIT-01, CONN-01, RELOAD-01/02); TestMTLS_NoCert uses ephemeral ecdsa certs; TestAuditInterceptor captures output via bytes.Buffer-backed logging.NewWithWriter; go test ./api/grpc/server/... ./api/grpc/middleware/... ./internal/admin/... exits 0; go build ./... passes
- logging.NewWithWriter(io.Writer) added to logging package for test-time buffer capture; Phase 7 admin-auth-hardening phase complete
- Phase 8 Plan 01 complete: internal/dsync package created; TypeDSYNC=66, DSYNCRecord, EncodeDSYNC/DecodeDSYNC/ParseRFC3597 (hex codec via dns.PackDomainName/UnpackDomainName); NotifyLimiter with per-IP token bucket (x/time/rate), background sweepStale() goroutine (5min sweep, 10min TTL), sync.Once Close(); 10 tests pass; go build/test ./internal/dsync/... exits 0
- TypeDSYNC=66: miekg/dns v1.1.72 does not define it; defined in internal/dsync (verified by direct grep of installed module)
- DSYNCRecord plain struct codec (not dns.RR interface); EncodeDSYNC returns hex string for dns.RFC3597.Rdata; DecodeDSYNC minimum 6-byte length check before any field access (T-08-01 mitigated)
- NotifyLimiter.Close() uses sync.Once — safe for defer + explicit call patterns without double-close panic (T-08-02: sweepStale evicts visitors lastSeen > 10min)
- Test helpers exported on NotifyLimiter: ForceLastSeen, SweepStaleForTest, VisitorCount for white-box eviction testing
- Phase 8 Plan 02 complete: Handler(Allower, NotifyLimiter, zerolog.Logger) with ACL-first/rate-limit-second REFUSED guards; AllowAllACL() stub satisfies Allower interface (Plan 05 replaces); scheduleDelegationCheck stub (log only); DiscoverDSYNC traverses _dsync.<zone> parent labels (RFC 9859 s3), bounded loop, malformed skipped; DSYNCNotifier buffered channel(64) non-blocking Notify(); sendNotify SetNotify+Qtype override SOA->CDS/CSYNC; 26 tests pass; go build/test ./internal/dsync/... exits 0
- Allower interface Check(net.IP) bool: NewHandler signature is FINAL — Plan 05 provides SourceACL satisfying this; Plan 03 uses AllowAllACL() as default
- HandleInbound order: empty question -> FormatError; ACL -> REFUSED; rate limit -> REFUSED; then NOERROR + async goroutine (CDS/CSYNC only)
- DiscoverDSYNC loop: len(labels)-1 bound (T-08-05); returns all records from first candidate with results
- sendNotify: m.SetNotify(zone) then m.Question[0].Qtype = qtype (override SOA); strings.TrimSuffix(target, ".") before JoinHostPort
- Phase 8 Plan 03 complete: ZoneDSYNCConfig + DSYNCConfig structs YAML-parseable; DSYNC field on server.Config + ZoneConfig; dsyncHandler *dsync.Handler field on Server; New() initializes with rpm/burst defaults (D-13/T-08-10); handleDNS opcode dispatch before pool/defensive (T-08-09); 3 integration tests pass; go build ./... passes
- NOTIFY opcode dispatch: inserted at top of handleDNS, BEFORE pool.GetMessage and defensive.CheckBlackhole — NOTIFY must short-circuit before all query processing
- pool.PutMessage resets Rcode: testResponseWriter must capture Rcode int in WriteMsg (not hold *dns.Msg pointer) to survive defer reset
- dsyncHandler logger: zerolog.Nop() — Server has no logger field; avoids scope creep without disrupting Phase 8 scope
- Phase 8 Plan 04 complete: internal/zone/parser_dsync_test.go created; TestDSYNCZoneFile_BIND (single TYPE66 record via miekg/dns RFC3597 fallback) and TestDSYNCZoneFile_MultipleRecords (two TYPE66 records) both PASS; all 5 build/test gate commands confirmed by human verification (go build./..., dsync codec, NOTIFY dispatch, zone file loading); two pre-existing failures in internal/engine and internal/resolver are documented non-regressions
- miekg/dns ParseBIND automatically uses dns.RFC3597 for TYPE66 (unknown-type RFC3597 fallback); no production code changes needed in zone package — DSYNC zone file support was already functional
- Zone file test vector: 003b0100350161016200 = CDS(59), NOTIFY(1), port 53(0x0035), target a.b. (wire: 016101 6200); use simplified target to keep hex short
- Phase 8 Plan 05 complete: SourceACL{networks, allowAll} satisfies Allower (compile-time var _ Allower = (*SourceACL)(nil)); WebhookClient fire-and-forget POST (json/base64) with configurable timeout; Handler.webhook field + SetWebhook() setter (NewHandler unchanged); ZoneDSYNCConfig extended with WebhookURL/WebhookBodyFormat/AllowedSources/RateLimitPerMin; 10 new tests pass; go build ./internal/dsync/... ./internal/config/... ./internal/server/... passes
- SetWebhook setter pattern: NewHandler signature is FINAL from Plan 02; webhook wired post-construction via SetWebhook (no constructor change)
- Empty CIDR allowlist = accept all sources (D-05); invalid CIDRs silently skipped (T-08-16)
- Webhook goroutine bounded by rate limiter throughput (T-08-15); Fire() no-op when URL empty (D-02)
- Phase 8 Plan 06 complete: DSYNCMetrics (3x prometheus.CounterVec: inbound/outbound/webhook) created; Handler.SetMetrics/DSYNCNotifier.SetMetrics wired; OutboundSent counter incremented INSIDE worker after sendNotify (not at RPC enqueue site); DSYNCAdminService + SendDSYNCNotify RPC added to admin.proto + code generated; DSYNCService validates zone_name and qtype (CDS/CSYNC only); RegisterAll extended with variadic dsyncNotifier for conditional registration; go build ./... passes; all tests pass
- SetMetrics setter pattern mirrors SetWebhook — constructor signatures remain stable, metrics injected post-construction
- OutboundSent location is critical (D-10): counter must reflect actual send results, not enqueue events
- RegisterAll variadic extension: backward-compatible; existing callers without dsyncNotifier arg skip DSYNC registration
- Strict qtype validation: "CDS" and "CSYNC" only (case-sensitive); any other value returns InvalidArgument (T-08-20)
- DSYNC-07 (Prometheus metrics) and DSYNC-08 (Admin RPC) requirements complete; Phase 8 rfc9859-dsync fully delivered
