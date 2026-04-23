# State

## Current Position

Phase: 4 — EDNS0 CustomerID
Plan: —
Status: Ready to plan — Phase 4 context captured; awaiting /gsd-plan-phase 4
Last activity: 2026-04-23 — Phase 4 context gathered (option code 65000, extraction inside Check(), 64-byte cap, debug log on oversized)

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23)

**Core value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.
**Current focus:** v1.1 — dnsfirewalld Completion

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
