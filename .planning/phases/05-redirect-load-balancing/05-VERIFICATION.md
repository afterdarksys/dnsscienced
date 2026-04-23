---
phase: 05-redirect-load-balancing
verified: 2026-04-23T19:47:00Z
status: passed
score: 13/13 must-haves verified
overrides_applied: 0
---

# Phase 5: Redirect Load Balancing — Verification Report

**Phase Goal:** Redirect verdicts (both static rules and Starlark) are distributed across a configured pool of upstream DNS targets using round-robin selection.
**Verified:** 2026-04-23T19:47:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | UpstreamPool.Next() returns upstreams in round-robin order for two-upstream pool | VERIFIED | forwarder.go:80 — `(p.counter.Add(1) - 1) % uint64(len(p.upstreams))`; TestUpstreamPool_RoundRobin passes |
| 2 | UpstreamPool.Next() returns an error when pool is empty | VERIFIED | forwarder.go:77-79 — empty check + fmt.Errorf; TestUpstreamPool_EmptyPool + TestUpstreamPool_Empty pass |
| 3 | UpstreamPool.Next() always returns the sole entry for a single-upstream pool | VERIFIED | forwarder.go:80 — modulo 1 always yields 0; TestUpstreamPool_SingleUpstream passes |
| 4 | RedirectConfig{Upstreams []string} is present on Config with yaml:"redirect" tag | VERIFIED | config.go:29 `Redirect RedirectConfig \`yaml:"redirect"\``; config.go:135-140 struct definition |
| 5 | Firewall.New() initializes pool from cfg.Redirect.Upstreams | VERIFIED | firewalld.go:137 `pool := newUpstreamPool(cfg.Redirect.Upstreams)` |
| 6 | Firewall.New() returns an error when any redirect rule has no redirect_server and the pool is empty | VERIFIED | firewalld.go:140-146 validation block; TestNew_EmptyPoolWithPoolRedirectRule passes |
| 7 | Firewall.Check() calls pool.Next() when policy returns VerdictRedirect with empty Server; logs error and returns SERVFAIL decision when pool is empty | VERIFIED | firewalld.go:200-211 pool-fill block with SERVFAIL path; TestStaticRedirectRule_UsesPool passes |
| 8 | Starlark firewall.redirect() with no args calls pool.Next() and sets Decision.Server | VERIFIED | starlark.go:271 `server, err := se.pool.Next()`; TestStarlarkRedirect_UsesPool passes |
| 9 | Starlark firewall.redirect(server=...) returns a hard error at evaluation time | VERIFIED | starlark.go:258-263 kwarg scan before UnpackArgs; TestStarlarkRedirect_ServerArgRejected passes |
| 10 | Starlark firewall.redirect(reason='...') retains reason in Decision.Reason | VERIFIED | starlark.go:275-278 reason handling; TestStarlarkRedirect_UsesPool asserts `assert.Equal(t, "pool test", d.Reason)` |
| 11 | Static redirect rule with empty redirect_server uses pool.Next() via Check() (compileRule no longer rejects empty redirect_server) | VERIFIED | policy.go:70-72 — no guard; TestStaticRedirectRule_UsesPool passes |
| 12 | Static redirect rule with non-empty redirect_server bypasses pool (per-rule override) | VERIFIED | firewalld.go:200 — `d.Server == ""` guard means non-empty Server skips pool.Next(); TestStaticRedirectRule_PerRuleOverride passes |
| 13 | go test ./internal/firewalld/... -count=1 -race exits 0 | VERIFIED | 43 tests pass with -race, exit 0 |

**Score:** 13/13 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/firewalld/forwarder.go` | UpstreamPool struct + newUpstreamPool() + Next() | VERIFIED | lines 63-82; atomic.Uint64 counter; round-robin via (Add(1)-1)%len |
| `internal/firewalld/config.go` | RedirectConfig struct + Redirect field on Config | VERIFIED | line 135 struct; line 29 Config field with yaml:"redirect" |
| `internal/firewalld/firewalld.go` | pool field on Firewall, initialization in New(), pool-empty SERVFAIL in Check() | VERIFIED | line 92 field; line 137 init; line 166 starlark.pool=pool; lines 200-211 Check() path |
| `internal/firewalld/starlark.go` | StarlarkEngine.pool field; updated redirect builtin | VERIFIED | line 37 `pool *UpstreamPool`; lines 254-281 new redirect builtin |
| `internal/firewalld/policy.go` | compileRule no longer rejects empty redirect_server | VERIFIED | lines 70-72 — no guard, comment explains pool provides target |
| `internal/firewalld/firewalld_test.go` | UpstreamPool unit tests + REDIR-03/04 integration tests | VERIFIED | 7 new test functions present; TestRedirect_PoolBehavior_RED at line 540, TestUpstreamPool_Empty at 569, 5 integration tests |
| `internal/firewalld/forwarder_test.go` | TestUpstreamPool_RoundRobin + TestUpstreamPool_SingleUpstream + TestUpstreamPool_EmptyPool | VERIFIED | lines 8, 20, 34 — all three functions present |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| firewalld.go New() | forwarder.go newUpstreamPool() | `pool := newUpstreamPool(cfg.Redirect.Upstreams)` | WIRED | firewalld.go:137 |
| firewalld.go Check() | forwarder.go UpstreamPool.Next() | `fw.pool.Next()` when VerdictRedirect + empty Server | WIRED | firewalld.go:201 |
| starlark.go buildFirewallModuleWithSink() | forwarder.go UpstreamPool.Next() | `se.pool.Next()` in redirect builtin | WIRED | starlark.go:271 |
| firewalld.go New() | starlark.go StarlarkEngine.pool | `starlark.pool = pool` post-construction setter | WIRED | firewalld.go:166 |

### Data-Flow Trace (Level 4)

Not applicable — this phase produces no components that render dynamic data. All artifacts are internal engine components (upstream pool selection, config structs, Starlark builtins) verified by direct test assertions that the correct server addresses flow into Decision.Server.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Build compiles clean | `go build ./internal/firewalld/...` | exit 0 | PASS |
| Full test suite with race detector | `go test ./internal/firewalld/... -count=1 -race` | 43 tests pass, exit 0 | PASS |
| Redirect pool tests pass | `-run "TestUpstreamPool\|TestStarlarkRedirect\|TestStaticRedirect\|TestNew_EmptyPool\|TestRedirect_PoolBehavior"` | 9 tests pass | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| REDIR-01 | 05-01 | Operator can configure multiple upstream redirect targets in config.yaml | SATISFIED | RedirectConfig.Upstreams []string yaml:"upstreams"; Config.Redirect yaml:"redirect"; config.go:29+135 |
| REDIR-02 | 05-01 | Forwarder selects among configured targets using round-robin | SATISFIED | UpstreamPool.Next() atomic round-robin; forwarder.go:80; TestUpstreamPool_RoundRobin passes |
| REDIR-03 | 05-02 | Starlark redirect() call uses the load-balanced upstream pool | SATISFIED | se.pool.Next() in redirect builtin; starlark.go:271; TestStarlarkRedirect_UsesPool passes |
| REDIR-04 | 05-02 | Static rule VerdictRedirect uses the same upstream pool | SATISFIED | fw.pool.Next() in Check() when d.Server==""; firewalld.go:201; TestStaticRedirectRule_UsesPool passes |

All 4 requirement IDs from plan frontmatter (REDIR-01 through REDIR-04) are satisfied. REQUIREMENTS.md traceability table marks all four as Complete (05-01/05-02). No orphaned requirements detected.

### Anti-Patterns Found

No blockers or warnings found. Scanned all modified files:

- `internal/firewalld/forwarder.go` — no TODOs, no stub returns, no hardcoded empty data
- `internal/firewalld/config.go` — no TODOs, Upstreams empty-slice default is intentional (D-13: empty pool triggers error at runtime, not a stub)
- `internal/firewalld/firewalld.go` — no TODOs, SERVFAIL path is a real error response not a stub
- `internal/firewalld/starlark.go` — comment on line 24 (`firewall.redirect(server="1.2.3.4:5353", reason="...")`) is doc-comment for old API, does not affect behavior
- `internal/firewalld/policy.go` — no TODOs
- `internal/firewalld/firewalld_test.go` — all new test functions contain real assertions

### Human Verification Required

None. All phase goal truths are verifiable programmatically. The ROADMAP success criteria for Phase 5 are:

1. With two upstreams configured, repeated redirect queries cycle between both targets — verified by TestUpstreamPool_RoundRobin and TestStarlarkRedirect_UsesPool / TestStaticRedirectRule_UsesPool (assertions that Server is in the configured pool; round-robin order covered by forwarder_test.go)
2. Static rule VerdictRedirect uses pool — verified by TestStaticRedirectRule_UsesPool
3. Starlark redirect() uses same pool — verified by TestStarlarkRedirect_UsesPool
4. Single upstream behaves identically — verified by TestUpstreamPool_SingleUpstream

### Gaps Summary

No gaps. All must-haves from both plan frontmatter files are verified at all levels (artifact exists, substantive implementation, wired, data flows through correct path). The full test suite (43 tests) passes with -race, confirming no concurrency issues in the atomic round-robin counter.

---

_Verified: 2026-04-23T19:47:00Z_
_Verifier: Claude (gsd-verifier)_
