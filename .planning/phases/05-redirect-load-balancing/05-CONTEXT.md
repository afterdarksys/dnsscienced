# Phase 5: Redirect Load Balancing - Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Add an `UpstreamPool` with atomic round-robin selection so both static firewall rules and Starlark `redirect()` distribute queries across multiple upstream DNS targets. No other firewall behavior changes. No health-check or weighted selection (those are v2 requirements REDIR-05/06).

</domain>

<decisions>
## Implementation Decisions

### Starlark API

- **D-01:** `firewall.redirect()` becomes **pool-only** — the `server=` keyword argument is removed entirely.
- **D-02:** If a Starlark script passes `server=` to `firewall.redirect()`, it is a **hard error** at Starlark evaluation time (return an error, fail loudly). No silent ignore. Error message should say something like: `"firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams"`.
- **D-03:** `reason=` kwarg is retained as-is.
- **D-04:** The pool target selected by round-robin is populated into `Decision.Server` before `fw.Redirect()` is called — no change to the Redirect/Forwarder call site, just what `Server` contains.

### Config Shape

- **D-05:** Global upstream pool lives at `firewall.redirect.upstreams: []string` — a new `RedirectConfig` struct nested inside `Config`.
- **D-06:** Config.yaml shape:
  ```yaml
  firewall:
    redirect:
      upstreams:
        - 1.2.3.4:53
        - 5.6.7.8:53
  ```
- **D-07:** `RuleConfig.RedirectServer` (single string) **stays** as a per-rule override. When a static rule has `redirect_server` set, that specific server is used for that rule (bypasses pool). When `redirect_server` is empty, the pool is used.

### Round-Robin Pool

- **D-08:** `UpstreamPool` lives in `internal/firewalld/forwarder.go` (alongside `Forwarder`).
- **D-09:** Selection algorithm: atomic round-robin counter (`sync/atomic` `uint64` counter mod `len(upstreams)`). No locking needed for reads — same pattern as existing atomic counters in `Firewall`.
- **D-10:** Pool is a single shared instance on `*Firewall`, initialized in `New()`. Both the static rule path and Starlark path call `fw.pool.Next()` to get the target server, then set `Decision.Server`.

### Failure Behavior

- **D-11:** When a redirect target is unreachable (timeout, connection refused, etc.), return **SERVFAIL** to the client. This is consistent with the existing `fw.Redirect()` behavior for single-target failures — no behavior change at that layer.
- **D-12:** No retry-on-failure in this phase. REDIR-05/06 (health-check-based removal, weighted selection) are v2 requirements.
- **D-13:** When the pool is empty (no upstreams configured and no rule-level `redirect_server`), return an error from `Next()` and the firewall returns SERVFAIL. Log at error level.

### Claude's Discretion

- Exact struct name for the new config type (`RedirectConfig` seems natural — Claude decides)
- Whether `UpstreamPool` is a struct with a method or a standalone function
- Internal field name on `Firewall` for the pool
- Test helper name for building a firewall with an upstream pool

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing redirect implementation
- `internal/firewalld/forwarder.go` — Forwarder struct, Forward() method, NewForwarder(); UpstreamPool goes here
- `internal/firewalld/firewalld.go` — Firewall struct (pool field goes here), fw.Redirect(), Decision struct (Server field), VerdictRedirect constant
- `internal/firewalld/config.go` — Config struct (add RedirectConfig), RuleConfig.RedirectServer (keep as override)
- `internal/firewalld/starlark.go` — firewall.redirect() builtin at line ~253; remove server= kwarg, add hard error if passed, call fw.pool.Next()
- `internal/firewalld/policy.go` — PolicyEngine.Evaluate() sets Decision.Server from RuleConfig.RedirectServer; update to use pool when RedirectServer is empty

### Prior phase patterns
- `internal/firewalld/edns0.go` — Example of a new helper file in the package
- `internal/firewalld/feed.go` — Example of a goroutine-safe component added in a prior phase
- `internal/firewalld/firewalld_test.go` — Existing test pattern (Config{} struct literal, package-private access)

No external specs — requirements fully captured in decisions above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Forwarder` struct in `forwarder.go` — `UpstreamPool` goes alongside it in the same file; `Forward(r, server)` is already the call site
- Atomic counters on `Firewall` (`totalRedirected atomic.Uint64`) — same pattern for the round-robin counter in `UpstreamPool`
- `fw.Redirect(r, d)` in `firewalld.go` — unchanged; just `d.Server` gets populated differently

### Established Patterns
- Pool selection: `atomic.Uint64` counter, `Next()` returns `upstreams[counter.Add(1) % len(upstreams)]`
- Config structs: plain Go structs with yaml tags, initialized in `DefaultConfig()`
- Test setup: inline `Config{}` struct literal (no `defaultTestConfig()` helper exists)
- Error returns from Starlark builtins: `return nil, fmt.Errorf("firewall.redirect: ...")`

### Integration Points
- `firewalld.go New()` — initialize `UpstreamPool` from `cfg.Redirect.Upstreams`
- `starlark.go` builtin — remove `server=` kwarg; call `fw.pool.Next()` to get server, set on Decision
- `policy.go Evaluate()` — when `cr.cfg.RedirectServer == ""`, call `fw.pool.Next()` instead
- `config.go` — add `RedirectConfig` struct and `Redirect RedirectConfig` field to `Config`

</code_context>

<specifics>
## Specific Ideas

- Config preview confirmed by user:
  ```yaml
  firewall:
    redirect:
      upstreams:
        - 1.2.3.4:53
        - 5.6.7.8:53
    rules:
      - name: legacy-rule
        match: { domain_suffix: .old.example.com }
        action: redirect
        redirect_server: 9.9.9.9:53  # per-rule override, bypasses pool
  ```
- Error message when `server=` is passed to Starlark redirect(): `"firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams"`
- Pool empty → `Next()` returns error → SERVFAIL + error-level log

</specifics>

<deferred>
## Deferred Ideas

- **REDIR-05** (v2): Weighted upstream selection (prefer faster/healthier targets)
- **REDIR-06** (v2): Health-check-based upstream removal — retry-on-failure deliberately NOT in this phase
- Per-Starlark-call pool override (e.g., named pools) — not in scope for v1

</deferred>

---

*Phase: 05-redirect-load-balancing*
*Context gathered: 2026-04-23*
