# Phase 5: Redirect Load Balancing - Research

**Researched:** 2026-04-23
**Domain:** Go atomic round-robin pool, DNS firewall policy integration
**Confidence:** HIGH

## Summary

Phase 5 adds an `UpstreamPool` struct to `internal/firewalld/forwarder.go` that selects among configured upstream DNS targets using an atomic round-robin counter. Both the static rule path (PolicyEngine.Evaluate) and the Starlark path (firewall.redirect builtin) are updated to call `fw.pool.Next()` to populate `Decision.Server` before `fw.Redirect()` is called — the Redirect/Forwarder call site itself is unchanged. A `RedirectConfig` struct is nested inside `Config` at `firewall.redirect.upstreams: []string` in YAML. The per-rule `RuleConfig.RedirectServer` override is preserved; when set, it bypasses the pool.

The implementation surface is small and entirely self-contained within the `internal/firewalld` package. No new external dependencies are required. All decisions are locked; no alternatives remain to evaluate.

**Primary recommendation:** Add `UpstreamPool` to `forwarder.go`, add `RedirectConfig` + `Redirect RedirectConfig` to `config.go`, wire the pool in `New()`, update the three call sites (starlark builtin, policy.Evaluate, check in New when pool is empty), and add targeted unit tests.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Starlark API**
- D-01: `firewall.redirect()` becomes pool-only — the `server=` keyword argument is removed entirely.
- D-02: Passing `server=` to `firewall.redirect()` is a hard error at evaluation time. Error message: `"firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams"`.
- D-03: `reason=` kwarg is retained as-is.
- D-04: Pool target selected by round-robin is populated into `Decision.Server` before `fw.Redirect()` is called — no change to the Redirect/Forwarder call site.

**Config Shape**
- D-05: Global upstream pool lives at `firewall.redirect.upstreams: []string` — a new `RedirectConfig` struct nested inside `Config`.
- D-06: Config YAML shape confirmed (see Specifics section).
- D-07: `RuleConfig.RedirectServer` stays as per-rule override; bypasses pool when set; pool used when empty.

**Round-Robin Pool**
- D-08: `UpstreamPool` lives in `internal/firewalld/forwarder.go`.
- D-09: Selection: `sync/atomic` `uint64` counter mod `len(upstreams)`.
- D-10: Single shared pool instance on `*Firewall`, initialized in `New()`.

**Failure Behavior**
- D-11: Unreachable target → SERVFAIL (existing `fw.Redirect()` behavior, no change).
- D-12: No retry-on-failure in this phase.
- D-13: Empty pool → `Next()` returns error → SERVFAIL + error-level log.

### Claude's Discretion
- Exact struct name for the new config type (`RedirectConfig` seems natural)
- Whether `UpstreamPool` is a struct with a method or a standalone function
- Internal field name on `Firewall` for the pool
- Test helper name for building a firewall with an upstream pool

### Deferred Ideas (OUT OF SCOPE)
- REDIR-05: Weighted upstream selection
- REDIR-06: Health-check-based upstream removal
- Per-Starlark-call pool override (named pools)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REDIR-01 | Operator can configure multiple upstream redirect targets in config.yaml | Add `RedirectConfig{Upstreams []string}` to `Config`; nest under `firewall.redirect.upstreams` in YAML |
| REDIR-02 | Forwarder selects among configured targets using round-robin | `UpstreamPool` with `atomic.Uint64` counter in `forwarder.go`; `Next()` returns `upstreams[counter.Add(1) % len]` |
| REDIR-03 | Starlark redirect() call uses the load-balanced upstream pool | Remove `server=` kwarg from builtin; call `fw.pool.Next()` to get server, set on Decision |
| REDIR-04 | Static rule VerdictRedirect uses the same upstream pool | In `policy.Evaluate()`, when `cr.cfg.RedirectServer == ""`, call `fw.pool.Next()` |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Upstream selection | API / Backend (firewalld package) | — | Pure server-side routing decision; no client involvement |
| Config parsing | API / Backend (config.go) | — | YAML struct; existing pattern in same file |
| Round-robin counter | API / Backend (forwarder.go) | — | Lives alongside Forwarder per D-08 |
| Starlark API surface | API / Backend (starlark.go) | — | Builtin modification; execution is in-process |
| Static rule path | API / Backend (policy.go) | — | PolicyEngine.Evaluate already owns redirect decision |

---

## Standard Stack

### Core (all already in go.mod — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sync/atomic` stdlib | Go 1.25 (in go.mod) | Atomic `uint64` counter for round-robin | Lock-free, zero allocation; matches existing `atomic.Uint64` pattern on `Firewall` struct [VERIFIED: codebase read] |
| `fmt` stdlib | Go 1.25 | Error formatting from `Next()` | Already imported everywhere [VERIFIED: codebase read] |
| `github.com/miekg/dns` | already in go.mod | DNS message types used at Forwarder call site | No change [VERIFIED: codebase read] |

### No New Dependencies

This phase requires zero new `go get` calls. All needed packages are stdlib or already declared in `go.mod`. [VERIFIED: codebase read of forwarder.go, firewalld.go, config.go]

**Installation:** None required.

---

## Architecture Patterns

### System Architecture Diagram

```
DNS Query (inbound)
       |
       v
  Firewall.Check()
       |
  ┌────┴──────────────────────┐
  │  1. PolicyEngine.Evaluate │
  │     cr.cfg.RedirectServer │
  │       != ""  ─────────────┼──> Decision{Server: RedirectServer}  (per-rule override)
  │       == ""  ─────────────┼──> fw.pool.Next() ──> Decision{Server: poolTarget}
  └────────────────────────────┘
       |
  ┌────┴──────────────────────┐
  │  2-4. Junk / Intel / ...  │  (unchanged)
  └────────────────────────────┘
       |
  ┌────┴──────────────────────┐
  │  5. StarlarkEngine.Run()  │
  │     firewall.redirect()   │
  │       server= kwarg ──────┼──> hard error (D-02)
  │       no server= kwarg ───┼──> fw.pool.Next() ──> Decision{Server: poolTarget}
  └────────────────────────────┘
       |
   VerdictRedirect
       |
       v
  Firewall.Redirect(r, d)      ← unchanged; d.Server is already populated
       |
       v
  Forwarder.Forward(r, d.Server)
       |
   upstream DNS target (round-robin selected)
```

```
UpstreamPool (in forwarder.go):
  upstreams []string            ← from cfg.Redirect.Upstreams
  counter   atomic.Uint64

  Next() (string, error):
    if len(upstreams) == 0 → return "", error
    idx = counter.Add(1) % uint64(len(upstreams))
    return upstreams[idx], nil
```

### Recommended Project Structure

No new files required beyond what the decisions specify. Changes are edits to existing files plus one possible new test helper in `firewalld_test.go`.

```
internal/firewalld/
├── forwarder.go     ← ADD: UpstreamPool struct + Next() method
├── config.go        ← ADD: RedirectConfig struct + Redirect field on Config + DefaultConfig update
├── firewalld.go     ← ADD: pool field on Firewall; initialize in New()
├── policy.go        ← EDIT: Evaluate() — call pool.Next() when RedirectServer is empty
├── starlark.go      ← EDIT: redirect builtin — remove server= kwarg, add hard error, call pool.Next()
└── firewalld_test.go ← ADD: UpstreamPool unit tests + integration tests
```

### Pattern 1: UpstreamPool — atomic round-robin

**What:** A struct holding a slice of upstream addresses and an atomic counter. `Next()` is safe for concurrent use without locks.

**When to use:** Any time a redirect decision needs a target address; called from both the static rule path and the Starlark path.

**Example (canonical form per D-09 + existing codebase pattern):**

```go
// Source: CONTEXT.md D-09 + existing atomic.Uint64 pattern in firewalld.go
type UpstreamPool struct {
    upstreams []string
    counter   atomic.Uint64
}

// newUpstreamPool creates a pool from cfg slice. nil/empty slice is valid —
// Next() will return an error, which the caller turns into SERVFAIL (D-13).
func newUpstreamPool(upstreams []string) *UpstreamPool {
    return &UpstreamPool{upstreams: upstreams}
}

// Next returns the next upstream address via atomic round-robin.
// Returns an error when the pool is empty (D-13).
func (p *UpstreamPool) Next() (string, error) {
    if len(p.upstreams) == 0 {
        return "", fmt.Errorf("upstream pool is empty — configure firewall.redirect.upstreams")
    }
    idx := p.counter.Add(1) % uint64(len(p.upstreams))
    return p.upstreams[idx], nil
}
```

[VERIFIED: matches atomic.Uint64 usage on Firewall struct in firewalld.go lines 99-103]

### Pattern 2: RedirectConfig in config.go

**What:** New nested struct with YAML tag, added to Config and DefaultConfig.

**Example (canonical form per D-05/06):**

```go
// Source: CONTEXT.md D-05/D-06 + existing ThreatIntelConfig pattern in config.go
type RedirectConfig struct {
    // Upstreams is the list of upstream DNS targets for redirect load balancing.
    // Each entry is "ip:port". At least one entry is required for redirect verdicts
    // that do not have a per-rule redirect_server override.
    Upstreams []string `yaml:"upstreams"`
}
```

Add to `Config` struct:

```go
// Redirect holds upstream pool configuration for VerdictRedirect.
Redirect RedirectConfig `yaml:"redirect"`
```

`DefaultConfig()` does not need a non-zero default for `Redirect.Upstreams` — empty slice is valid and produces SERVFAIL with an error log when redirect is attempted (D-13). [VERIFIED: DefaultConfig() in config.go]

### Pattern 3: Starlark builtin — remove server= kwarg, hard error on server= present

**What:** Replace the current `server` positional/kwarg with detection of `server=` as an error, keep `reason?`.

**Key insight from existing code:** The current builtin uses `starlark.UnpackArgs("firewall.redirect", args, kwargs, "server", &server, "reason?", &reason)`. The new version must accept zero positional args, detect `server=` in kwargs, and error if found.

**Example (canonical form per D-01/D-02/D-03):**

```go
// Source: CONTEXT.md D-01/D-02/D-03 + existing builtin pattern in starlark.go lines 253-271
"redirect": starlark.NewBuiltin("firewall.redirect", func(
    _ *starlark.Thread, _ *starlark.Builtin,
    args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
    // D-02: hard error if caller passes server=
    for _, kv := range kwargs {
        if string(kv[0].(starlark.String)) == "server" {
            return nil, fmt.Errorf("firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams")
        }
    }
    var reason starlark.String
    if err := starlark.UnpackArgs("firewall.redirect", args, kwargs,
        "reason?", &reason); err != nil {
        return nil, err
    }
    // D-04: pool.Next() populates Server on Decision
    server, err := fw.pool.Next()
    if err != nil {
        return nil, fmt.Errorf("firewall.redirect: %w", err)
    }
    r := "starlark policy"
    if string(reason) != "" {
        r = string(reason)
    }
    sink.set(&Decision{Verdict: VerdictRedirect, Server: server, Reason: r})
    return starlark.None, nil
}),
```

**Critical complication:** `buildFirewallModuleWithSink` is currently on `*StarlarkEngine`, which has no reference to `*Firewall` and therefore no access to `fw.pool`. The pool reference must be threaded in. Two options:

1. Add a `pool *UpstreamPool` field to `StarlarkEngine` set during `newStarlarkEngine` or via a setter — cleaner isolation.
2. Pass `fw.pool` as a parameter to `buildFirewallModuleWithSink` — simpler but more verbose.

**Recommendation (Claude's discretion):** Option 1 — add `pool *UpstreamPool` to `StarlarkEngine`. Set it in `firewalld.go New()` after pool initialization: `starlark.pool = fw.pool`. This is the same pattern as how `StarlarkEngine` already owns its `timeout`. [ASSUMED — either approach is valid; this is the tidiest]

### Pattern 4: policy.go Evaluate() — pool fallback

**What:** When a static rule has `redirect` action and `RedirectServer == ""`, call `fw.pool.Next()`. Problem: `PolicyEngine` currently has no reference to the pool either.

**Options (parallel to Starlark issue):**

1. Add `pool *UpstreamPool` to `PolicyEngine`, set in `newPolicyEngine` or via the Firewall.
2. Populate `Decision.Server` in `Firewall.Check()` after `policy.Evaluate()` returns — if verdict is VerdictRedirect and Server is "", call `fw.pool.Next()`.

**Recommendation (Claude's discretion):** Option 2 — post-process in `Check()`. This avoids threading pool into both `PolicyEngine` and `StarlarkEngine`, keeps both engines free of pool knowledge, and centralizes the "ensure Decision.Server is populated" logic in one place. The flow becomes:

```go
// In Check() after fw.policy.Evaluate(qctx):
if d := fw.policy.Evaluate(qctx); d.Verdict != VerdictAllow {
    if d.Verdict == VerdictRedirect && d.Server == "" {
        server, err := fw.pool.Next()
        if err != nil {
            fw.logger.Error().Err(err).Msg("redirect pool empty")
            fail := new(dns.Msg)
            fail.SetReply(r)
            fail.Rcode = dns.RcodeServerFailure
            return &Decision{Verdict: VerdictDrop} // or synthesize inline
        }
        d.Server = server
    }
    return fw.record(d, qctx)
}
```

However, SERVFAIL must be returned to the client — `Check()` returns a `*Decision`, not a `*dns.Msg`. The caller handles VerdictRedirect by calling `fw.Redirect()`. So the correct approach for empty-pool-at-static-rule time is: set a sentinel verdict or let `fw.Redirect()` handle the error. Looking at the existing code, `fw.Redirect()` already returns SERVFAIL on forward error (lines 258-265 in firewalld.go). Therefore the cleanest path is:

- `policy.Evaluate()` sets `Decision.Server = ""` when `RedirectServer == ""` (already the case — `Server: cr.cfg.RedirectServer` in Evaluate at line 93)
- In `Check()`, after policy.Evaluate returns VerdictRedirect with Server == "", call `fw.pool.Next()` and set `d.Server`. If pool returns error, log at error level and return a SERVFAIL decision directly (D-13). A `VerdictDrop` would silently discard; instead return the SERVFAIL inline using a new decision with a marker, OR simply call `fw.record()` with a SERVFAIL-like decision and let the caller deal with it.

**Cleanest D-13 implementation:** Introduce a `VerdictServFail` verdict, or re-use the existing SERVFAIL path that `fw.Redirect()` already produces. The simplest approach: return `&Decision{Verdict: VerdictRedirect, Server: ""}` from Check and let `fw.Redirect()` attempt `Forward(r, "")` which will fail and produce SERVFAIL — but that logs a confusing "forward to :53 failed" message. Better: Check() inlines the SERVFAIL construction when pool.Next() fails. [ASSUMED — Claude decides; the inline approach in Check() with explicit error log is cleanest per D-13]

**Revised simplified recommendation:** Add `pool *UpstreamPool` to `PolicyEngine` — set it from `Firewall.New()` via a setter or constructor parameter — and in `compileRule`, allow `redirect` action with empty `RedirectServer` (currently a compile-time error at line 71-73 of policy.go). Then in `Evaluate()`, when `cr.cfg.RedirectServer == ""`, call `pe.pool.Next()`. This keeps the pool-empty error at the exact right layer. [ASSUMED — either approach works; planner should choose one and lock it]

**Critical policy.go change:** Line 71-73 of policy.go currently requires `redirect_server` to be non-empty:
```go
case "redirect":
    if r.RedirectServer == "" {
        return cr, fmt.Errorf("redirect action requires redirect_server")
    }
```
This validation MUST be relaxed when `upstreams` are configured. The new rule: redirect is valid if `RedirectServer != ""` OR pool upstreams are configured. But `compileRule` has no pool reference at compile time — it just validates config. The simplest fix: **remove the hard error** for empty `RedirectServer` in `compileRule`, and defer validation to runtime when the verdict fires. Or validate at `New()` time: if any rule has `action: redirect` and `redirect_server: ""` and `cfg.Redirect.Upstreams` is empty, return an error from `New()`. [VERIFIED: policy.go line 71-73]

### Anti-Patterns to Avoid

- **Locking in Next():** `atomic.Uint64.Add()` is already atomic; no `sync.Mutex` needed. The existing `Firewall` pattern uses `atomic.Uint64` directly without locks. [VERIFIED: firewalld.go lines 99-103]
- **Copying the upstreams slice in Next():** The pool is initialized once in `New()` and never mutated, so no copy is needed.
- **Passing `server=` silently:** D-02 is a hard error. Silent ignore would hide operator config mistakes.
- **Retrying on failure:** D-12 explicitly prohibits retry-on-failure. Return SERVFAIL immediately.
- **Empty pool returning a zero-value string:** Must return `("", error)` — not `("", nil)` — so callers can distinguish "no upstreams" from a valid address.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Atomic counter | Custom mutex-based counter | `sync/atomic` `atomic.Uint64.Add()` | Already the codebase pattern; zero-allocation, race-free [VERIFIED: firewalld.go] |
| Thread-safe module building | Per-goroutine copies of builtin | `decisionSink` + `buildFirewallModuleWithSink` per query | Already implemented; just extend the pattern [VERIFIED: starlark.go] |

**Key insight:** Everything needed is already in the standard library or already in the codebase. The entire implementation is additive plumbing of existing patterns.

---

## Runtime State Inventory

Step 2.5: SKIPPED — this is a greenfield feature addition, not a rename/refactor/migration phase.

---

## Environment Availability Audit

Step 2.6: No external dependencies. All tools are stdlib Go.

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Go toolchain | Build | ✓ | go 1.25.0 | — |
| `go test ./internal/firewalld/...` | Validation | ✓ | 31 tests pass [VERIFIED: test run] | — |

---

## Common Pitfalls

### Pitfall 1: compileRule rejects redirect rules without redirect_server

**What goes wrong:** Existing validation at `policy.go:71-73` returns an error for any `redirect` rule that lacks `redirect_server`. After Phase 5, operators may configure redirect rules that rely on the pool, leaving `redirect_server` empty. `New()` would fail with "redirect action requires redirect_server".

**Why it happens:** The v1.0 implementation assumed a single upstream was always specified per-rule.

**How to avoid:** Relax the validation in `compileRule` — remove the `redirect_server != ""` requirement. Add a different validation gate in `New()`: if any rule has `action: redirect` + empty `redirect_server`, ensure `cfg.Redirect.Upstreams` is non-empty; if both are empty, return an error from `New()`.

**Warning signs:** `New()` returns "redirect action requires redirect_server" when operator omits `redirect_server` from a rule intending to use the pool.

### Pitfall 2: Starlark builtin still accepts server= during compilation

**What goes wrong:** `buildFirewallModule()` (used during compilation at `Load()`) builds the module with a no-op sink. If the kwarg-detection logic isn't present in this stub, scripts that pass `server=` will compile successfully but fail at runtime. This is acceptable per D-02 (error is at evaluation time, not compile time), but tests must exercise runtime evaluation.

**Why it happens:** Starlark scripts are compiled without running; builtins only execute at query time.

**How to avoid:** The hard error in the builtin body fires at runtime (evaluation time) which is correct per D-02. Tests should verify this: load a script that calls `redirect(server="1.2.3.4")` and run it against a query — expect an error from `se.runOne()`.

**Warning signs:** No test coverage for the `server=` rejection path.

### Pitfall 3: Off-by-one in round-robin index

**What goes wrong:** Using `counter.Add(1) % len` with a starting counter of 0 means the first call returns index 1, not 0. This is fine for distribution purposes but may surprise tests that expect the first call to return `upstreams[0]`.

**Why it happens:** `atomic.Uint64` starts at 0; `Add(1)` returns 1; `1 % 2 = 1`.

**How to avoid:** Tests should verify distribution across N calls, not expect a specific first index. OR start the counter at `maxUint64` so the first Add(1) overflows to 0 — but overflow semantics require care. Simplest: document that the first call returns `upstreams[1 % len]` and write tests accordingly, OR subtract 1: `idx = (counter.Add(1) - 1) % uint64(len)` to get 0-based first call.

**Recommendation:** Use `(counter.Add(1) - 1) % uint64(len(upstreams))` so `upstreams[0]` is returned on the first call. This is cleaner for tests. [ASSUMED — either works for actual load balancing]

### Pitfall 4: Pool reference threading through StarlarkEngine

**What goes wrong:** `buildFirewallModuleWithSink` is called inside `runOne`, which is called from `StarlarkEngine.Run()`. If pool is not accessible from `StarlarkEngine`, the builtin cannot call `pool.Next()`.

**Why it happens:** `StarlarkEngine` was designed without pool awareness.

**How to avoid:** Add `pool *UpstreamPool` field to `StarlarkEngine`. Set it in `New()` after both engine and pool are created: `se.pool = fw.pool` (or pass pool to `newStarlarkEngine` — but that changes the existing signature). A post-construction setter keeps `newStarlarkEngine` signature stable. [ASSUMED — Claude decides]

---

## Code Examples

### Full UpstreamPool (verified against codebase patterns)

```go
// Source: CONTEXT.md D-08/D-09 + firewalld.go atomic.Uint64 pattern [VERIFIED]
// In forwarder.go

type UpstreamPool struct {
    upstreams []string
    counter   atomic.Uint64
}

func newUpstreamPool(upstreams []string) *UpstreamPool {
    return &UpstreamPool{upstreams: upstreams}
}

// Next returns the next upstream address via round-robin.
// Returns ("", error) when the pool is empty (caller must return SERVFAIL per D-13).
func (p *UpstreamPool) Next() (string, error) {
    if len(p.upstreams) == 0 {
        return "", fmt.Errorf("upstream pool is empty — configure firewall.redirect.upstreams")
    }
    idx := (p.counter.Add(1) - 1) % uint64(len(p.upstreams))
    return p.upstreams[idx], nil
}
```

### Config additions (verified against config.go pattern)

```go
// Source: config.go existing struct pattern [VERIFIED]
type RedirectConfig struct {
    Upstreams []string `yaml:"upstreams"`
}

// Add to Config struct:
Redirect RedirectConfig `yaml:"redirect"`
```

### New() initialization (verified against firewalld.go)

```go
// Source: firewalld.go New() lines 142-161 [VERIFIED]
// In New(), after starlark engine creation:
pool := newUpstreamPool(cfg.Redirect.Upstreams)

fw := &Firewall{
    // ... existing fields ...
    pool: pool,
}
// Wire pool into starlark engine so redirect builtin can call pool.Next():
starlark.pool = pool
```

### Test patterns (verified against firewalld_test.go)

```go
// Source: firewalld_test.go Config{} struct literal pattern [VERIFIED]

func TestUpstreamPool_RoundRobin(t *testing.T) {
    p := newUpstreamPool([]string{"1.1.1.1:53", "2.2.2.2:53"})
    got0, err := p.Next()
    require.NoError(t, err)
    got1, err := p.Next()
    require.NoError(t, err)
    assert.NotEqual(t, got0, got1, "round-robin should alternate")
    got2, err := p.Next()
    require.NoError(t, err)
    assert.Equal(t, got0, got2, "should wrap around")
}

func TestUpstreamPool_Empty(t *testing.T) {
    p := newUpstreamPool(nil)
    _, err := p.Next()
    assert.Error(t, err)
}

func TestUpstreamPool_SingleUpstream(t *testing.T) {
    p := newUpstreamPool([]string{"9.9.9.9:53"})
    for i := 0; i < 5; i++ {
        got, err := p.Next()
        require.NoError(t, err)
        assert.Equal(t, "9.9.9.9:53", got)
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single `redirect_server` per Starlark call | Pool-only; `server=` removed | Phase 5 | Starlark scripts must remove `server=` arg |
| `redirect_server` required on redirect rules | Optional (pool fallback) | Phase 5 | Rules without `redirect_server` use global pool |

**Deprecated/outdated:**
- `server=` kwarg in `firewall.redirect()`: hard error at evaluation time after Phase 5
- `compileRule` requiring `redirect_server != ""`: validation relaxed (pool is the fallback)

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Pool reference added to StarlarkEngine via post-construction setter (`starlark.pool = pool`) | Patterns 3/4 | Alternative: pass pool to buildFirewallModuleWithSink as parameter — either works, planner picks one |
| A2 | PolicyEngine gets pool reference via post-construction setter OR pool call moves to Check() — two valid options documented | Pattern 4 | Both are correct per decisions; planner must choose one approach for plan tasks |
| A3 | `(counter.Add(1) - 1) % uint64(len)` for 0-based first call | UpstreamPool example | `counter.Add(1) % len` also works; only affects which index is first, not distribution |
| A4 | `compileRule` validation relaxed in-place; `New()` validates pool non-empty when any rule uses redirect without redirect_server | Pitfall 1 | If validation stays strict, operators cannot use pool-only redirect rules |

**All other claims verified against codebase source files read in this session.**

---

## Open Questions

1. **Where does the pool-empty SERVFAIL get synthesized for the static rule path?**
   - What we know: `Check()` returns `*Decision`; `fw.Redirect()` already returns SERVFAIL on forward error.
   - What's unclear: When `pool.Next()` fails before `fw.Redirect()` is called, who synthesizes the SERVFAIL response?
   - Recommendation: Inline in `Check()` — if pool.Next() returns error, log at error level and return `&Decision{Verdict: VerdictDrop}` with a note, OR add a `VerdictServFail` constant that the caller (server.go) handles. Planner should lock this approach in the plan.

2. **Should compileRule accept redirect with empty redirect_server?**
   - What we know: Current code returns error if `redirect_server == ""`. Pool is a new concept not yet in compiledRule.
   - What's unclear: Compile-time vs runtime validation of pool availability.
   - Recommendation: Relax compile-time check, add `New()` level validation that at least one redirect target (pool or per-rule) is reachable.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `testing` + `testify` (assert/require) |
| Config file | none (go test convention) |
| Quick run command | `go test ./internal/firewalld/... -count=1 -short` |
| Full suite command | `go test ./internal/firewalld/... -count=1 -race` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REDIR-01 | `RedirectConfig.Upstreams` survives YAML round-trip | unit | `go test ./internal/firewalld/... -run TestRedirectConfig` | ❌ Wave 0 |
| REDIR-02 | `UpstreamPool.Next()` alternates targets; single-target; empty-pool error | unit | `go test ./internal/firewalld/... -run TestUpstreamPool` | ❌ Wave 0 |
| REDIR-03 | Starlark `redirect()` with no args uses pool; `server=` arg returns error | unit | `go test ./internal/firewalld/... -run TestStarlarkRedirect` | ❌ Wave 0 |
| REDIR-04 | Static redirect rule with no `redirect_server` uses pool; per-rule override bypasses pool | unit | `go test ./internal/firewalld/... -run TestFirewall_Redirect` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./internal/firewalld/... -count=1 -short`
- **Per wave merge:** `go test ./internal/firewalld/... -count=1 -race`
- **Phase gate:** Full suite green (`go test ./... -count=1 -race` on non-broken packages) before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/firewalld/firewalld_test.go` — new test functions for REDIR-01 through REDIR-04 (appended to existing file)
- [ ] No new test files needed — all tests follow the single-file pattern already established

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | Validate `ip:port` format in `Upstreams`; `Forwarder.Forward()` already calls `net.SplitHostPort` [VERIFIED: forwarder.go:38-40] |
| V6 Cryptography | no | — |

### Known Threat Patterns for DNS redirect pooling

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| SSRF via operator-supplied upstream addresses | Tampering | Upstreams are operator-configured at startup; no user input path to pool; acceptable [VERIFIED: config is YAML at startup] |
| Pool exhaustion / amplification | Denial of Service | Round-robin; no unbounded growth; pool size is static [VERIFIED: slice from config] |
| Log injection via upstream address in error messages | Tampering | Zerolog uses structured fields; `server` field is quoted/escaped [VERIFIED: forwarder.go Warn log] |

---

## Sources

### Primary (HIGH confidence)

- Codebase: `internal/firewalld/forwarder.go` — Forwarder struct, Forward(), NewForwarder() [VERIFIED: read in session]
- Codebase: `internal/firewalld/firewalld.go` — Firewall struct, atomic.Uint64 pattern, New(), Check(), Redirect() [VERIFIED: read in session]
- Codebase: `internal/firewalld/config.go` — Config, RuleConfig, DefaultConfig() [VERIFIED: read in session]
- Codebase: `internal/firewalld/starlark.go` — buildFirewallModuleWithSink, redirect builtin at line 253 [VERIFIED: read in session]
- Codebase: `internal/firewalld/policy.go` — compileRule redirect validation at line 71-73, Evaluate() [VERIFIED: read in session]
- Codebase: `internal/firewalld/firewalld_test.go` — test patterns, Config{} struct literal, makeQuery helper [VERIFIED: read in session]
- Codebase: `internal/firewalld/edns0.go` — new-file pattern for Phase 4 [VERIFIED: read in session]
- Go stdlib: `sync/atomic` — `atomic.Uint64.Add()` semantics [VERIFIED: matches codebase usage]
- Test run: `go test ./internal/firewalld/... -count=1 -short` → `ok` 31 tests [VERIFIED: bash run in session]
- `.planning/phases/05-redirect-load-balancing/05-CONTEXT.md` — all locked decisions [VERIFIED: read in session]

### Secondary (MEDIUM confidence)

- `.planning/STATE.md` — accumulated cross-phase context [VERIFIED: read in session]
- `.planning/REQUIREMENTS.md` — REDIR-01 through REDIR-04 [VERIFIED: read in session]

### Tertiary (LOW confidence)

None — all claims are verified against codebase or locked decisions.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new dependencies; everything is stdlib or already in go.mod
- Architecture: HIGH — all locked decisions verified against actual source code
- Pitfalls: HIGH — identified from direct code inspection of the three mutation points
- Open questions: MEDIUM — two design choices left to planner (pool-empty SERVFAIL path; policy.go threading approach)

**Research date:** 2026-04-23
**Valid until:** 2026-05-23 (stable Go stdlib patterns; no external dependency drift risk)
