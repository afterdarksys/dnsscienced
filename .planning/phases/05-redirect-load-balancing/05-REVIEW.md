---
phase: 05-redirect-load-balancing
reviewed: 2026-04-23T23:44:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - internal/firewalld/config.go
  - internal/firewalld/firewalld.go
  - internal/firewalld/firewalld_test.go
  - internal/firewalld/forwarder.go
  - internal/firewalld/forwarder_test.go
  - internal/firewalld/policy.go
  - internal/firewalld/starlark.go
findings:
  critical: 0
  warning: 5
  info: 2
  total: 7
status: issues_found
---

# Phase 05: Code Review Report

**Reviewed:** 2026-04-23T23:44:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

This review covers the redirect / load-balancing additions to `internal/firewalld`: the new `UpstreamPool`, `Forwarder`, `RedirectConfig`, and the Starlark `firewall.redirect()` builtin that uses the pool. The core redirect plumbing is correct — round-robin `UpstreamPool` is properly implemented, per-rule `redirect_server` overrides bypass the pool correctly, and `New()` fails fast when a redirect rule has no server and the pool is empty. No critical security issues were found.

Five warnings were identified, ranging from an incorrect SERVFAIL path that silently drops queries instead of returning an error response, to dead/never-checked config fields, to a goroutine leak on script timeout. Two info items cover a stale test name and a misleading comment.

---

## Warnings

### WR-01: Pool-empty branch constructs SERVFAIL response but then discards it (VerdictDrop is wrong)

**File:** `internal/firewalld/firewalld.go:200-209`

**Issue:** When `pool.Next()` fails (pool is empty), the code builds a `dns.Msg` SERVFAIL, but that message is never used. The function returns `&Decision{Verdict: VerdictDrop, ...}` — a silent discard. This violates the D-13 spec comment on `UpstreamPool.Next()` ("caller must return SERVFAIL"). The constructed `fail` variable is dead code. Additionally `record()` is not called so the drop is uncounted in metrics.

**Fix:**
```go
// In firewalld.go ~line 200
if d.Verdict == VerdictRedirect && d.Server == "" {
    server, err := fw.pool.Next()
    if err != nil {
        fw.logger.Error().Err(err).Msg("redirect pool empty — returning SERVFAIL")
        fail := new(dns.Msg)
        fail.SetReply(r)
        fail.Rcode = dns.RcodeServerFailure
        // Return a real SERVFAIL decision, not VerdictDrop.
        // Option A: add VerdictServFail verdict type.
        // Option B (simpler): call Apply() directly from caller.
        // Minimal fix: record and return NXDomain to at least count it.
        return fw.record(&Decision{Verdict: VerdictNXDomain, Reason: "pool empty", RuleName: "redirect"}, qctx)
    }
    d.Server = server
}
```
The right long-term fix is to propagate an out-of-band SERVFAIL back to the DNS handler. The immediate fix is at minimum to not silently drop (VerdictDrop returns no response, leaving the client to time out).

---

### WR-02: Starlark script errors are silently swallowed — no logging

**File:** `internal/firewalld/starlark.go:104-108`

**Issue:** When `runOne()` returns an error (compilation, init, timeout, or runtime error in `on_query`), `Run()` logs nothing and moves to the next script. A broken or timed-out policy script becomes completely invisible in production — the operator has no signal that their policy is not executing.

```go
// Current code
d, err := se.runOne(s, qctx, threatScore)
if err != nil {
    // Script error: log and continue to next.
    continue   // <-- no actual logging happens here
}
```

**Fix:**
```go
d, err := se.runOne(s, qctx, threatScore)
if err != nil {
    // Log at warn level so operators notice broken scripts without being flooded.
    // Consider a per-script error rate limiter for high-traffic deployments.
    log.Warn().Str("script", s.id).Err(err).Msg("starlark policy script error")
    continue
}
```

---

### WR-03: Goroutine leak on Starlark script timeout

**File:** `internal/firewalld/starlark.go:157-169`

**Issue:** When the context deadline fires before the script goroutine completes, `thread.Cancel("timeout")` is called and the function returns. However the goroutine holding a reference to `qctx`, `sink`, and `thread` continues running until Starlark checks its cancel flag at a safe point. Since `runOne()` is called per-query (potentially thousands of QPS), a sustained timeout condition will accumulate live goroutines. There is no `done` channel drain after the timeout case.

**Fix:**
```go
case <-ctx.Done():
    thread.Cancel("timeout")
    // Drain the goroutine: it will terminate quickly once Cancel fires.
    // This prevents goroutine accumulation under sustained timeout.
    go func() { <-done }()
    return nil, fmt.Errorf("on_query in %s timed out", s.id)
```
Using a detached goroutine to drain `done` ensures the script goroutine does not keep `qctx` alive indefinitely while remaining bounded (it will exit as soon as Starlark sees the cancel flag).

---

### WR-04: `IsJunk` match field is declared but never evaluated — rules that set it silently have no effect

**File:** `internal/firewalld/policy.go:99-134`, `internal/firewalld/config.go:72`

**Issue:** `MatchConfig.IsJunk` is a documented field ("matches when junk detection fires") but `compiledRule.matches()` never checks it. The comment at line 128-133 of `policy.go` says rules with `IsJunk` are "re-evaluated inside the junk stage", but there is no such secondary evaluation anywhere in `JunkDetector.Detect()` or elsewhere. A rule like:

```yaml
- name: redirect-junk-to-sinkhole
  match:
    is_junk: true
  action: redirect
```

will match every query (because no condition is false), not only junk queries. This is a correctness bug — the field is silently dead.

**Fix (short term):** Remove the `IsJunk` field from `MatchConfig` and its YAML tag until the re-evaluation path is actually implemented, to prevent operators from relying on broken behavior:
```go
// Remove from MatchConfig until implemented:
// IsJunk bool `yaml:"is_junk"`
```

**Fix (long term):** Implement the junk-stage re-evaluation described in the comment, or refactor the pipeline so that junk detection populates `QueryContext` with a flag that `compiledRule.matches()` can check.

---

### WR-05: `totalBlocked` counter double-counts redirect verdicts; `totalRedirected` is never incremented by `record()`

**File:** `internal/firewalld/firewalld.go:344-364`, `internal/firewalld/firewalld.go:283-294`

**Issue:** `record()` increments `totalBlocked` for every non-ALLOW verdict including `VerdictRedirect`. But `totalRedirected` is only incremented inside `Redirect()` (the method that performs the actual upstream forward). `record()` never increments `totalRedirected`. As a result:

- `Stats().TotalBlocked` includes redirect verdicts (misleading — redirects are not blocks).
- `Stats().TotalRedirected` equals 0 unless the caller happens to invoke `Redirect()` — which is the DNS handler's responsibility and may not be guaranteed.
- The `fw.metrics.queriesBlocked` Prometheus counter is labeled with `VerdictRedirect` as a "blocked" query.

**Fix:**
```go
// In record():
switch d.Verdict {
case VerdictNXDomain:
    fw.totalNXDomain.Add(1)
    fw.totalBlocked.Add(1)
case VerdictDrop:
    fw.totalDropped.Add(1)
    fw.totalBlocked.Add(1)
case VerdictRedirect:
    fw.totalRedirected.Add(1)
    // Do NOT count as blocked.
default:
    fw.totalBlocked.Add(1)
}
```
Move the `fw.totalBlocked.Add(1)` call out of the unconditional position and into the appropriate case branches.

---

## Info

### IN-01: Forwarder timeout multiplier comment is misleading

**File:** `internal/firewalld/firewalld.go:161`

**Issue:** The comment `// generous: 3× script timeout` is incorrect. The actual multiplier is `1500`, not `3`. The result happens to be 3 seconds because the default `ScriptTimeout` is 2ms (`2ms × 1500 = 3s`), but if an operator sets `ScriptTimeout: 10ms` the forwarder timeout becomes 15 seconds — far from "3×". The magic number `1500` should be replaced with a named constant and the comment corrected.

**Fix:**
```go
const forwarderTimeoutMultiplier = 1500 // yields ~3s with default 2ms ScriptTimeout

// In New():
forwarder: NewForwarder(cfg.ScriptTimeout * forwarderTimeoutMultiplier),
```
Or, preferably, make the forwarder timeout a first-class config field so operators can tune it independently.

---

### IN-02: Stale TDD test name and obsolete comment should be cleaned up

**File:** `internal/firewalld/firewalld_test.go:540-563`

**Issue:** `TestRedirect_PoolBehavior_RED` has a comment block above it saying "This test fails until starlark.go is updated" — the implementation is now complete and the test passes. The `_RED` suffix (TDD red-phase convention) and the stale comment are misleading to future readers. There is also a near-duplicate test `TestStarlarkRedirect_UsesPool` (line 577) that covers the same scenario with cleaner assertions.

**Fix:** Remove or rename the stale test, and remove the obsolete comment block. If retaining it for historical context, rename to `TestRedirect_PoolBehavior` and delete the "fails until" comment.

---

_Reviewed: 2026-04-23T23:44:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
