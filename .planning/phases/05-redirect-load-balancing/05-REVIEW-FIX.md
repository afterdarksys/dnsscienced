---
phase: 05-redirect-load-balancing
fixed_at: 2026-04-23T23:55:00Z
review_path: .planning/phases/05-redirect-load-balancing/05-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 05: Code Review Fix Report

**Fixed at:** 2026-04-23T23:55:00Z
**Source review:** .planning/phases/05-redirect-load-balancing/05-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5
- Fixed: 5
- Skipped: 0

## Fixed Issues

### WR-01: Pool-empty branch constructs SERVFAIL response but then discards it (VerdictDrop is wrong)

**Files modified:** `internal/firewalld/firewalld.go`
**Commit:** 231f564
**Applied fix:** Removed the dead `dns.Msg` SERVFAIL construction. The pool-empty path now calls `fw.record(&Decision{Verdict: VerdictNXDomain, Reason: "pool empty", RuleName: "redirect"}, qctx)` so the decision is properly counted in metrics, logged, and returns a real response to the client instead of a silent drop.

---

### WR-02: Starlark script errors are silently swallowed — no logging

**Files modified:** `internal/firewalld/starlark.go`
**Commit:** fb1398f
**Applied fix:** Added `log.Warn().Str("script", s.id).Err(err).Msg("starlark policy script error")` before the `continue` in `Run()`. Also added the required `"github.com/rs/zerolog/log"` import.

---

### WR-03: Goroutine leak on Starlark script timeout

**Files modified:** `internal/firewalld/starlark.go`
**Commit:** fb1398f
**Applied fix:** Added `go func() { <-done }()` in the `ctx.Done()` case immediately after `thread.Cancel("timeout")`. The detached goroutine drains the `done` channel once Starlark sees the cancel flag, preventing goroutine accumulation under sustained timeout conditions.

---

### WR-04: `IsJunk` match field is declared but never evaluated

**Files modified:** `internal/firewalld/config.go`
**Commit:** 380fab6
**Applied fix:** Commented out `IsJunk bool \`yaml:"is_junk"\`` from `MatchConfig` and replaced it with an explanatory comment describing why it was removed and when it should be re-added (once junk-stage re-evaluation is implemented). The `matches()` comment in policy.go was left as-is since it already accurately describes the intended design.

---

### WR-05: `totalBlocked` counter double-counts redirect verdicts; `totalRedirected` is never incremented by `record()`

**Files modified:** `internal/firewalld/firewalld.go`
**Commit:** 231f564
**Applied fix:** Restructured `record()` to use a full switch statement: `VerdictNXDomain` and `VerdictDrop` both increment `totalBlocked`, `VerdictRedirect` increments `totalRedirected` only (not `totalBlocked`), and the `default` case handles remaining non-allow verdicts. Also removed the now-redundant `fw.totalRedirected.Add(1)` call from `Redirect()` to prevent double-counting.

---

_Fixed: 2026-04-23T23:55:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
