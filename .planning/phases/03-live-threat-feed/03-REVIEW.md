---
phase: 03-live-threat-feed
reviewed: 2026-04-23T20:53:26Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - internal/firewalld/config.go
  - internal/firewalld/config_test.go
  - internal/firewalld/feed.go
  - internal/firewalld/feed_test.go
  - internal/firewalld/threat_intel.go
  - internal/firewalld/threat_intel_test.go
  - internal/server/server.go
findings:
  critical: 0
  warning: 4
  info: 2
  total: 6
status: issues_found
---

# Phase 03: Code Review Report

**Reviewed:** 2026-04-23T20:53:26Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

This review covers the live threat feed implementation across `internal/firewalld` (config, feed poller, threat intel engine) and the wiring in `internal/server/server.go`. The overall design is sound: full-replace semantics are correctly implemented, the auth token is never logged, and the TLS opt-in is guarded with a `//nolint` comment. Four warnings were identified — one a potential panic/nil-dereference in the server handler, one a silent data-loss risk in feed parsing, one a context-propagation gap that delays graceful shutdown, and one a scoring inconsistency under concurrent writes. Two info items cover `fmt.Printf` use in production log paths and a missing scanner error check in tests.

## Warnings

### WR-01: `Redirect` response used without nil guard

**File:** `internal/server/server.go:429-437`

**Issue:** The `VerdictRedirect` branch calls `s.firewall.Redirect(r, d)` and passes the return value directly to `shouldRateLimit` and `w.WriteMsg` without checking whether `resp` is nil. In contrast, the adjacent `VerdictNXDomain`/`VerdictRewrite` branch at line 416 has an explicit `if resp != nil` guard. If `Redirect` ever returns nil (e.g., upstream connection failure or future refactor), this path will panic at runtime.

**Fix:**
```go
case firewalld.VerdictRedirect:
    resp := s.firewall.Redirect(r, d)
    if resp == nil {
        return // drop silently — upstream unreachable
    }
    if s.shouldRateLimit(resp, clientIP) {
        return
    }
    s.answers.Add(1)
    if resp.Rcode == dns.RcodeNameError {
        s.nxdomain.Add(1)
    }
    w.WriteMsg(resp)
    return
```

---

### WR-02: Feed parser silently drops `bufio.Scanner` errors

**File:** `internal/firewalld/feed.go:174-229`

**Issue:** `parseFeed` uses `bufio.NewScanner(r)` but never calls `scanner.Err()` after the loop. If the underlying `io.Reader` returns a network error mid-stream (connection reset, timeout), the scanner silently stops and `parseFeed` returns a partial entry list with no warning and no error. `fetchAndApply` then calls `apply()` on the partial list, performing a full-replace with truncated data — potentially removing legitimate threat entries that were not yet transmitted.

**Fix:**
```go
// After the scanner loop in parseFeed, before returning:
if err := scanner.Err(); err != nil {
    // Return nil entries and a single descriptive warning so the caller
    // can treat this as a failed fetch (D-14 semantics).
    return nil, []string{fmt.Sprintf("scanner error: %v", err)}
}
return entries, warnings
```

Then in `fetchAndApply`, treat a non-empty warnings slice that contains a scanner error as a failure condition (or return a dedicated error from `parseFeed`) to avoid calling `apply` with partial data.

---

### WR-03: In-flight HTTP request not cancelled on context cancellation

**File:** `internal/firewalld/feed.go:141-166`

**Issue:** `fetch()` builds the request with `http.NewRequest` (no context). The `http.Client` has a per-request `Timeout`, but context cancellation from server shutdown does not abort the in-flight fetch. During a `Stop()` call, `s.wg.Wait()` blocks until the goroutine exits, which may take up to `cfg.Timeout` (default 30 s) if a fetch is in progress at shutdown time. The fix is one line.

**Fix:**
```go
// In fetch(), replace:
req, err := http.NewRequest(http.MethodGet, fc.cfg.FeedURL, nil)

// With:
req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.cfg.FeedURL, nil)
```

This requires threading `ctx` through from `run()` → `fetchAndApply(ctx)` → `fetch(ctx)`. The goroutine already has `ctx` available in `run()`.

---

### WR-04: Two separate `dynMu` read-lock acquisitions create inconsistent score snapshot

**File:** `internal/firewalld/threat_intel.go:82-102`

**Issue:** `Score()` acquires `dynMu.RLock()` twice — once to read `dynIPs` (lines 82-86) and again to read `dynDomains` (lines 91-102). Between the two unlocks a concurrent `apply()` (which holds `dynMu.Lock()`) can swap both maps atomically. The result is that a single query can be scored against the old IP map and the new domain map (or vice versa), producing an internally inconsistent score. While this is unlikely to cause a security bypass in practice, it violates the intended "atomic snapshot" behavior.

**Fix:** Hold `dynMu.RLock()` for the entire dynamic-score section:
```go
// Replace the two separate RLock/RUnlock pairs with one:
ti.dynMu.RLock()
if s, ok := ti.dynIPs[qctx.ClientIP.String()]; ok {
    score += s
}
bare := strings.TrimSuffix(qctx.Name, ".")
labels := dns.SplitDomainName(bare)
for i := range labels {
    suffix := strings.ToLower(strings.Join(labels[i:], "."))
    if s, ok := ti.dynDomains[suffix]; ok {
        score += s
        break
    }
}
ti.dynMu.RUnlock()
```

## Info

### IN-01: Production log paths use `fmt.Printf` instead of structured logger

**File:** `internal/server/server.go:172-176, 185-188, 256, 269, 281, 289, 292, 318`

**Issue:** The rest of the codebase (including `feed.go`) uses zerolog for structured, leveled logging. `server.go` uses raw `fmt.Printf` throughout — including for experimental feature warnings (with emoji), startup messages, and shutdown progress. This makes log aggregation and filtering inconsistent and prints to stdout even when a structured log sink is configured.

**Fix:** Replace `fmt.Printf`/`fmt.Println` calls in `server.go` with the project's zerolog pattern, e.g.:
```go
log.Info().Str("component", "server").Str("addr", s.cfg.UDPAddr).Int("listener", i).Msg("UDP listener started")
```

---

### IN-02: `TestFeedConfig` stores `AuthToken: "secret"` as a literal in test code

**File:** `internal/firewalld/feed_test.go:26`

**Issue:** The value `"secret"` used in the config struct assertion is a magic string with no explanatory comment. Secret-scanning tools (GitHub, truffleHog) sometimes flag `AuthToken: "secret"` patterns in test files. Consider using a clearly-synthetic value like `"test-bearer-token"` to avoid false positives in automated scanning pipelines.

**Fix:**
```go
AuthToken: "test-bearer-token",
// ...
assert.Equal(t, "test-bearer-token", cfg.AuthToken)
```

---

_Reviewed: 2026-04-23T20:53:26Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
