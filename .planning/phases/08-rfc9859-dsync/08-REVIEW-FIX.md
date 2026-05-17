---
phase: 08-rfc9859-dsync
fixed_at: 2026-05-17T00:00:00Z
review_path: .planning/phases/08-rfc9859-dsync/08-REVIEW.md
iteration: 1
findings_in_scope: 8
fixed: 7
skipped: 1
status: partial
---

# Phase 08: Code Review Fix Report

**Fixed at:** 2026-05-17T00:00:00Z
**Source review:** .planning/phases/08-rfc9859-dsync/08-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 8 (3 Critical + 5 Warning; Info excluded per fix_scope=critical_warning)
- Fixed: 7
- Skipped: 1 (WR-04 resolved as part of CR-01)

## Fixed Issues

### CR-01: DSYNCNotifier worker goroutine leaks — no shutdown path

**Files modified:** `internal/dsync/sender.go`, `internal/server/server.go`, `api/grpc/services/dsync_test.go`
**Commit:** 2ae4d27
**Applied fix:** Added `stopCh`/`doneCh`/`closeOnce` fields to `DSYNCNotifier`. Rewrote `worker()` to select on `stopCh` and `close(doneCh)` on exit. Added `Close()` method with `closeOnce` guard. Extracted `processEvent()` and `sendToEndpoint()` helpers (the latter also fixes WR-04 via `defer cancel()`). Updated `server.Stop()` to call `s.dsyncNotifier.Close()`. Added `t.Cleanup(notifier.Close)` to all 6 notifier-creating tests. The propagation delay `time.Sleep` was also replaced with a timer+select so `Close()` can interrupt a sleeping worker promptly.

---

### CR-02: Webhook silently ignores HTTP 4xx/5xx response codes

**Files modified:** `internal/dsync/webhook.go`
**Commit:** ac19404
**Applied fix:** Changed `resp.Body.Close()` + bare `return nil` to `defer resp.Body.Close()` + explicit status check: returns `fmt.Errorf("webhook POST %s: unexpected status %d", ...)` for any status outside 200–299.

---

### CR-03: Nil clientIP passed to HandleInbound creates shared limiter bucket for all unknown transports

**Files modified:** `internal/server/server.go`
**Commit:** 8cc12bc
**Applied fix:** Added an early guard inside the `r.Opcode == dns.OpcodeNotify` branch: if `clientIP == nil` (unknown transport type), immediately respond with `RcodeRefused` and return before calling `HandleInbound`. This prevents the nil-IP from reaching the rate limiter or ACL.

---

### WR-01: DSYNCNotifier uses the server's own listen address as the discovery resolver

**Files modified:** `internal/server/server.go`
**Commit:** 68c560d
**Applied fix:** Added `Resolver string` field to `DSYNCConfig` (yaml: `resolver`) with doc comment. Updated `server.New()` to use `cfg.DSYNC.Resolver` with a fallback default of `"8.8.8.8:53"` when empty. The old `cfg.UDPAddr` (server's own listen address) is no longer passed as the resolver.

---

### WR-02: Data race — metrics field written after worker goroutine starts

**Files modified:** `internal/dsync/handler.go`, `internal/dsync/sender.go`, `internal/dsync/handler_test.go`, `internal/dsync/sender_test.go`, `internal/server/server.go`, `api/grpc/services/dsync_test.go`
**Commit:** d1fee66
**Applied fix:** Added `metrics *DSYNCMetrics` parameter to both `NewHandler` and `NewDSYNCNotifier` constructors. `dsyncMetrics` is now created before either constructor is called in `server.New()`, and both constructors receive the same instance. The data race window (worker goroutine starting before `SetMetrics` call) is eliminated. `SetMetrics` is retained for test use but its doc comment now indicates the constructor is preferred. All callers updated (tests pass `nil`).

---

### WR-03: SourceACL fails open when all CIDR entries are malformed

**Files modified:** `internal/dsync/source_acl.go`, `internal/dsync/source_acl_test.go`
**Commit:** 75bbc4c
**Applied fix:** Changed `NewSourceACL` signature to `(*SourceACL, error)`. Any invalid CIDR/IP entry now returns an error immediately (fail-closed). Added `TestSourceACL_InvalidCIDRErrors` test verifying that a malformed CIDR returns a non-nil error. All existing tests updated to handle the error return.

---

### WR-05: RegisterAll variadic dsyncNotifier silently ignores extra arguments

**Files modified:** `api/grpc/registry/register.go`, `cmd/dnsscience-grpc/main.go`
**Commit:** 5748cfb
**Applied fix:** Changed `dsyncNotifier ...*dsync.DSYNCNotifier` to `dsyncNotifier *dsync.DSYNCNotifier` (explicit pointer). Updated the registration guard from `len(dsyncNotifier) > 0 && dsyncNotifier[0] != nil` to simply `dsyncNotifier != nil`. Updated `cmd/dnsscience-grpc/main.go` to pass explicit `nil`.

---

## Skipped Issues

### WR-04: Context cancel not deferred inside sender loop — leaks on panic

**File:** `internal/dsync/sender.go`
**Reason:** Already resolved as part of CR-01 fix. The `sendToEndpoint` helper function extracted during CR-01 uses `defer cancel()` idiomatically, which is precisely the fix WR-04 called for. No separate commit needed.

---

_Fixed: 2026-05-17_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
