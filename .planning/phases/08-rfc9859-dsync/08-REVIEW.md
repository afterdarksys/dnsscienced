---
phase: 08-rfc9859-dsync
reviewed: 2026-05-16T00:00:00Z
depth: standard
files_reviewed: 21
files_reviewed_list:
  - api/grpc/proto/admin.proto
  - api/grpc/proto/pb/admin_grpc.pb.go
  - api/grpc/proto/pb/admin.pb.go
  - api/grpc/registry/register.go
  - api/grpc/services/dsync_test.go
  - api/grpc/services/dsync.go
  - internal/config/config.go
  - internal/dsync/discovery_test.go
  - internal/dsync/discovery.go
  - internal/dsync/dsync_test.go
  - internal/dsync/dsync.go
  - internal/dsync/handler_test.go
  - internal/dsync/handler.go
  - internal/dsync/metrics_test.go
  - internal/dsync/metrics.go
  - internal/dsync/ratelimit_test.go
  - internal/dsync/ratelimit.go
  - internal/dsync/sender_test.go
  - internal/dsync/sender.go
  - internal/server/notify_test.go
  - internal/server/server.go
  - internal/zone/parser_dsync_test.go
findings:
  critical: 3
  warning: 5
  info: 2
  total: 10
status: issues_found
---

# Phase 08: Code Review Report

**Reviewed:** 2026-05-16T00:00:00Z
**Depth:** standard
**Files Reviewed:** 21
**Status:** issues_found

## Summary

This phase implements RFC 9859 DSYNC (Generalized DNS Notifications): inbound NOTIFY(CDS/CSYNC) handling, outbound discovery and NOTIFY sending, a per-source-IP rate limiter, Prometheus metrics, webhook delivery, a gRPC admin RPC, and zone-file parsing of TYPE66. The overall design is coherent and RFC-conformant. However, three blockers were found that risk context leaks, duplicate Prometheus panics, and a goroutine leak on server shutdown. Five warnings cover lesser correctness and robustness issues.

---

## Critical Issues

### CR-01: `cancel2()` called after context already consumed — not deferred; context leaks on early returns

**File:** `internal/dsync/sender.go:91-105`

**Issue:** `cancel2` is called unconditionally at line 105 only when the `for` loop body completes normally. However, if `sendNotify` returns an error and the `if n.metrics != nil` branch executes, `cancel2()` is still reached — so in the happy path the cancel is fine. The real problem is that if a future `continue` or `break` is added inside the loop body (e.g., for retry logic), the cancel will be skipped. More critically, `cancel2` is NOT deferred. If a panic occurs anywhere between lines 91 and 105, the context is leaked. Go's `context.WithTimeout` spins a timer goroutine that runs until `cancel` is called or the timeout expires. With a 5-second timeout this is bounded, but Go's context documentation explicitly states callers MUST call cancel to release resources. The pattern is fragile and non-idiomatic.

**Fix:** Use `defer` immediately after creating the context:

```go
for _, rec := range records {
    if rec.RRtype != ev.qtype || rec.Scheme != DSYNCSchemeNOTIFY {
        continue
    }
    ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel2() // or use an inline func to scope it to the iteration
    // ...
}
```

Because `defer` in a loop defers until the enclosing function returns (not the iteration), the idiomatic fix is an inline closure:

```go
for _, rec := range records {
    if rec.RRtype != ev.qtype || rec.Scheme != DSYNCSchemeNOTIFY {
        continue
    }
    func() {
        ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel2()
        if err := sendNotify(ctx2, ev.zone, ev.qtype, rec.Target, rec.Port); err != nil {
            // ...
        } else {
            // ...
        }
    }()
}
```

---

### CR-02: `NewDSYNCMetrics` uses `prometheus.MustRegister` on the global registry — panics if called more than once

**File:** `internal/dsync/metrics.go:49-51`

**Issue:** `prometheus.MustRegister` panics if the same metric name is already registered in the global registry. `NewDSYNCMetrics` is called from `server.New()` (line 258 of `server.go`) every time a new `Server` is constructed. In test suites, multiple `New(cfg)` calls in the same process will cause a panic on the second call because the metrics are already registered under the global `prometheus.DefaultRegisterer`. This is confirmed by `metrics_test.go` comments at line 16: "We use a manually constructed DSYNCMetrics with unregistered counters" — test authors worked around the problem, but the production code path (multiple `server.New` calls, e.g. in integration tests or test helpers like `notify_test.go`) will panic.

**Fix:** Use `prometheus.MustRegister` with error recovery, or (better) register with `prometheus.NewRegistry()` and use `promauto`, or use the `errors.As` pattern to detect already-registered errors:

```go
func NewDSYNCMetrics() *DSYNCMetrics {
    m := &DSYNCMetrics{
        NotifyInbound: prometheus.NewCounterVec( /* ... */ ),
        NotifyOutbound: prometheus.NewCounterVec( /* ... */ ),
        Webhook: prometheus.NewCounterVec( /* ... */ ),
    }
    // Use Register (not MustRegister) and ignore AlreadyRegisteredError,
    // returning the existing collector if present.
    for _, c := range []prometheus.Collector{m.NotifyInbound, m.NotifyOutbound, m.Webhook} {
        if err := prometheus.Register(c); err != nil {
            if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
                _ = are // already registered; safe to continue
            } else {
                panic(err)
            }
        }
    }
    return m
}
```

Alternatively, accept a `prometheus.Registerer` parameter so callers can pass an isolated registry in tests.

---

### CR-03: `DSYNCNotifier` worker goroutine is never stopped — goroutine leak on server shutdown

**File:** `internal/dsync/sender.go:40-49`, `internal/server/server.go:243-260`

**Issue:** `NewDSYNCNotifier` starts a `worker()` goroutine at line 47 that blocks on `for ev := range n.events`. The only way this goroutine can exit is if the `events` channel is closed. There is no `Close()`, `Stop()`, or context-based shutdown path on `DSYNCNotifier`. In `server.Stop()` (server.go line 342-382), the server cancels its context and shuts down all components, but `DSYNCNotifier` is stored nowhere on the `Server` struct and has no shutdown hook. The `NotifyLimiter` correctly implements `Close()` with `stopCh`/`doneCh`; the notifier does not. On server shutdown, the worker goroutine leaks permanently.

**Fix:** Add a `Close()` method to `DSYNCNotifier` that closes the `events` channel and waits for the worker to exit:

```go
type DSYNCNotifier struct {
    // ... existing fields ...
    closeOnce sync.Once
    done      chan struct{}
}

func NewDSYNCNotifier(resolver string, propagationDelay time.Duration, log zerolog.Logger) *DSYNCNotifier {
    n := &DSYNCNotifier{
        // ...
        done: make(chan struct{}),
    }
    go n.worker()
    return n
}

func (n *DSYNCNotifier) Close() {
    n.closeOnce.Do(func() {
        close(n.events)
        <-n.done
    })
}

func (n *DSYNCNotifier) worker() {
    defer close(n.done)
    for ev := range n.events { /* ... */ }
}
```

Then call `notifier.Close()` from `server.Stop()`, and store the notifier on the `Server` struct.

---

## Warnings

### WR-01: `clientIP` can be nil when passed to `Handler.HandleInbound` — potential nil dereference in rate limiter

**File:** `internal/server/server.go:422-427`, `internal/dsync/ratelimit.go:51`

**Issue:** In `handleDNS`, `clientIP` is computed from `w.RemoteAddr()` type assertions. If `RemoteAddr()` returns an address type that is neither `*net.UDPAddr` nor `*net.TCPAddr` (e.g., a custom `net.Addr` in tests or unusual transport), `clientIP` remains `nil`. This nil is then passed to `HandleInbound`, which passes it to `h.limiter.Allow(clientIP)`. Inside `Allow`, `ip.String()` is called — `net.IP(nil).String()` returns `"<nil>"` in Go, so this will not panic, but it means all nil-IP clients share a single rate-limiter bucket, which is an incorrect behavior. Similarly, `h.acl.Check(clientIP)` with a nil IP is passed to the stub `allowAll`, which ignores it, but a real ACL could panic or misclassify.

**Fix:** Add a nil check before dispatching to `HandleInbound`:

```go
if r.Opcode == dns.OpcodeNotify {
    if clientIP == nil {
        // Reject with REFUSED if we cannot determine source IP
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    if s.dsyncHandler != nil {
        s.dsyncHandler.HandleInbound(w, r, clientIP)
    } else {
        // ...
    }
    return
}
```

---

### WR-02: Webhook HTTP response body not checked for error status codes — silent delivery failures

**File:** `internal/dsync/webhook.go:68-73`

**Issue:** After `wc.client.Post(...)`, the code closes the response body but does not inspect `resp.StatusCode`. A webhook endpoint returning HTTP 500 or 404 is silently treated as a successful delivery. The metrics label will show `"ok"` even when the endpoint rejected the payload. This violates the intent of D-04 ("failure logged") since non-2xx responses are not considered failures.

**Fix:**

```go
resp, err := wc.client.Post(wc.url, contentType, bytes.NewReader(body))
if err != nil {
    return fmt.Errorf("webhook POST %s: %w", wc.url, err)
}
defer resp.Body.Close()
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return fmt.Errorf("webhook POST %s: non-2xx status %d", wc.url, resp.StatusCode)
}
return nil
```

---

### WR-03: `DiscoverDSYNC` returns `nil, nil` on all-error path — caller cannot distinguish "no records" from "DNS error"

**File:** `internal/dsync/discovery.go:24-32`

**Issue:** The discovery loop at line 28 swallows DNS errors with `if err == nil && len(records) > 0`. When every query returns an error (e.g., network partition, resolver misconfiguration), the function returns `nil, nil` — indistinguishable from "no DSYNC records exist." The caller in `sender.go` line 81 treats both identically (`if err != nil || len(records) == 0 { continue }`), so outbound NOTIFYs are silently dropped during network outages. At minimum, the final error should be surfaced.

**Fix:** Accumulate the last error and return it if no records were found:

```go
func DiscoverDSYNC(ctx context.Context, delegation string, client *dns.Client, resolver string) ([]DSYNCRecord, error) {
    labels := dns.SplitDomainName(dns.Fqdn(delegation))
    var lastErr error
    for i := 0; i < len(labels)-1; i++ {
        suffix := strings.Join(labels[i:], ".") + "."
        candidate := "_dsync." + suffix
        records, err := queryDSYNC(ctx, candidate, client, resolver)
        if err != nil {
            lastErr = err
            continue
        }
        if len(records) > 0 {
            return records, nil
        }
    }
    return nil, lastErr // nil lastErr means NXDOMAIN on all candidates
}
```

---

### WR-04: `sendNotify` creates a new `dns.Client` on every call, ignoring the `ctx` parameter for connection setup

**File:** `internal/dsync/sender.go:115-131`

**Issue:** `sendNotify` receives a `ctx context.Context` and calls `c.ExchangeContext(ctx, m, addr)` — correct. However, it also creates a new `dns.Client{Net: "udp", Timeout: 5 * time.Second}` on every call (line 120), duplicating the timeout already encoded in the context. This means the effective timeout is the minimum of the context deadline and `c.Timeout`. More importantly, it creates a new ephemeral UDP socket for every outbound NOTIFY rather than reusing the one already created in the `worker()` function (line 71). The `worker()` creates `client := &dns.Client{...}` but then does not pass it to `sendNotify`. This is dead code (the `worker`-level `client` is only used for `DiscoverDSYNC`, which is correct), but the pattern inside `sendNotify` itself is wasteful and inconsistent with the rest of the design.

**Fix:** Accept a `*dns.Client` parameter in `sendNotify` so the worker's client can be reused:

```go
func sendNotify(ctx context.Context, zoneName string, qtype uint16, target string, port uint16, c *dns.Client) error {
    // ...
    resp, _, err := c.ExchangeContext(ctx, m, addr)
    // ...
}
```

Call as `sendNotify(ctx2, ev.zone, ev.qtype, rec.Target, rec.Port, client)` from the worker.

---

### WR-05: `DSYNCAdminService` RPC accepts any non-empty `zone_name` without validating it is a syntactically valid DNS name

**File:** `api/grpc/services/dsync.go:38-39`

**Issue:** The `SendDSYNCNotify` RPC checks that `zone_name` is non-empty but does not validate it as a valid DNS name. A caller can pass `"not a valid domain!!!"` or an excessively long string (>255 bytes), which will then propagate to `DiscoverDSYNC` and `dns.SplitDomainName` / `dns.Fqdn`. `dns.Fqdn` will blindly append a trailing dot, and `dns.SplitDomainName` will split on any string. Malformed names will produce incorrect `_dsync.<label>` queries that either error out or, in edge cases, query unintended names.

**Fix:** Validate the zone name using `dns.IsFqdn` after normalization, or use `dns.IsSubDomain`/`dns.CanonicalName` combined with a length check:

```go
zoneFQDN := dns.Fqdn(req.ZoneName)
if _, ok := dns.IsDomainName(zoneFQDN); !ok {
    return nil, status.Errorf(codes.InvalidArgument, "zone_name %q is not a valid DNS name", req.ZoneName)
}
```

---

## Info

### IN-01: `ForceLastSeen` and `SweepStaleForTest` are exported test helpers on a production type

**File:** `internal/dsync/ratelimit.go:107-119`

**Issue:** `ForceLastSeen` and `SweepStaleForTest` are exported methods on `NotifyLimiter`, a production type. Exporting test helpers on production structs pollutes the public API surface. Any consumer of the `dsync` package sees these methods.

**Fix:** Move these methods to a `_test.go` file as unexported helpers, or use a `testing` build tag. Alternatively, keep them in a `dsync_test` helper file if the tests are in the `dsync_test` (external test) package. Since `ratelimit_test.go` is in `package dsync_test`, the methods must be exported or the tests must be moved to the internal package; however a cleaner approach is to use a `testutil` or `export_test.go` file:

```go
// export_test.go (build tag: only compiled in test mode)
package dsync

var ForceLastSeen = (*NotifyLimiter).forceLastSeen
var SweepStaleForTest = (*NotifyLimiter).sweepStale
```

---

### IN-02: `handler_test.go` is in `package dsync` (internal) while `dsync_test.go` and `ratelimit_test.go` are in `package dsync_test` (external) — inconsistent test package strategy

**File:** `internal/dsync/handler_test.go:1`, `internal/dsync/dsync_test.go:1`, `internal/dsync/ratelimit_test.go:1`

**Issue:** The package mixing forces internal test helpers (`mockResponseWriter`, `rejectAll`, `newTestHandler`, `permissiveLimiter`, `blockedLimiter`) to be defined in `handler_test.go` using `package dsync`, but `metrics_test.go` is also in `package dsync` and reuses those same helpers directly. Meanwhile `dsync_test.go` and `ratelimit_test.go` are `package dsync_test` and cannot access unexported helpers or internal types. This inconsistency means tests rely on different levels of access in an ad-hoc way and `permissiveLimiter`/`blockedLimiter` defined in handler_test.go are silently available to metrics_test.go only because both happen to be in the same package — creating invisible coupling between test files.

**Fix:** Standardize on one approach. Using `package dsync` for all test files in this package is simplest given that the tests require internal access to `NotifyLimiter`, `DSYNCMetrics`, etc. Move `dsync_test.go` and `ratelimit_test.go` to `package dsync` and remove the import of the `dsync` package from them. This eliminates the split-package confusion.

---

_Reviewed: 2026-05-16T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
