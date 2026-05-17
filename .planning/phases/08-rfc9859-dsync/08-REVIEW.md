---
phase: 08-rfc9859-dsync
reviewed: 2026-05-17T00:00:00Z
depth: standard
files_reviewed: 27
files_reviewed_list:
  - api/grpc/proto/admin.proto
  - api/grpc/proto/pb/admin.pb.go
  - api/grpc/proto/pb/admin_grpc.pb.go
  - api/grpc/registry/register.go
  - api/grpc/services/dsync.go
  - api/grpc/services/dsync_test.go
  - cmd/dnsscienced/main.go
  - internal/config/config.go
  - internal/dsync/discovery.go
  - internal/dsync/discovery_test.go
  - internal/dsync/dsync.go
  - internal/dsync/dsync_test.go
  - internal/dsync/handler.go
  - internal/dsync/handler_test.go
  - internal/dsync/metrics.go
  - internal/dsync/metrics_test.go
  - internal/dsync/ratelimit.go
  - internal/dsync/ratelimit_test.go
  - internal/dsync/sender.go
  - internal/dsync/sender_test.go
  - internal/dsync/source_acl.go
  - internal/dsync/source_acl_test.go
  - internal/dsync/webhook.go
  - internal/dsync/webhook_test.go
  - internal/server/dsync_wiring_test.go
  - internal/server/notify_test.go
  - internal/server/server.go
  - internal/zone/parser_dsync_test.go
findings:
  critical: 3
  warning: 5
  info: 3
  total: 11
status: issues_found
---

# Phase 08: Code Review Report

**Reviewed:** 2026-05-17T00:00:00Z
**Depth:** standard
**Files Reviewed:** 27
**Status:** issues_found

## Summary

This phase delivers RFC 9859 DSYNC support: inbound NOTIFY handling, outbound NOTIFY sending, _dsync discovery, per-source-IP rate limiting, source ACL, webhook delivery, Prometheus metrics, and a gRPC admin RPC to trigger manual sends. The overall structure is sound and test coverage is good. However, three blockers were found: a goroutine leak in `DSYNCNotifier` (no shutdown path), an unchecked HTTP response status in the webhook client that silently accepts 4xx/5xx errors as successful deliveries, and a nil-IP path in the NOTIFY handler when the client address type is unexpected. Five warnings cover a misconfigured outbound resolver address, a data race window in metrics wiring, fail-open behavior in ACL CIDR parsing, a fragile context-cancel placement in the sender loop, and an ambiguous variadic API in the service registry.

---

## Critical Issues

### CR-01: DSYNCNotifier worker goroutine leaks — no shutdown path

**File:** `internal/dsync/sender.go:70-108`

**Issue:** `NewDSYNCNotifier` starts a goroutine that loops forever over `n.events` with `for ev := range n.events`. The channel is never closed and no stop mechanism exists. Unlike `NotifyLimiter` (which has `Close()` / `stopCh` / `doneCh`), `DSYNCNotifier` has no equivalent shutdown. The comment in `internal/server/server.go:394-396` acknowledges this and declares it intentional: "The channel is not closed explicitly because no sentinel is needed — the background goroutine simply terminates with the process."

This causes two concrete problems:

1. **Test goroutine leaks.** `dsync_test.go:122` and `dsync_service_test.go:20-21` each create a `DSYNCNotifier` with a long propagation delay. None are ever stopped. Every test run leaks a goroutine that blocks on `range n.events` for the lifetime of the test binary. Under `-count=N` or `-race`, this accumulates.

2. **Future config-reload safety.** If a config reload ever re-creates the notifier, the old worker will leak permanently. The design makes this refactor dangerous.

**Fix:** Add a `Close()` method mirroring `NotifyLimiter`. Use a `stopCh`/`doneCh` pair and select in the worker:

```go
// Fields to add to DSYNCNotifier:
stopCh    chan struct{}
doneCh    chan struct{}
closeOnce sync.Once

// In NewDSYNCNotifier, add after make(chan notifyEvent, 64):
n.stopCh = make(chan struct{})
n.doneCh = make(chan struct{})

// Replace worker loop body:
func (n *DSYNCNotifier) worker() {
    defer close(n.doneCh)
    client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
    for {
        select {
        case ev, ok := <-n.events:
            if !ok {
                return
            }
            // ... existing processing logic
        case <-n.stopCh:
            return
        }
    }
}

func (n *DSYNCNotifier) Close() {
    n.closeOnce.Do(func() {
        close(n.stopCh)
        <-n.doneCh
    })
}
```

Call `srv.dsyncNotifier.Close()` inside `server.Stop()` alongside `s.rrl.Close()` etc.

---

### CR-02: Webhook silently ignores HTTP 4xx/5xx response codes

**File:** `internal/dsync/webhook.go:68-73`

**Issue:** After `wc.client.Post(...)` returns without a transport error, the code closes the body and returns `nil` — regardless of `resp.StatusCode`. A webhook endpoint responding with `500 Internal Server Error`, `401 Unauthorized`, or `404 Not Found` is treated identically to `200 OK`. The caller in `handler.go:122-132` logs an error and increments the `"err"` metric label only when `Fire()` returns a non-nil error. Failed deliveries therefore count as successes in both logs and metrics.

```go
resp, err := wc.client.Post(wc.url, contentType, bytes.NewReader(body))
if err != nil {
    return fmt.Errorf("webhook POST %s: %w", wc.url, err)
}
resp.Body.Close()  // HTTP status never checked; 500 looks like success
return nil
```

The test `TestWebhookClient_FireJSON` verifies only that the body is received correctly, not that a non-2xx status produces an error.

**Fix:**

```go
resp, err := wc.client.Post(wc.url, contentType, bytes.NewReader(body))
if err != nil {
    return fmt.Errorf("webhook POST %s: %w", wc.url, err)
}
defer resp.Body.Close()
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return fmt.Errorf("webhook POST %s: unexpected status %d", wc.url, resp.StatusCode)
}
return nil
```

---

### CR-03: Nil clientIP passed to HandleInbound can create a shared limiter bucket for all unknown transports

**File:** `internal/server/server.go:443-463` and `internal/dsync/ratelimit.go:51-65`

**Issue:** `handleDNS` extracts `clientIP` via two type assertions (`*net.UDPAddr`, `*net.TCPAddr`). If `RemoteAddr()` returns any other concrete type, `clientIP` remains `nil`. The NOTIFY dispatch unconditionally calls `s.dsyncHandler.HandleInbound(w, r, clientIP)` with that nil value.

Inside `HandleInbound`, `h.limiter.Allow(nil)` is called. `Allow` calls `ip.String()` on line 52 of `ratelimit.go`. `net.IP(nil).String()` returns `"<nil>"` (does not panic), so a visitor entry is created under the key `"<nil>"`. All connections from unknown address types share one rate limiter bucket. An attacker who can reach the NOTIFY handler from such a transport can send an unlimited stream of NOTIFYs once the `"<nil>"` limiter is exhausted, since the `allowAll` ACL accepts nil IPs (line 26: `return true` unconditionally).

While a nil `net.IP` deref is not an immediate panic today, the nil-IP path is semantically wrong, and any future nil check in `SourceACL.Check` (currently `allowAll: true` guard) or the limiter that calls `ip.To4()` or `ip.Equal()` would panic.

**Fix:** Guard against nil clientIP before dispatching to the NOTIFY handler:

```go
if r.Opcode == dns.OpcodeNotify {
    if clientIP == nil {
        m := new(dns.Msg)
        m.SetReply(r)
        m.Rcode = dns.RcodeRefused
        w.WriteMsg(m) //nolint:errcheck
        return
    }
    if s.dsyncHandler != nil {
        s.dsyncHandler.HandleInbound(w, r, clientIP)
    } else {
        // ... NOTIMPL path
    }
    return
}
```

---

## Warnings

### WR-01: DSYNCNotifier uses the server's own listen address as the discovery resolver

**File:** `internal/server/server.go:265`

**Issue:**

```go
s.dsyncNotifier = dsync.NewDSYNCNotifier(cfg.UDPAddr, 60*time.Second, zerolog.Nop())
```

`cfg.UDPAddr` is the server's own UDP listen address (e.g. `:5353`, `0.0.0.0:53`, `127.0.0.1:15353`). This address is passed to `NewDSYNCNotifier` as the `resolver` parameter and used for outbound `_dsync.<parent>` discovery queries in `DiscoverDSYNC`.

Querying `0.0.0.0:53` or `:5353` will either fail (binding error on connect), loop back to the server itself (where the zone may not exist), or resolve to localhost. The server will not query the actual upstream DNS hierarchy for `_dsync` records. In practice, `DiscoverDSYNC` will find zero endpoints for every zone, all `Notify()` events will be silently discarded after the discovery step (line 81: `if err != nil || len(records) == 0 { continue }`), and all `SendDSYNCNotify` gRPC calls will return `success: true` while never actually sending a NOTIFY.

Neither `DSYNCConfig` (server level) nor `ZoneDSYNCConfig` (per zone) exposes a `Resolver` field, so there is no way for operators to configure a correct value today.

**Fix:** Add a `Resolver string` field to `DSYNCConfig` defaulting to `"8.8.8.8:53"` (or the system resolver via `net.DefaultResolver`). Use this field when constructing `DSYNCNotifier`.

---

### WR-02: Data race — metrics field written after worker goroutine starts

**File:** `internal/server/server.go:254-266`

**Issue:** In `server.New()`:

```go
limiter := dsync.NewNotifyLimiter(rps, burst)
s.dsyncHandler = dsync.NewHandler(limiter, dsync.AllowAllACL(), zerolog.Nop())
// Handler's metrics field is nil here.

dsyncMetrics := dsync.NewDSYNCMetrics()
s.dsyncHandler.SetMetrics(dsyncMetrics)   // write to metrics field

s.dsyncNotifier = dsync.NewDSYNCNotifier(cfg.UDPAddr, 60*time.Second, zerolog.Nop())
// Worker goroutine starts here and immediately reads n.metrics:
s.dsyncNotifier.SetMetrics(dsyncMetrics)  // concurrent write
```

The `DSYNCNotifier` worker goroutine starts inside `NewDSYNCNotifier` and reads `n.metrics` on every processed event (lines 97-99, 102-103 of `sender.go`). The `SetMetrics` call happens in the main goroutine immediately after but without synchronization. This is a data race under Go's memory model: `n.metrics` (a pointer) is written by the main goroutine and read concurrently by the worker goroutine. `go test -race` will flag this if an event is processed before `SetMetrics` completes.

**Fix:** Pass metrics as a constructor parameter to both `NewHandler` and `NewDSYNCNotifier`, eliminating the race window:

```go
dsyncMetrics := dsync.NewDSYNCMetrics()
s.dsyncHandler = dsync.NewHandler(limiter, dsync.AllowAllACL(), zerolog.Nop(), dsyncMetrics)
s.dsyncNotifier = dsync.NewDSYNCNotifier(cfg.UDPAddr, 60*time.Second, zerolog.Nop(), dsyncMetrics)
```

Alternatively, start the worker goroutine in a `Start()` method called after wiring is complete.

---

### WR-03: SourceACL fails open when all CIDR entries are malformed

**File:** `internal/dsync/source_acl.go:23-41`

**Issue:** Invalid CIDR entries are silently skipped. If every entry in `allowed_sources` fails parsing (e.g., due to a config typo), `nets` remains empty and the constructor sets `allowAll: true`:

```go
return &SourceACL{networks: nets, allowAll: len(nets) == 0}
```

An operator who intends to restrict NOTIFY sources to `10.0.0.0/8` but writes `"10.0.0./8"` ends up with an ACL that accepts all sources. The security failure mode is silent: no error is logged, no startup warning is emitted, and the server behaves as if no ACL was configured.

**Fix:** Return an error (or at minimum log a warning and fail closed — allow nothing — when the input list is non-empty but all entries fail to parse):

```go
func NewSourceACL(cidrs []string) (*SourceACL, error) {
    if len(cidrs) == 0 {
        return &SourceACL{allowAll: true}, nil
    }
    var nets []*net.IPNet
    for _, cidr := range cidrs {
        _, network, err := net.ParseCIDR(cidr)
        if err != nil {
            ip := net.ParseIP(cidr)
            if ip == nil {
                return nil, fmt.Errorf("invalid CIDR/IP in allowed_sources: %q", cidr)
            }
            if ip.To4() != nil {
                _, network, _ = net.ParseCIDR(cidr + "/32")
            } else {
                _, network, _ = net.ParseCIDR(cidr + "/128")
            }
        }
        if network != nil {
            nets = append(nets, network)
        }
    }
    if len(nets) == 0 {
        return nil, fmt.Errorf("allowed_sources: all %d entries were invalid", len(cidrs))
    }
    return &SourceACL{networks: nets}, nil
}
```

---

### WR-04: Context cancel not deferred inside sender loop — leaks on panic

**File:** `internal/dsync/sender.go:91-106`

**Issue:** Inside the `worker()` loop, a per-record context is created and manually cancelled at the end of each iteration:

```go
ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
if err := sendNotify(ctx2, ...); err != nil {
    // error handling
} else {
    // success handling
}
cancel2()  // ← not deferred; not called if sendNotify panics
```

If `sendNotify` panics (e.g., due to a nil dereference in the dns library on a malformed target), `cancel2()` is never called, leaking the timer goroutine created by `context.WithTimeout`. Because this runs inside a goroutine loop, the leak is multiplicative — one leaked timer goroutine per panicked send attempt.

**Fix:** Refactor the inner body into a helper function so `defer cancel()` is idiomatic and safe:

```go
func (n *DSYNCNotifier) sendToEndpoint(ev notifyEvent, rec DSYNCRecord) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := sendNotify(ctx, ev.zone, ev.qtype, rec.Target, rec.Port); err != nil {
        n.log.Error().Err(err).Str("zone", ev.zone).Str("target", rec.Target).Msg("sendNotify failed")
        if n.metrics != nil {
            n.metrics.NotifyOutbound.WithLabelValues(ev.zone, "failed").Inc()
        }
    } else if n.metrics != nil {
        n.metrics.NotifyOutbound.WithLabelValues(ev.zone, "sent").Inc()
    }
}
```

---

### WR-05: RegisterAll variadic dsyncNotifier silently ignores extra arguments

**File:** `api/grpc/registry/register.go:47`

**Issue:** `RegisterAll` accepts `dsyncNotifier ...*dsync.DSYNCNotifier`. Only `dsyncNotifier[0]` is ever used. A caller who passes multiple notifiers (possible, since Go allows it) will have all but the first silently ignored. More practically, the variadic signature obscures intent — the parameter is not "zero or more notifiers" in any meaningful sense; it is "zero or one optional notifier."

Additionally, the `connRegistry` parameter is documented as "may be nil" and is always passed as `nil` from `main.go:255` due to the chicken-and-egg problem noted in the comment. This means `ListConnections` is permanently broken in production. The comment references "Plan 05" which has already shipped (based on git history), suggesting this was never completed.

**Fix for variadic:** Replace with an explicit `*dsync.DSYNCNotifier` parameter (nil-safe):

```go
func RegisterAll(s *grpc.Server, srv SrvIface, zonesDir string, compileBin string,
    connRegistry *grpcserver.ConnRegistry, dsyncNotifier *dsync.DSYNCNotifier) {
    // ...
    if dsyncNotifier != nil {
        pb.RegisterDSYNCAdminServiceServer(s, services.NewDSYNCService(dsyncNotifier))
    }
}
```

---

## Info

### IN-01: SendDSYNCNotify does not validate zone_name as a valid DNS name

**File:** `api/grpc/services/dsync.go:38-39`

**Issue:** `SendDSYNCNotify` checks that `req.ZoneName` is non-empty but accepts any non-empty string, including malformed DNS names (`"not valid!@#"`, `"."` root zone, excessively long labels). A malformed name will be enqueued, pass through to `DiscoverDSYNC`, and produce a silent discovery failure with no feedback to the caller beyond the eventual log entry.

**Fix:**

```go
if _, ok := dns.IsDomainName(req.ZoneName); !ok {
    return nil, status.Errorf(codes.InvalidArgument,
        "zone_name %q is not a valid DNS name", req.ZoneName)
}
```

---

### IN-02: ZoneDSYNCConfig.WebhookURL is parsed but silently never used

**File:** `internal/server/server.go:268-272`

**Issue:** The comment block explicitly says the webhook is not wired:

```
// Webhook: per-zone config (ZoneDSYNCConfig.WebhookURL) — not available at
// server-level DSYNCConfig. Per-zone webhook wiring requires zone iteration
// which is not implemented yet.
```

The `WebhookURL` and `WebhookBodyFormat` fields in `ZoneDSYNCConfig` are fully parsed from config YAML but `SetWebhook` is never called. An operator who configures `dsync.webhook_url` will observe no webhook deliveries and no error.

**Fix:** Either implement per-zone webhook wiring, or emit a startup warning when `WebhookURL` is non-empty and log that it is not yet supported. At minimum, document this limitation in the config struct comment.

---

### IN-03: Two vacuous assertions in dsync_test.go provide no coverage value

**File:** `api/grpc/services/dsync_test.go:125-126`

**Issue:**

```go
assert.Equal(t, dns.TypeCDS, uint16(dns.TypeCDS), "TypeCDS should match miekg/dns")
assert.Equal(t, dns.TypeCSYNC, uint16(dns.TypeCSYNC), "TypeCSYNC should match miekg/dns")
```

`dns.TypeCDS` is already of type `uint16`; `uint16(dns.TypeCDS)` is an identity conversion. This compares a value to itself and always passes. The assertions test nothing about the service implementation.

**Fix:** Remove the assertions, or replace them with wire-value checks that document the protocol constants:

```go
assert.Equal(t, uint16(59), dns.TypeCDS, "TypeCDS wire value (RFC 7344)")
assert.Equal(t, uint16(62), dns.TypeCSYNC, "TypeCSYNC wire value (RFC 7477)")
```

---

_Reviewed: 2026-05-17_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
