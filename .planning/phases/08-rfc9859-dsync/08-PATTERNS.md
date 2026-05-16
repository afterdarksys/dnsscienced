# Phase 8: RFC 9859 DSYNC — Pattern Map

**Mapped:** 2026-05-16
**Files analyzed:** 10 new/modified files
**Analogs found:** 9 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/dsync/dsync.go` | utility (codec) | transform | `internal/rrl/limiter.go` (struct+constants pattern) | partial-match |
| `internal/dsync/handler.go` | handler/middleware | request-response | `internal/server/server.go` `handleDNS` dispatch | role-match |
| `internal/dsync/ratelimit.go` | utility (rate limiter) | request-response | `internal/rrl/limiter.go` | exact |
| `internal/dsync/sender.go` | service | request-response | `internal/firewalld/feed.go` (fire-and-forget HTTP client pattern) | role-match |
| `internal/dsync/discovery.go` | utility | request-response | `internal/resolver/` (DNS client exchange pattern) | partial-match |
| `internal/dsync/dsync_test.go` | test | — | `internal/rrl/limiter_test.go` | exact |
| `internal/config/config.go` | config | — | `internal/config/config.go` (ZoneDNSSECConfig, ThreatIntelConfig patterns) | exact |
| `internal/server/server.go` | handler (modification) | request-response | self (opcode dispatch insertion) | exact |
| `api/grpc/proto/admin.proto` | config/proto | — | `api/grpc/proto/admin.proto` (existing RPC definitions) | exact |
| `api/grpc/services/dsync.go` | service (gRPC) | request-response | `api/grpc/services/firewall.go` | exact |

---

## Pattern Assignments

### `internal/dsync/dsync.go` (utility codec, transform)

**Analog:** `internal/rrl/limiter.go` (package structure, constants block, struct definition)

**Package declaration + imports pattern** (limiter.go lines 1-9):
```go
package dsync

import (
    "encoding/binary"
    "encoding/hex"
    "fmt"

    "github.com/miekg/dns"
)
```

**Constants block pattern** (limiter.go lines 17-32 — copy the constant grouping style):
```go
// From internal/rrl/limiter.go lines 17-32
const (
    DefaultResponsesPerSecond = 5
    DefaultErrorsPerSecond    = 5
    // ...
    CategoryResponse = iota
    // ...
)
```
Apply the same grouping: first define the type constant, then scheme values:
```go
const TypeDSYNC uint16 = 66  // Not in miekg/dns v1.1.72

const (
    DSYNCSchemeNull   uint8 = 0 // No-op — receivers MUST ignore
    DSYNCSchemeNOTIFY uint8 = 1 // RFC 1996 NOTIFY
)
```

**Struct definition pattern** (limiter.go lines 111-127 — exported struct with doc comment):
```go
// From internal/rrl/limiter.go lines 111-127
type Limiter struct {
    cfg   Config
    cfgMu sync.RWMutex
    buckets sync.Map
    // ...
}
```
Apply same style for DSYNCRecord:
```go
// DSYNCRecord holds decoded DSYNC RDATA fields (RFC 9859 §2).
type DSYNCRecord struct {
    RRtype uint16 // CDS(59) or CSYNC(62)
    Scheme uint8  // 1 = NOTIFY
    Port   uint16
    Target string // FQDN
}
```

**Error wrapping pattern** (limiter.go lines 130-148 — constructor with validation, fmt.Errorf wrapping):
```go
// From internal/rrl/limiter.go lines 130-148
func NewLimiter(cfg Config) *Limiter {
    if cfg.Window == 0 {
        cfg.Window = DefaultWindow
    }
    // ...
}
```
Apply same early-validation style in DecodeDSYNC:
```go
func DecodeDSYNC(rr *dns.RFC3597) (DSYNCRecord, error) {
    raw, err := hex.DecodeString(rr.Rdata)
    if err != nil {
        return DSYNCRecord{}, fmt.Errorf("dsync hex decode: %w", err)
    }
    if len(raw) < 6 {
        return DSYNCRecord{}, fmt.Errorf("dsync rdata too short: %d bytes", len(raw))
    }
    // ...
    name, _, err := dns.UnpackDomainName(raw, 5)
    if err != nil {
        return DSYNCRecord{}, fmt.Errorf("dsync target unpack: %w", err)
    }
    // ...
}
```

---

### `internal/dsync/handler.go` (handler, request-response)

**Analog:** `internal/server/server.go` `handleDNS` function (lines 371-530)

**Imports pattern** (server.go lines 1-24):
```go
package dsync

import (
    "net"

    "github.com/miekg/dns"
)
```

**Opcode/error guard pattern** (server.go lines 422-428 — validate question before dispatch):
```go
// From internal/server/server.go lines 422-428
if len(r.Question) == 0 {
    m.Rcode = dns.RcodeFormatError
    s.errors.Add(1)
    w.WriteMsg(m)
    return
}
```
Apply same pattern at top of HandleInbound:
```go
func (h *Handler) HandleInbound(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
    if len(r.Question) == 0 {
        replyRefused(w, r)
        return
    }
    // ...
}
```

**Blackhole/ACL check then continue pattern** (server.go lines 391-406 — early return on block, otherwise fall through):
```go
// From internal/server/server.go lines 391-406
if s.defensive != nil {
    if block, action := s.defensive.CheckBlackhole(clientIP); block {
        if action == "drop" {
            return
        } else if action == "refused" {
            m.SetReply(r)
            m.Rcode = dns.RcodeRefused
            w.WriteMsg(m)
            return
        }
    }
}
```
Apply rate-limit check with same pattern: check → early-return on REFUSED, otherwise continue.

**Async dispatch pattern** (server.go lines 211-216 — goroutine with WaitGroup for background work):
```go
// From internal/server/server.go lines 211-216
s.wg.Add(1)
go func() {
    defer s.wg.Done()
    // ...
}()
```
Apply same go func pattern for scheduleDelegationCheck (no WaitGroup needed for fire-and-forget):
```go
go h.scheduleDelegationCheck(zone, qtype, clientIP)
```

---

### `internal/dsync/ratelimit.go` (utility rate limiter, request-response)

**Analog:** `internal/rrl/limiter.go` — exact role match

**Config struct pattern** (limiter.go lines 35-63):
```go
// From internal/rrl/limiter.go lines 35-63
type Config struct {
    ResponsesPerSecond int `yaml:"responses_per_second"`
    // ...
    Enabled bool `yaml:"enabled"`
}

func DefaultConfig() Config {
    return Config{
        ResponsesPerSecond: DefaultResponsesPerSecond,
        // ...
        Enabled: true,
    }
}
```
Apply for NotifyLimiter:
```go
// NotifyLimiter is per-source-IP token bucket for inbound NOTIFY rate limiting.
// Uses golang.org/x/time/rate (already in go.mod) — separate from internal/rrl.
type NotifyLimiter struct {
    mu       sync.Mutex
    visitors map[string]*notifyVisitor
    r        rate.Limit
    b        int
    stopCh   chan struct{}
    doneCh   chan struct{}
}

type notifyVisitor struct {
    lim      *rate.Limiter
    lastSeen time.Time
}
```

**Background cleanup goroutine pattern** (limiter.go lines 306-341 — ticker + stopCleanup channel):
```go
// From internal/rrl/limiter.go lines 306-341
func (l *Limiter) cleanup() {
    defer l.cleanupDone.Done()
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            l.performCleanup()
        case <-l.stopCleanup:
            return
        }
    }
}

func (l *Limiter) performCleanup() {
    now := time.Now().Unix()
    cutoff := now - int64(window*2)
    l.buckets.Range(func(key, value interface{}) bool {
        // ...
        if lastCheck < cutoff {
            l.buckets.Delete(key)
        }
        return true
    })
}
```
Apply same stop-channel + ticker pattern in NotifyLimiter, sweeping entries where `lastSeen > 10 minutes`.

**Close() pattern** (limiter.go lines 344-347):
```go
// From internal/rrl/limiter.go lines 344-347
func (l *Limiter) Close() {
    close(l.stopCleanup)
    l.cleanupDone.Wait()
}
```
Mirror exactly in NotifyLimiter.Close().

**Stats struct pattern** (limiter.go lines 351-377 — atomic counters + Stats struct):
```go
// From internal/rrl/limiter.go lines 351-377
type Stats struct {
    Allowed  uint64
    Dropped  uint64
    // ...
}
func (l *Limiter) GetStats() Stats { ... }
```
Apply same Stats+atomic pattern in NotifyLimiter.

---

### `internal/dsync/sender.go` (service, fire-and-forget outbound)

**Analog:** `internal/firewalld/feed.go` — fire-and-forget delivery, http.Client timeout, failure-logged-and-counted pattern

**HTTP client with explicit timeout pattern** (feed.go lines 46-59):
```go
// From internal/firewalld/feed.go lines 46-59
client: &http.Client{
    Timeout:   cfg.Timeout,
    Transport: transport,
},
```
Apply DNS client equivalent:
```go
c := &dns.Client{
    Net:     "udp",
    Timeout: 5 * time.Second,
}
```

**Fire-and-forget with logging on failure pattern** (feed.go lines 62-80 — goroutine started, returns immediately, error logged):
```go
// From internal/firewalld/feed.go lines 62-80
func (fw *Firewall) StartFeed(ctx context.Context, wg interface{ Add(int); Done() }) {
    if fw.cfg.ThreatIntel.FeedURL == "" {
        return // no-op guard
    }
    // ...
    wg.Add(1)
    go func() {
        defer wg.Done()
        fc.run(ctx)
    }()
}
```
Apply same no-op guard + goroutine pattern for SendDSYNCNotify:
```go
func (s *Sender) Send(ctx context.Context, zoneName string, qtype uint16) {
    go func() {
        if err := s.sendNotify(ctx, zoneName, qtype); err != nil {
            s.logger.Error().Err(err).Str("zone", zoneName).Msg("dsync outbound notify failed")
            s.failureCounter.Add(1)
        }
    }()
}
```

**Struct with logger pattern** (feed.go lines 31-42 — zerolog.Logger field on struct):
```go
// From internal/firewalld/feed.go lines 31-42
type FeedClient struct {
    cfg    ThreatIntelConfig
    engine *ThreatIntel
    logger zerolog.Logger
    client *http.Client
    // ...
}
```
Apply same struct layout for Sender.

---

### `internal/dsync/discovery.go` (utility, request-response)

**Analog:** `internal/firewalld/feed.go` (DNS query loop pattern) + RESEARCH.md Pattern 4

No exact analog exists for _dsync DNS discovery in the codebase. Use RESEARCH.md Pattern 4 directly.

**Context + timeout pattern** (feed.go lines 46-59 — context propagated to network calls):
```go
// From internal/firewalld/feed.go — context used for http.NewRequestWithContext
req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.cfg.FeedURL, nil)
```
Apply same context threading for dns.Client.ExchangeContext:
```go
resp, _, err := c.ExchangeContext(ctx, m, resolver)
```

**Early return on empty result** (feed.go and server.go — consistent "if nothing found, return nil" pattern):
```go
if len(records) == 0 {
    return nil, nil // no DSYNC endpoints — not an error
}
```

---

### `internal/dsync/dsync_test.go` and `*_test.go` files (test)

**Analog:** `internal/rrl/limiter_test.go` — exact test structure match

**Test file header pattern** (limiter_test.go lines 1-7):
```go
package rrl  // same package as tested code (white-box test)

import (
    "net"
    "testing"
    "time"
)
```
Apply: `package dsync` (white-box tests access unexported helpers).

**Table-free unit test pattern** (limiter_test.go lines 9-17 — TestXxx(t), t.Error/t.Errorf, no testify for simple cases):
```go
// From internal/rrl/limiter_test.go lines 9-17
func TestNewLimiter(t *testing.T) {
    cfg := DefaultConfig()
    limiter := NewLimiter(cfg)
    defer limiter.Close()
    if !limiter.cfg.Enabled {
        t.Error("limiter should be enabled by default")
    }
}
```
Apply same t.Error/t.Errorf style for TestDSYNCCodec, TestDSYNCDecodeTooShort.

**Rate limiting exhaustion test pattern** (limiter_test.go lines 41-68):
```go
// From internal/rrl/limiter_test.go lines 41-68
func TestCheck_RateLimit(t *testing.T) {
    cfg := DefaultConfig()
    cfg.ResponsesPerSecond = 2
    cfg.Window = 1
    limiter := NewLimiter(cfg)
    defer limiter.Close()
    // Exhaust tokens
    for i := 0; i < 2; i++ {
        action := limiter.Check(...)
        if action != ActionAllow { t.Errorf(...) }
    }
    // Next should be rate limited
    action := limiter.Check(...)
    if action == ActionAllow { t.Error("should be rate limited") }
}
```
Copy exact structure for TestNotifyRateLimiter: construct limiter with small rate, exhaust, assert blocked.

---

### `internal/config/config.go` (config, modification)

**Analog:** self — `ZoneDNSSECConfig` struct (lines 133-146) and `ThreatIntelConfig` struct

**Per-zone optional config struct pattern** (config.go lines 100-101 and 133-146):
```go
// From internal/config/config.go lines 100-101
DNSSECSigning *ZoneDNSSECConfig `yaml:"dnssec_signing,omitempty"`

// From internal/config/config.go lines 133-146
type ZoneDNSSECConfig struct {
    Enabled           bool          `yaml:"enabled"`
    Algorithm         string        `yaml:"algorithm"`
    KSKLifetime       time.Duration `yaml:"ksk_lifetime"`
    ZSKLifetime       time.Duration `yaml:"zsk_lifetime"`
    // ...
}
```
Add after `DNSSECSigning` field:
```go
DSYNC *ZoneDSYNCConfig `yaml:"dsync,omitempty"`
```
And new struct:
```go
// ZoneDSYNCConfig controls RFC 9859 generalized notifications for a zone.
type ZoneDSYNCConfig struct {
    NotifyParent     bool          `yaml:"notify_parent"`
    PropagationDelay time.Duration `yaml:"propagation_delay"`
}
```

**Pointer-to-config pattern for optional feature** (config.go lines 100-101 — pointer means nil = not configured):
```go
DNSSECSigning *ZoneDNSSECConfig `yaml:"dnssec_signing,omitempty"`
```
Use same `*ZoneDSYNCConfig` pointer — nil means DSYNC not configured for zone.

**ThreatIntelConfig pattern** (firewalld/config.go lines 79-114) for the global server-level DSYNCConfig:
```go
// From internal/firewalld/config.go lines 79-114
type ThreatIntelConfig struct {
    // ...
    FeedURL      string        `yaml:"feed_url"`
    PollInterval time.Duration `yaml:"poll_interval"`
    Timeout      time.Duration `yaml:"timeout"`
    Enabled bool `yaml:"enabled"`  // implicit via FeedURL
}
```
Apply same field ordering (bool enabled first, then durations, then numerics) for:
```go
type DSYNCConfig struct {
    Enabled       bool    `yaml:"enabled"`
    RatePerSecond float64 `yaml:"rate_per_second"`
    Burst         int     `yaml:"burst"`
}
```

---

### `internal/server/server.go` (modification — opcode dispatch)

**Analog:** self — existing handleDNS function structure (lines 371-530)

**Field addition to Server struct pattern** (server.go lines 115-146 — add field alongside rrl):
```go
// From internal/server/server.go lines 119-126
type Server struct {
    cfg Config
    recursive   *resolver.Recursive
    cookies     *cookie.Manager
    rrl         *rrl.Limiter      // ← existing: pattern to follow
    defensive   *defensive.Manager
    // ...
}
```
Add `dsync *dsync.Handler` field in the same style, adjacent to `rrl`.

**Config-guarded initialization pattern** (server.go lines 219-224):
```go
// From internal/server/server.go lines 219-224
if cfg.EnableRRL {
    s.rrl = rrl.NewLimiter(cfg.RRLConfig)
}
```
Mirror for DSYNC:
```go
if cfg.DSYNC.Enabled {
    s.dsync = dsync.NewHandler(cfg.DSYNC)
}
```

**Opcode dispatch insertion point** — insert before the `len(r.Question) == 0` check (line 422) so NOTIFY is short-circuited before question validation:
```go
// INSERT before line 422 in handleDNS:
if r.Opcode == dns.OpcodeNotify {
    if s.dsync != nil {
        s.dsync.HandleInbound(w, r, clientIP)
    } else {
        m := pool.GetMessage()
        defer pool.PutMessage(m)
        m.SetReply(r)
        m.Rcode = dns.RcodeNotImplemented
        w.WriteMsg(m)
    }
    return
}
```

---

### `api/grpc/proto/admin.proto` (modification — new RPC)

**Analog:** self — existing `AdminService` definition (lines 11-55) and `FirewallAdminService` (lines 386-393)

**New service pattern** (admin.proto lines 386-393 — additive separate service, not modifying AdminService):
```go
// From api/grpc/proto/admin.proto lines 386-393
// FirewallAdminService exposes firewall management operations over gRPC.
// Additive to AdminService — registered on the same admin gRPC server port.
service FirewallAdminService {
  rpc FirewallStats(FirewallStatsRequest) returns (FirewallStatsResponse);
  // ...
}
```
Add a `DSYNCAdminService` following the same additive-service pattern:
```proto
// DSYNCAdminService exposes RFC 9859 DSYNC operations over gRPC.
// Additive to AdminService — registered on the same admin gRPC server port.
service DSYNCAdminService {
  rpc SendDSYNCNotify(SendDSYNCNotifyRequest) returns (SendDSYNCNotifyResponse);
}

message SendDSYNCNotifyRequest {
  string zone_name = 1;
  string qtype     = 2; // "CDS" or "CSYNC"
}

message SendDSYNCNotifyResponse {
  bool   success = 1;
  string message = 2;
}
```

**Simple boolean success message pattern** (admin.proto lines 253-259 — success+message pair):
```proto
// From admin.proto lines 253-259
message AdminCreateZoneResponse {
  bool   success = 1;
  string message = 2;
  // ...
}
```
Use the same `bool success + string message` pair in SendDSYNCNotifyResponse.

---

### `api/grpc/services/dsync.go` (gRPC service, request-response)

**Analog:** `api/grpc/services/firewall.go` — exact role match (thin wrapper service)

**Full file structure pattern** (firewall.go lines 1-82):
```go
// From api/grpc/services/firewall.go lines 1-25
package services

import (
    "context"

    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
    "github.com/dnsscience/dnsscienced/internal/dsync"
)

// DSYNCService implements pb.DSYNCAdminServiceServer.
// Thin wrapper — no business logic lives here.
type DSYNCService struct {
    pb.UnimplementedDSYNCAdminServiceServer
    handler *dsync.Handler
}

func NewDSYNCService(h *dsync.Handler) *DSYNCService {
    return &DSYNCService{handler: h}
}
```

**Input validation pattern** (firewall.go lines 40-50):
```go
// From api/grpc/services/firewall.go lines 40-50
func (s *FirewallService) LoadScript(_ context.Context, req *pb.FirewallLoadScriptRequest) (*pb.FirewallLoadScriptResponse, error) {
    if req.ScriptId == "" {
        return nil, status.Error(codes.InvalidArgument, "script_id is required")
    }
    if req.Body == "" {
        return nil, status.Error(codes.InvalidArgument, "body is required")
    }
    if err := s.fw.LoadSource(req.ScriptId, req.Body); err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "compile script: %v", err)
    }
    return &pb.FirewallLoadScriptResponse{ScriptId: req.ScriptId}, nil
}
```
Apply same `if req.Field == "" { return nil, status.Error(codes.InvalidArgument, ...) }` pattern in SendDSYNCNotify.

**Error wrapping to gRPC status pattern** (firewall.go lines 47-49):
```go
if err := s.fw.LoadSource(...); err != nil {
    return nil, status.Errorf(codes.InvalidArgument, "compile script: %v", err)
}
```
Use `codes.Internal` for unexpected errors from dsync.Handler.

---

## Shared Patterns

### Config Struct with Optional Pointer
**Source:** `internal/config/config.go` `ZoneDNSSECConfig` field (line 100-101) + `ZoneDNSSECConfig` struct (lines 133-146)
**Apply to:** `ZoneDSYNCConfig` addition to `ZoneConfig`, `DSYNCConfig` addition to `server.Config`

```go
// Pointer = optional (nil means not configured) — same as DNSSECSigning
DSYNC *ZoneDSYNCConfig `yaml:"dsync,omitempty"`
```

### Background Goroutine with Stop Channel
**Source:** `internal/rrl/limiter.go` lines 125-147 and 306-347
**Apply to:** `internal/dsync/ratelimit.go` (stale-entry sweep), `internal/dsync/sender.go` (propagation delay queue)

```go
// From internal/rrl/limiter.go lines 125-147
l := &Limiter{
    stopCleanup: make(chan struct{}),
}
l.cleanupDone.Add(1)
go l.cleanup()
// ...
func (l *Limiter) Close() {
    close(l.stopCleanup)
    l.cleanupDone.Wait()
}
```

### Error Wrapping with %w
**Source:** `internal/rrl/limiter.go` and `internal/server/server.go` lines 161, 165, 170
**Apply to:** All new `internal/dsync/*.go` files

```go
// From internal/server/server.go lines 161-162
if err != nil {
    cancel()
    return nil, fmt.Errorf("init recursive resolver: %w", err)
}
```

### gRPC Thin Wrapper (UnimplementedXxx + delegate)
**Source:** `api/grpc/services/firewall.go` lines 13-23
**Apply to:** `api/grpc/services/dsync.go`

```go
type FirewallService struct {
    pb.UnimplementedFirewallAdminServiceServer  // embed for forward compat
    fw *firewalld.Firewall
}
func NewFirewallService(fw *firewalld.Firewall) *FirewallService {
    return &FirewallService{fw: fw}
}
```

### White-Box Package Test
**Source:** `internal/rrl/limiter_test.go` line 1 (`package rrl`)
**Apply to:** All `internal/dsync/*_test.go` files — use `package dsync` (not `package dsync_test`) to access unexported helpers.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `internal/dsync/discovery.go` | utility | request-response | No `_dsync.<parent>` DNS label-walking lookup exists in the codebase. Use RESEARCH.md Pattern 4 directly. Note: `dns.SplitDomainName` + loop over labels is the prescribed approach. |

---

## Metadata

**Analog search scope:** `internal/rrl/`, `internal/server/`, `internal/config/`, `internal/firewalld/`, `internal/zone/`, `api/grpc/services/`, `api/grpc/proto/`
**Files scanned:** 14 source files read directly
**Pattern extraction date:** 2026-05-16
