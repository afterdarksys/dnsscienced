# Phase 3: Live Threat Feed - Research

**Researched:** 2026-04-23
**Domain:** Go background HTTP polling, goroutine lifecycle, feed parsing
**Confidence:** HIGH

## Summary

Phase 3 adds a background HTTP poller (`FeedClient`) that fetches newline-delimited threat scores
from a configured URL and injects them into the live `ThreatIntel` engine. The existing codebase
provides all required integration points: `AddDomainScore`/`AddIPScore`/`RemoveDomainScore` are
already mutex-protected, `ThreatIntelEngine()` exposes the engine, and the server's `context.Context`
lifecycle (`s.ctx` / `s.cancel`) is the correct hook for goroutine management.

The two concrete gaps that need code: (1) `ThreatIntelConfig` does not yet have feed fields (FeedURL,
PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers) — they must be added to `config.go`; (2)
`RemoveIPScore` does not exist on `*ThreatIntel` — it must be added in `threat_intel.go` before
full-replace semantics can work on IP entries.

**Primary recommendation:** Implement in three focused changes — extend config, add `RemoveIPScore`,
then write `feed.go` with `FeedClient`. Wire into server.go at the existing firewall init block.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Lines are whitespace-delimited `<target> <score>` — e.g., `example.com 75` or `1.2.3.0/24 60`.
- **D-02:** Lines starting with `#` are comments, silently skipped. Blank lines also skipped.
- **D-03:** Type detection is automatic: `net.ParseCIDR` → `net.ParseIP` → domain. No explicit type prefix.
- **D-04:** Malformed lines logged at WARN with line content and line number, then skipped.
- **D-05:** Full replace on each fetch. FeedClient tracks previous cycle's injected entries; removes all before applying new fetch.
- **D-06:** Latest feed score wins when target appears in consecutive fetches with different score.
- **D-07:** All feed config lives flat inside `threat_intel:` in config.yaml.
- **D-08:** Default `poll_interval` = 5 minutes; default `timeout` = 30 seconds.
- **D-09:** If `feed_url` is empty/unset, no poller is started. Not a config error.
- **D-10:** HTTP client configurable: `timeout`, `tls_skip_verify`, `auth_token`, `headers`.
- **D-11:** `auth_token` sent as `Authorization: Bearer <value>` when non-empty.
- **D-12:** `auth_token` redacted from all log output. Log `auth: bearer (set)` or `auth: none`.
- **D-13:** Follow redirects by default (standard HTTP client behavior).
- **D-14:** On HTTP failure (timeout, 4xx, 5xx): log error, keep previous feed-sourced scores, retry next interval.

### Claude's Discretion

- Poller goroutine lifecycle: use context derived from server shutdown signal (`s.ctx`).
- Log level: DEBUG for individual entries, INFO for fetch summary.
- Score range clamping: clamp to [0, 100] before calling AddDomainScore/AddIPScore.

### Deferred Ideas (OUT OF SCOPE)

- Multiple feed sources (FEED-06)
- Authenticated endpoints beyond Bearer token (API key, mTLS)
- Feed health metrics (Prometheus gauge for last successful fetch time)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FEED-01 | Operator can configure a threat feed URL in config.yaml | Config extension: add FeedURL + 4 companion fields to ThreatIntelConfig |
| FEED-02 | Server polls configured feed URL at configurable interval and ingests domain/IP scores | FeedClient.Start() goroutine using time.NewTicker; wire into server.Start() |
| FEED-03 | Feed client calls AddDomainScore/AddIPScore on ThreatIntelEngine for each entry | Both methods already exist, mutex-protected; RemoveIPScore must be added for full-replace |
| FEED-04 | Feed errors are logged and do not crash the server | Non-destructive on error: retain previous scores; log and continue |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| HTTP feed fetching | Background goroutine (`internal/firewalld/feed.go`) | — | Belongs in the firewall package alongside the engine it feeds |
| Feed config parsing | Config layer (`internal/firewalld/config.go`) | — | All firewall config lives in ThreatIntelConfig struct |
| Score injection | `*ThreatIntel` (`threat_intel.go`) | — | Thread-safe engine already owns Add/Remove methods |
| Goroutine lifecycle | Server (`internal/server/server.go`) | Firewall (`feed.go` Start/Stop) | Server owns the root context; feed client respects it |
| Feed entry type detection | `internal/firewalld/feed.go` (parse step) | — | net.ParseCIDR / net.ParseIP / domain heuristic inline in parse |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `net/http` (stdlib) | go1.25 | HTTP feed fetching | Already in use; custom transport for TLS skip verify |
| `crypto/tls` (stdlib) | go1.25 | TLS config for skip-verify | Stdlib; used with `http.Transport` |
| `net` (stdlib) | go1.25 | `net.ParseCIDR` / `net.ParseIP` for type detection | Already imported in `threat_intel.go` |
| `bufio` (stdlib) | go1.25 | `bufio.Scanner` for line-by-line feed parsing | Standard Go idiom for text line scanning |
| `strconv` (stdlib) | go1.25 | `strconv.Atoi` for score parsing | Stdlib |
| `time` (stdlib) | go1.25 | `time.NewTicker` for poll interval | Standard Go ticker pattern |
| `context` (stdlib) | go1.25 | Context propagation for goroutine cancellation | Already used in server.go |
| `github.com/rs/zerolog` | v1.35.0 | Logging (WARN for parse errors, INFO for fetch summary) | Project-wide logging library [VERIFIED: go.mod] |

All libraries are already in go.mod — no new dependencies required. [VERIFIED: /Users/ryan/development/dnsscienced/go.mod]

### No new `go get` commands needed
Everything required is in the Go standard library or already imported by the project.

## Architecture Patterns

### System Architecture Diagram

```
server.Start()
    │
    ├── if cfg.Firewall.FeedURL != ""
    │       └── go fw.StartFeed(ctx)
    │                 │
    │           time.NewTicker(PollInterval)
    │                 │
    │           ┌─────┴──────┐
    │           │  fetch()   │  ← net/http GET with timeout, Bearer auth, custom headers
    │           │            │
    │           │  parse()   │  ← bufio.Scanner, line-by-line
    │           │            │     net.ParseCIDR → IP/CIDR
    │           │            │     net.ParseIP → plain IP
    │           │            │     else → domain
    │           │            │
    │           │  apply()   │  ← remove prev cycle entries (full-replace)
    │           │            │     clamp score [0,100]
    │           │            │     AddDomainScore / AddIPScore
    │           └─────┬──────┘
    │                 │
    │           <-ctx.Done()  ← server Stop() calls s.cancel()
    │                 │
    │           return (goroutine exits)
    │
    └── server continues normal query handling
```

### Recommended Project Structure

New file — everything else already exists:

```
internal/firewalld/
├── config.go          # EXTEND: add feed fields to ThreatIntelConfig + DefaultConfig()
├── threat_intel.go    # EXTEND: add RemoveIPScore()
├── feed.go            # NEW: FeedClient struct + Start() + fetch() + parse() + apply()
├── feed_test.go       # NEW: unit tests with httptest.NewServer mock
├── firewalld.go       # WIRE: StartFeed(ctx) method on *Firewall
└── ... (unchanged)
internal/server/
└── server.go          # WIRE: call fw.StartFeed(s.ctx) in New() after firewalld.New()
```

### Pattern 1: Config Extension

Add to `ThreatIntelConfig` struct in `config.go`:

```go
// Source: existing pattern in config.go — flat yaml struct fields
type ThreatIntelConfig struct {
    BlockThreshold int                    `yaml:"block_threshold"`
    StaticIPScores map[string]int         `yaml:"static_ip_scores"`
    ZoneScores     map[string]int         `yaml:"zone_scores"`
    CustomerMeta   map[string]CustomerMeta `yaml:"customer_meta"`

    // Feed poller config (D-07 through D-14)
    FeedURL       string            `yaml:"feed_url"`
    PollInterval  time.Duration     `yaml:"poll_interval"`
    Timeout       time.Duration     `yaml:"timeout"`
    TLSSkipVerify bool              `yaml:"tls_skip_verify"`
    AuthToken     string            `yaml:"auth_token"`
    Headers       map[string]string `yaml:"headers"`
}
```

Add defaults to `DefaultConfig()`:

```go
// Source: existing DefaultConfig() pattern in config.go
ThreatIntel: ThreatIntelConfig{
    BlockThreshold: 80,
    StaticIPScores: make(map[string]int),
    ZoneScores:     make(map[string]int),
    CustomerMeta:   make(map[string]CustomerMeta),
    PollInterval:   5 * time.Minute,   // D-08
    Timeout:        30 * time.Second,  // D-08
},
```

### Pattern 2: RemoveIPScore (missing method)

Add to `threat_intel.go` immediately after `RemoveDomainScore`:

```go
// Source: mirrors RemoveDomainScore pattern in threat_intel.go line 165-169
// RemoveIPScore removes a previously-injected IP score.
func (ti *ThreatIntel) RemoveIPScore(ip string) {
    ti.dynMu.Lock()
    delete(ti.dynIPs, ip)
    ti.dynMu.Unlock()
}
```

### Pattern 3: FeedClient Core Structure

```go
// Source: [ASSUMED] standard Go background worker pattern; validated against project patterns
package firewalld

import (
    "bufio"
    "context"
    "crypto/tls"
    "fmt"
    "net"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

// FeedClient polls a remote threat-intel feed and injects scores into ThreatIntel.
type FeedClient struct {
    cfg    ThreatIntelConfig
    engine *ThreatIntel
    logger zerolog.Logger

    // Track entries injected last cycle for full-replace semantics (D-05).
    prevDomains map[string]bool
    prevIPs     map[string]bool

    client *http.Client
}

func newFeedClient(cfg ThreatIntelConfig, engine *ThreatIntel) *FeedClient {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}, //nolint:gosec
    }
    return &FeedClient{
        cfg:         cfg,
        engine:      engine,
        logger:      log.With().Str("component", "feed_client").Logger(),
        prevDomains: make(map[string]bool),
        prevIPs:     make(map[string]bool),
        client: &http.Client{
            Timeout:   cfg.Timeout,
            Transport: transport,
        },
    }
}
```

### Pattern 4: Goroutine Lifecycle

```go
// Source: mirrors server.go goroutine pattern — s.ctx passed to Start()
// StartFeed launches the background poller if FeedURL is configured.
// It returns immediately; the poller runs until ctx is cancelled.
func (fw *Firewall) StartFeed(ctx context.Context) {
    if fw.cfg.ThreatIntel.FeedURL == "" {
        return // D-09: no poller when feed_url is empty
    }
    fc := newFeedClient(fw.cfg.ThreatIntel, fw.intel)
    go fc.run(ctx)
}

func (fc *FeedClient) run(ctx context.Context) {
    // Fetch immediately on start, then on ticker.
    fc.fetchAndApply()

    ticker := time.NewTicker(fc.cfg.PollInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            fc.fetchAndApply()
        }
    }
}
```

### Pattern 5: Feed Parsing

```go
// Source: [ASSUMED] standard bufio.Scanner text parsing pattern
type feedEntry struct {
    target string
    score  int
    isIP   bool   // true for IP/CIDR, false for domain
    key    string // normalized key for deduplication (IP string or lower-cased domain)
}

func parseFeed(body io.Reader) ([]feedEntry, []string) {
    var entries []feedEntry
    var warnings []string

    scanner := bufio.NewScanner(body)
    lineNum := 0
    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue // D-02: skip comments and blank lines
        }

        fields := strings.Fields(line)
        if len(fields) < 2 {
            warnings = append(warnings, fmt.Sprintf("line %d: missing score: %q", lineNum, line))
            continue // D-04
        }

        target := fields[0]
        score, err := strconv.Atoi(fields[1])
        if err != nil {
            warnings = append(warnings, fmt.Sprintf("line %d: non-numeric score: %q", lineNum, line))
            continue // D-04
        }

        // Clamp score [0,100] per discretion decision.
        if score < 0 { score = 0 }
        if score > 100 { score = 100 }

        // Type detection: D-03
        entry := feedEntry{target: target, score: score}
        if _, _, err := net.ParseCIDR(target); err == nil {
            entry.isIP = true
            entry.key = target
        } else if ip := net.ParseIP(target); ip != nil {
            entry.isIP = true
            entry.key = ip.String() // normalize
        } else {
            entry.isIP = false
            entry.key = strings.ToLower(target)
        }
        entries = append(entries, entry)
    }
    return entries, warnings
}
```

### Pattern 6: Full-Replace Apply (D-05)

```go
// Source: [ASSUMED] D-05 semantics from CONTEXT.md
func (fc *FeedClient) apply(entries []feedEntry) {
    // Step 1: remove all entries from previous cycle.
    for domain := range fc.prevDomains {
        fc.engine.RemoveDomainScore(domain)
    }
    for ip := range fc.prevIPs {
        fc.engine.RemoveIPScore(ip)
    }

    // Step 2: inject new entries; track for next cycle.
    newDomains := make(map[string]bool, len(entries))
    newIPs := make(map[string]bool, len(entries))

    for _, e := range entries {
        if e.isIP {
            fc.engine.AddIPScore(e.key, e.score)
            newIPs[e.key] = true
        } else {
            fc.engine.AddDomainScore(e.key, e.score)
            newDomains[e.key] = true
        }
    }

    fc.prevDomains = newDomains
    fc.prevIPs = newIPs
}
```

### Pattern 7: HTTP Fetch with Auth

```go
// Source: [ASSUMED] standard net/http pattern; D-11, D-12, D-14
func (fc *FeedClient) fetch() (io.ReadCloser, error) {
    req, err := http.NewRequest(http.MethodGet, fc.cfg.FeedURL, nil)
    if err != nil {
        return nil, err
    }

    // D-11: Bearer auth when set
    if fc.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+fc.cfg.AuthToken)
    }

    // D-10: custom headers
    for k, v := range fc.cfg.Headers {
        req.Header.Set(k, v)
    }

    resp, err := fc.client.Do(req)
    if err != nil {
        return nil, err
    }
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        resp.Body.Close()
        return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    return resp.Body, nil
}
```

### Pattern 8: Server Wiring

In `server.go`, after the `firewalld.New()` block (lines 190-198):

```go
// Wire feed poller when feed_url is configured.
// Source: mirrors existing nil-guard pattern in server.go
if s.firewall != nil && cfg.Firewall.ThreatIntel.FeedURL != "" {
    s.firewall.StartFeed(s.ctx)
}
```

This goes in `New()` before `return s, nil`.

### Pattern 9: Logging Convention

```go
// Source: zerolog pattern used throughout project (firewalld.go logger usage)
// D-12: auth token redaction
authDesc := "none"
if fc.cfg.AuthToken != "" {
    authDesc = "bearer (set)"
}
fc.logger.Info().
    Str("url", fc.cfg.FeedURL).
    Str("auth", authDesc).
    Dur("interval", fc.cfg.PollInterval).
    Msg("feed poller started")

// Per-fetch INFO summary
fc.logger.Info().
    Int("entries", len(entries)).
    Int("warnings", len(warnings)).
    Dur("elapsed", elapsed).
    Msg("feed fetch complete")

// Individual entry at DEBUG
fc.logger.Debug().Str("target", e.key).Int("score", e.score).Msg("feed entry applied")

// D-04 WARN for malformed lines
fc.logger.Warn().Str("line", line).Int("line_num", lineNum).Msg("feed: malformed line skipped")

// D-14 error on HTTP failure — keep previous scores intact
fc.logger.Error().Err(err).Msg("feed fetch failed, retaining previous scores")
```

### Anti-Patterns to Avoid

- **Do not call `RemoveIPScore`/`RemoveDomainScore` only on failure.** They must be called at the START of every successful fetch cycle (full-replace, D-05). If the fetch fails, skip removal — retain previous scores (D-14).
- **Do not log `auth_token` value anywhere.** Only log presence/absence (D-12). This includes debug log lines.
- **Do not block server startup on feed.** `StartFeed` launches a goroutine; it must return immediately. The first fetch happens inside `run()`.
- **Do not use `context.Background()` for the poller.** Use the server's `s.ctx` so the poller exits when `Stop()` is called.
- **Do not panic on malformed lines.** Log WARN and continue (D-04).
- **Do not use `panic` or `log.Fatal` in the feed client.** The design requirement (FEED-04) is that feed errors never crash the server.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Line scanning | Custom byte reader | `bufio.Scanner` | Handles edge cases (partial lines, large buffers, newline variants) |
| HTTP client | `net.Dial` manually | `net/http.Client` with `http.Transport` | Handles redirects (D-13), timeouts, connection reuse |
| TLS skip-verify | Custom TLS dial | `crypto/tls.Config{InsecureSkipVerify: true}` on `http.Transport` | Standard, auditable |
| Score integer parse | Regex or manual | `strconv.Atoi` | Stdlib, zero deps |
| Goroutine shutdown | Custom channel | `context.WithCancel` + `select` | Already the project's established pattern |
| IP type detection | Regex or string split | `net.ParseCIDR` then `net.ParseIP` | stdlib, correct for IPv4/IPv6/CIDR |

**Key insight:** Every sub-problem in this phase has a stdlib solution. No new dependencies.

## Runtime State Inventory

> Not applicable. This is a greenfield feature addition (new file `feed.go`). No data migration or runtime state rename involved.

## Common Pitfalls

### Pitfall 1: Removing Entries on Error (Breaking D-14)

**What goes wrong:** Implementor calls `RemoveDomainScore`/`RemoveIPScore` for previous entries at the start of `fetchAndApply()`, then the HTTP fetch fails — leaving the engine with NO scores from the feed.

**Why it happens:** Logical: "start fresh each cycle" applied unconditionally.

**How to avoid:** Only remove previous entries AFTER a successful fetch and parse. If fetch fails, skip the remove step entirely and return early. Previous scores remain active.

**Warning signs:** After a feed error, threat scores that were previously elevated return to 0.

### Pitfall 2: AuthToken in Logs

**What goes wrong:** `fc.logger.Debug().Str("token", fc.cfg.AuthToken)` leaks credentials to log files.

**Why it happens:** Standard debug-all approach during development.

**How to avoid:** Always log `authDesc` computed once: `if token != "" { authDesc = "bearer (set)" }`. Never reference `AuthToken` in any log field value.

**Warning signs:** Log file contains a string starting with `Bearer ` or a raw token value.

### Pitfall 3: TLSSkipVerify Gosec Warning

**What goes wrong:** `InsecureSkipVerify: cfg.TLSSkipVerify` triggers `gosec` lint warning G402.

**Why it happens:** Gosec flags all `InsecureSkipVerify: true` usage.

**How to avoid:** Add `//nolint:gosec` comment on the `TLSClientConfig` line. The field is user-controlled and intentional.

**Warning signs:** CI fails with `G402: TLS InsecureSkipVerify set to true`.

### Pitfall 4: IP Key Normalization Inconsistency

**What goes wrong:** `AddIPScore("1.2.3.4", 60)` then `RemoveIPScore("::ffff:1.2.3.4")` — different string representations of the same IP cause the remove to miss, leaving stale scores.

**Why it happens:** `net.ParseIP` can return IPv4-mapped IPv6 representation.

**How to avoid:** Always normalize through `ip.String()` on the parsed `net.IP` value — not on the raw string from the feed. `net.ParseIP("1.2.3.4").String()` returns `"1.2.3.4"` consistently.

**Warning signs:** After a feed cycle where an IP was removed, that IP's score persists in queries.

### Pitfall 5: Race on prevDomains/prevIPs

**What goes wrong:** `prevDomains` and `prevIPs` are maps mutated by the goroutine and potentially read externally.

**Why it happens:** Shared mutable state.

**How to avoid:** `prevDomains`/`prevIPs` are only accessed inside the single `run()` goroutine. No external readers. This is safe by design — document it with a comment.

### Pitfall 6: Wiring in Start() vs New()

**What goes wrong:** `StartFeed` called in `Start()` instead of `New()` — but `s.ctx` is created in `New()`. If the server errors before `Start()`, the goroutine is never launched (OK), but the wiring point must be consistent.

**Why it happens:** `Start()` is where goroutines launch for DNS listeners.

**How to avoid:** Check the existing pattern. In this project, `s.ctx` is available from `New()` and components are initialized there. `StartFeed` can be called in `New()` right after `firewalld.New()` — or in `Start()`. Either works because `s.ctx` exists by then. The CONTEXT.md suggests in `New()` at lines 190-196 vicinity; follow that.

**Correct approach:** Wire in `New()` alongside the other component initializations, not in `Start()`.

## Code Examples

### Mock HTTP server for testing (httptest pattern)

```go
// Source: [VERIFIED: net/http/httptest stdlib — standard Go test pattern]
import "net/http/httptest"

func TestFeedClient_ParseAndApply(t *testing.T) {
    body := "example.com 75\n1.2.3.0/24 60\n# comment line\nbadline\n"
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, body)
    }))
    defer srv.Close()

    cfg := ThreatIntelConfig{
        FeedURL:      srv.URL,
        PollInterval: time.Minute,
        Timeout:      5 * time.Second,
    }
    engine := newThreatIntel(cfg)
    fc := newFeedClient(cfg, engine)
    fc.fetchAndApply()

    // Verify domain score injected
    // (access via engine.dynDomains or via Score() with a QueryContext)
}
```

### Context cancellation test

```go
// Source: [ASSUMED] standard context cancellation test pattern
func TestFeedClient_StopsOnContextCancel(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, "example.com 50\n")
    }))
    defer srv.Close()

    cfg := ThreatIntelConfig{
        FeedURL:      srv.URL,
        PollInterval: 10 * time.Millisecond,
        Timeout:      5 * time.Second,
    }
    engine := newThreatIntel(cfg)
    fc := newFeedClient(cfg, engine)

    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})
    go func() {
        defer close(done)
        fc.run(ctx)
    }()

    cancel()
    select {
    case <-done:
        // OK
    case <-time.After(500 * time.Millisecond):
        t.Fatal("goroutine did not exit after context cancel")
    }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `ioutil.ReadAll` then split lines | `bufio.Scanner` for streaming line scan | Go 1.16+ (`ioutil` deprecated) | Use `bufio.Scanner` — never `ioutil` |
| `http.Get` (package-level) | `*http.Client` instance | Always best practice | Instance client allows timeout + TLS config |

**Deprecated/outdated:**
- `ioutil.ReadAll`: deprecated in Go 1.16. Use `io.ReadAll` (stdlib). However for line scanning, `bufio.Scanner` is more idiomatic than `io.ReadAll` + `strings.Split`.
- Package-level `http.Get`/`http.Post`: never use in production code — no timeout, shared transport.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `net.ParseIP("1.2.3.4").String()` always returns `"1.2.3.4"` (not IPv4-mapped form) | Pitfall 4, Pattern 5 | IP key mismatch; stale scores not removed |
| A2 | `wg.Add/Done` not required for feed goroutine — `s.ctx` cancellation + goroutine exit is sufficient | Pattern 4 (wiring) | If server waits on WaitGroup before returning from Stop(), feed goroutine may leak briefly |
| A3 | `StartFeed` wired in `New()` rather than `Start()` is safe — both are called before query handling begins | Pattern 8 | Not a correctness issue; timing only |

**On A1:** [VERIFIED: net.ParseIP docs and Go playground — `net.ParseIP("1.2.3.4").String()` returns `"1.2.3.4"`, not the mapped form. The mapped form `"::ffff:1.2.3.4"` only appears if explicitly constructed.]

**On A2:** The server uses `s.wg.Wait()` in `Stop()`. The feed goroutine is currently not tracked in `s.wg`. The planner should decide whether to add `s.wg.Add(1)` before launching the goroutine (preferred for clean shutdown) or accept that the goroutine exits independently when `s.ctx` is cancelled.

## Open Questions (RESOLVED)

1. **WaitGroup tracking for feed goroutine**
   - What we know: `server.Stop()` calls `s.wg.Wait()` before closing components. UDP/TCP goroutines are tracked. The feed goroutine currently would not be tracked.
   - What's unclear: Whether the plan should add `s.wg.Add(1)` / `defer s.wg.Done()` inside `run()` (requires passing `wg` into FeedClient or using a closure).
   - Recommendation: Track it. Add `s.wg.Add(1)` before `go fc.run(ctx)` in `StartFeed`. Pass `*sync.WaitGroup` as parameter, or launch from `server.go` with a closure that calls `s.wg.Done()`.
   - [RESOLVED] Plan 03-02 `StartFeed` takes `wg interface{ Add(int); Done() }` as parameter; Plan 03-03 wires it as `s.firewall.StartFeed(s.ctx, &s.wg)`.

2. **FeedURL already claimed to exist in config.go**
   - What we know: STATE.md says "ThreatIntelConfig.FeedURL field exists in config.go but is unused." Code inspection shows this is FALSE — no FeedURL field exists in `config.go`.
   - What's unclear: Whether this was an error in STATE.md or was removed at some point.
   - Recommendation: Plan must add FeedURL (and all companion fields) as if starting from scratch. Do not assume it pre-exists.
   - [RESOLVED] Plan 03-01 Task 1 adds all 6 feed fields to ThreatIntelConfig from scratch (FeedURL, PollInterval, Timeout, TLSSkipVerify, AuthToken, Headers).

## Environment Availability

Phase is code-only. No external services, CLIs, or databases beyond the existing Go toolchain are required.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Build | ✓ | go1.25.0 | — |
| `net/http`, `bufio`, `crypto/tls` | Feed client | ✓ | stdlib | — |
| `github.com/rs/zerolog` | Logging | ✓ | v1.35.0 | — |
| `net/http/httptest` | Unit tests | ✓ | stdlib | — |

**No missing dependencies.**

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | go test (stdlib) + testify v1.11.1 |
| Config file | none (standard `go test`) |
| Quick run command | `go test ./internal/firewalld/... -run TestFeed -v` |
| Full suite command | `go test ./internal/firewalld/... -v` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FEED-01 | FeedURL + companion fields in config.yaml parse correctly | unit | `go test ./internal/firewalld/... -run TestFeedConfig -v` | ❌ Wave 0 |
| FEED-02 | Poller fetches on interval; context cancel stops it | unit | `go test ./internal/firewalld/... -run TestFeedClient_Lifecycle -v` | ❌ Wave 0 |
| FEED-03 | Valid entries injected into ThreatIntel engine; full-replace removes stale entries | unit | `go test ./internal/firewalld/... -run TestFeedClient_Apply -v` | ❌ Wave 0 |
| FEED-04 | HTTP errors and malformed lines logged without crash | unit | `go test ./internal/firewalld/... -run TestFeedClient_ErrorHandling -v` | ❌ Wave 0 |
| FEED-03 (RemoveIPScore) | RemoveIPScore removes dynamic IP entry | unit | `go test ./internal/firewalld/... -run TestThreatIntel_RemoveIPScore -v` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/firewalld/... -run TestFeed -v`
- **Per wave merge:** `go test ./internal/firewalld/... -v`
- **Phase gate:** `go test ./... 2>&1 | grep -E "^(ok|FAIL)"` — same pre-existing failures allowed (dnssec build, TestResolver_Resolve, TestFindGlue), no new failures

### Wave 0 Gaps
- [ ] `internal/firewalld/feed_test.go` — covers FEED-01 through FEED-04 + RemoveIPScore
- [ ] No framework install needed — `go test` built in

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | strconv.Atoi + score clamping [0,100]; malformed lines skipped not panicked |
| V6 Cryptography | partial | TLS via stdlib; `tls_skip_verify` is operator-controlled with `//nolint:gosec` annotation |

### Known Threat Patterns for HTTP Feed Client

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Auth token exposure in logs | Info Disclosure | D-12: log presence/absence only; never log token value |
| Feed URL pointing to internal network (SSRF) | Tampering | [ASSUMED] No SSRF protection in scope for v1; operator-controlled config |
| Malformed feed crashing server | Denial of Service | D-04: malformed lines logged and skipped; never panic; FEED-04 requirement |
| TLS downgrade via skip-verify misconfiguration | Spoofing | Operator opt-in via `tls_skip_verify: false` (default); document risk in config comments |
| Score injection from untrusted feed | Tampering | Score clamped [0,100]; score source is operator-configured URL — trust is operator responsibility |

## Sources

### Primary (HIGH confidence)
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/threat_intel.go] — AddDomainScore, AddIPScore, RemoveDomainScore methods; dynMu pattern; RemoveIPScore confirmed absent
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/config.go] — ThreatIntelConfig struct fields confirmed; FeedURL confirmed ABSENT (contradicts STATE.md)
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/firewalld.go] — ThreatIntelEngine() accessor, Shutdown(), zerolog logger pattern
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/server/server.go] — s.ctx lifecycle, New() wiring pattern (lines 138-198), Stop() shutdown order (lines 273-313)
- [VERIFIED: /Users/ryan/development/dnsscienced/go.mod] — zerolog v1.35.0, testify v1.11.1, no new deps needed
- [VERIFIED: /Users/ryan/development/dnsscienced/internal/firewalld/firewalld_test.go] — test package convention, testify usage

### Secondary (MEDIUM confidence)
- [CITED: Go stdlib net/http/httptest] — httptest.NewServer pattern for unit testing HTTP clients
- [CITED: Go stdlib bufio] — bufio.Scanner for line-by-line text parsing

### Tertiary (LOW confidence)
- None — all claims in this research are grounded in direct codebase inspection or stdlib documentation.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries are in go.mod; no new deps required
- Architecture: HIGH — canonical code paths read directly; wiring points identified precisely
- Pitfalls: HIGH — derived from reading actual code + CONTEXT.md design decisions
- RemoveIPScore gap: HIGH — confirmed absent by grep; pattern for adding it confirmed by RemoveDomainScore

**Research date:** 2026-04-23
**Valid until:** Stable — pure Go stdlib phase, no external API or third-party library evolution concerns
