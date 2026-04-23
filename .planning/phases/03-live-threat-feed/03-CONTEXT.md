# Phase 3: Live Threat Feed - Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

A background HTTP poller that fetches threat scores from a configured URL and injects them
into the firewall's live scoring engine. No operator intervention required after initial
config. The server starts the poller at boot when `feed_url` is set, and cleanly skips
it when `feed_url` is blank.

</domain>

<decisions>
## Implementation Decisions

### Feed Entry Format

- **D-01:** Lines are whitespace-delimited `<target> <score>` — e.g., `example.com 75` or `1.2.3.0/24 60`.
- **D-02:** Lines starting with `#` are treated as comments and silently skipped. Blank lines also skipped.
- **D-03:** Type detection is automatic via `net.ParseCIDR` → `net.ParseIP` → domain. No explicit type prefix required.
- **D-04:** Malformed lines (missing score, non-numeric score, empty target) are logged at WARN level with line content and line number, then skipped. The rest of the fetch continues.

### Score Refresh Semantics

- **D-05:** **Full replace on each fetch.** The FeedClient tracks which domains/IPs it injected during the previous cycle. Before applying a new fetch, it removes all previously-injected entries first. Each poll cycle reflects exactly what the current feed says — entries removed from the feed lose their scores.
- **D-06:** When the same target appears in consecutive fetches with a different score, the **latest feed score replaces** the previous one. No accumulation, no taking-the-higher value.

### Config Structure

- **D-07:** All feed config lives **flat inside `threat_intel:`** in config.yaml alongside existing fields:

  ```yaml
  firewall:
    threat_intel:
      block_threshold: 70
      feed_url: https://feeds.example.com/threats.txt
      poll_interval: 5m
      timeout: 30s
      tls_skip_verify: false
      auth_token: ""
      headers: {}
  ```

- **D-08:** Default `poll_interval` is **5 minutes** when not set. Default `timeout` is **30 seconds**.
- **D-09:** If `feed_url` is empty or unset, **no poller is started**. Server starts normally. This is not a config error.

### HTTP Client

- **D-10:** The HTTP client is **fully configurable** with four settings in config: `timeout`, `tls_skip_verify`, `auth_token`, `headers`.
- **D-11:** `auth_token` is sent as `Authorization: Bearer <value>` when non-empty.
- **D-12:** `auth_token` is **redacted from all log output**. Log presence/absence only: `auth: bearer (set)` or `auth: none`.
- **D-13:** Follow redirects by default (standard HTTP client behavior).
- **D-14:** On HTTP request failure (timeout, 4xx, 5xx): log the error, **keep previous feed-sourced scores intact**, and retry on the next poll interval. A failed fetch is non-destructive.

### Claude's Discretion

- Poller goroutine lifecycle: use a context derived from server shutdown signal (existing `context.Context` pattern in server.go) so the poller exits cleanly on `Shutdown()`.
- Log level for successful fetches: DEBUG for individual entries, INFO for fetch summary (`fetched N entries from feed in Xms`).
- Score range clamping: clamp scores from the feed to [0, 100] before calling `AddDomainScore`/`AddIPScore`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing Threat Intel Engine
- `internal/firewalld/threat_intel.go` — `AddDomainScore`, `AddIPScore`, `RemoveDomainScore` methods; thread-safety via `dynMu` mutex
- `internal/firewalld/firewalld.go` lines 305-307 — `ThreatIntelEngine() *ThreatIntel` accessor on `*Firewall`

### Config Extension Point
- `internal/firewalld/config.go` lines 72-95 — `ThreatIntelConfig` struct to extend with feed fields
- `internal/firewalld/config.go` lines 115-130 — `DefaultConfig()` to extend with feed defaults

### Server Wiring Pattern
- `internal/server/server.go` lines 190-196 — firewall initialization pattern (how `firewalld.New()` is called and wired)
- `internal/server/server.go` lines 305-310 — `Shutdown()` method (feed poller must hook into this lifecycle)

### No external specs — requirements fully captured in decisions above and REQUIREMENTS.md

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `*ThreatIntel.AddDomainScore(domain string, score int)` — mutex-protected, ready to call from poller goroutine
- `*ThreatIntel.AddIPScore(ip string, score int)` — same, mutex-protected
- `*ThreatIntel.RemoveDomainScore(domain string)` — exists for full-replace semantics (check if `RemoveIPScore` exists or needs adding)
- `*Firewall.ThreatIntelEngine() *ThreatIntel` — accessor for feed client to call into

### Established Patterns
- Goroutine lifecycle: server uses a shutdown pattern in `Shutdown()` — feed poller should use `context.WithCancel` and respect the same signal
- Config defaults: `DefaultConfig()` in `internal/firewalld/config.go` — add feed defaults here
- Error handling: existing code logs and continues (no panic on bad input) — follow same pattern

### Integration Points
- `internal/firewalld/firewalld.go` — add `StartFeed(ctx context.Context)` method or wire from `New()`
- `internal/server/server.go` — call `fw.StartFeed(ctx)` after `firewalld.New()` when `cfg.ThreatIntel.FeedURL != ""`
- New file: `internal/firewalld/feed.go` — `FeedClient` struct + `Start(ctx)` + `fetch()` + `parse()`

</code_context>

<specifics>
## Specific Ideas

- **RemoveIPScore gap:** `RemoveDomainScore` exists but `RemoveIPScore` may not. Phase 3 implementor must check and add it if missing (needed for full-replace semantics on IP entries).
- **Feed source tracking:** FeedClient must maintain two sets (domains and IPs injected last cycle) to implement full-replace. A simple `map[string]bool` per type works.
- **auth_token redaction:** When logging config at startup, replace token value with `"(set)"` or `"(not set)"`. Never log the raw value.
- **Score clamping:** `if score < 0 { score = 0 } else if score > 100 { score = 100 }` before calling AddDomainScore/AddIPScore.

</specifics>

<deferred>
## Deferred Ideas

- **Multiple feed sources** (FEED-06) — v2 requirement, explicitly out of scope for v1
- **Authenticated feed endpoints beyond Bearer token** (API key schemes, mTLS) — v2
- **Feed health metrics** (Prometheus gauge for last successful fetch time) — useful but not required for v1

</deferred>

---

*Phase: 03-live-threat-feed*
*Context gathered: 2026-04-23*
