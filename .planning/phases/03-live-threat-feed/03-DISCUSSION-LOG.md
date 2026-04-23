# Phase 3: Live Threat Feed - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 03-live-threat-feed
**Areas discussed:** Feed entry format, Score refresh semantics, Config structure, HTTP client hardening

---

## Feed Entry Format

| Option | Description | Selected |
|--------|-------------|----------|
| `<target> <score>` whitespace-delimited | `example.com 75`, `1.2.3.0/24 60` | ✓ |
| CSV `<target>,<score>` | Comma-delimited | |
| JSON lines | `{"domain":"example.com","score":75}` per line | |

**User's choice:** Whitespace-delimited `<target> <score>`

| Option | Description | Selected |
|--------|-------------|----------|
| Skip `#` comment lines | Standard convention | ✓ |
| Malformed = skip anyway | No special comment handling | |

**User's choice:** Yes, skip `#` lines

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-detect via net.ParseCIDR / net.ParseIP | Try CIDR, then IP, then domain | ✓ |
| Explicit prefix `domain:` / `ip:` | Require producer to add prefix | |

**User's choice:** Auto-detect (no prefix required)

| Option | Description | Selected |
|--------|-------------|----------|
| Log and skip malformed lines | WARN log with line content + number | ✓ |
| Silent skip | No logging | |
| Abort entire fetch | One bad line blocks all | |

**User's choice:** Log and skip

---

## Score Refresh Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Scores accumulate forever | Injected scores stay until restart | |
| Full replace on each fetch | Track injected entries, clear before re-applying | ✓ |

**User's choice:** Full replace — each fetch reflects exactly what the current feed says

| Option | Description | Selected |
|--------|-------------|----------|
| Replace with latest feed score | Latest wins | ✓ |
| Take the higher score | Only escalate, never de-escalate | |
| Sum / accumulate | Add each fetch's score | |

**User's choice:** Replace with latest — feed is source of truth

---

## Config Structure

| Option | Description | Selected |
|--------|-------------|----------|
| Inside `threat_intel:` block (flat) | Co-located with score thresholds | ✓ |
| Separate `feed:` block under `firewall:` | Cleaner separation for future multi-feed | |

**User's choice:** Flat inside `threat_intel:`

| Option | Description | Selected |
|--------|-------------|----------|
| 5 minutes default poll interval | Balance of freshness vs server load | ✓ |
| 1 minute | More aggressive | |
| No default — 0 means disabled | Explicit opt-in required | |

**User's choice:** 5 minutes default

| Option | Description | Selected |
|--------|-------------|----------|
| No poller when feed_url empty | Blank = disabled, no error | ✓ |
| Error on startup | Treat missing URL as config error | |

**User's choice:** No poller started — silent disable

---

## HTTP Client Hardening

| Option | Description | Selected |
|--------|-------------|----------|
| Hardened defaults, no auth | 30s timeout, TLS on, no auth | |
| Minimal — default http.Client | No timeout, no customization | |
| Fully configurable | Expose timeout, TLS skip, auth, headers | ✓ |

**User's choice:** Fully configurable

**Settings to expose:** timeout, tls_skip_verify, auth_token (Bearer), custom headers

| Option | Description | Selected |
|--------|-------------|----------|
| Flat inside `threat_intel:` | All feed config in one place | ✓ |
| Nested `feed:` sub-block | HTTP settings separated from polling config | |

**User's choice:** Flat in `threat_intel:`

| Option | Description | Selected |
|--------|-------------|----------|
| Redact auth_token in logs | Log `(set)` or `(not set)` only | ✓ |
| No special handling | Log raw token value | |

**User's choice:** Redact — never log raw token

| Option | Description | Selected |
|--------|-------------|----------|
| Log error, keep scores, retry next interval | Non-destructive on failure | ✓ |
| Clear all feed scores on failure | Fail-safe / conservative | |

**User's choice:** Keep previous scores on failure — retry next interval

---

## Claude's Discretion

- Goroutine lifecycle (context + shutdown signal)
- Log levels (DEBUG per-entry, INFO for fetch summary)
- Score clamping to [0, 100]

## Deferred Ideas

- Multiple feed sources (FEED-06 — v2)
- Auth beyond Bearer token (v2)
- Feed health Prometheus metrics (not required for v1)
