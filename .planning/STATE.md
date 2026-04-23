# State

## Current Position

Phase: 2 — gRPC Admin
Plan: —
Status: Ready to plan
Last activity: 2026-04-23 — Phase 2 context gathered (discuss-phase complete)

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23)

**Core value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.
**Current focus:** v1.1 — dnsfirewalld Completion

## Accumulated Context

- v1.0 shipped cleanly; 19 tests green; binary builds as `dnsscienced-linux`
- HTTP admin handler lives in `internal/firewalld/admin.go` — interim, stays as fallback
- Proto codegen: run `generate.sh` after any `.proto` changes
- ThreatIntelConfig.FeedURL field exists in config.go but is unused
- QueryContext.CustomerID exists in struct but never populated
- Forwarder currently takes a single upstream target from rule/Starlark
- Starlark `on_query(q, score)` signature — q is dict, score 0-100 int
- Phase 2 starts next: add FirewallStats/LoadScript/RemoveScript/InjectScore to admin.proto, run generate.sh, implement handlers in internal/admin/
