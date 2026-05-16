---
phase: 06-admin-api-stubs-registration
plan: "05"
subsystem: dns
tags: [tsig, rfc2845, dns, hmac, zone-transfer, miekg-dns]

# Dependency graph
requires:
  - phase: 06-02
    provides: Admin API stubs and server accessor chains established

provides:
  - internal/tsig package with KeyRing, Verify, Sign, ValidateAlgorithm
  - TsigKeyConfig struct in internal/config/config.go
  - server.Config.TsigKeys field and Server.tsigKeyRing wiring
  - dns.Server instances on UDP and TCP have TsigSecret populated from config

affects:
  - 06-06
  - Phase 7 admin auth hardening
  - Phase 8 DSYNC (RFC 9859)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "KeyRing pattern: wraps map[string]keyEntry; exposes TsigSecretMap() for miekg/dns wiring"
    - "TSIG secret never exposed via String/Log methods — only presence logged (T-06-16)"
    - "ValidateAlgorithm rejects hmac-md5/sha1; only sha256/384/512 accepted (T-06-17)"
    - "TsigSecret wired at dns.Server construction; miekg/dns auto-verifies incoming messages"

key-files:
  created:
    - internal/tsig/tsig.go
    - internal/tsig/tsig_test.go
  modified:
    - internal/config/config.go
    - internal/server/server.go

key-decisions:
  - "tsig.KeyConfig in server.Config uses yaml:\"-\" tag — populated by main.go after config load, not from server yaml stanza, to allow config.TsigKeyConfig→tsig.KeyConfig conversion at the top level"
  - "TSIG key ring initialized before dns.Server construction so TsigSecret is set at creation time (not patched later)"
  - "GetTsigKeyRing() accessor added for downstream AXFR/IXFR handler use in Phase 8"
  - "hmac-md5 and hmac-sha1 rejected (ValidateAlgorithm) per T-06-17; only sha256/384/512 supported"

patterns-established:
  - "TSIG verify/sign round-trip tested at package level before wiring into server"
  - "TDD RED→GREEN cycle used for Task 1: test commit d7a7d0c, feat commit c30832c"

requirements-completed: [TSIG-01, TSIG-02, TSIG-03]

# Metrics
duration: 3min
completed: 2026-05-16
---

# Phase 06 Plan 05: TSIG Package Summary

**TSIG (RFC 2845) KeyRing with HMAC-SHA256/384/512 verify/sign wired into dns.Server via miekg/dns TsigSecret**

## Performance

- **Duration:** 3 min
- **Started:** 2026-05-16T14:16:02Z
- **Completed:** 2026-05-16T14:18:41Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created `internal/tsig` package providing `KeyRing`, `Verify`, `Sign`, `ValidateAlgorithm`
- `KeyRing.TsigSecretMap()` returns `map[string]string` for direct assignment to `dns.Server.TsigSecret`
- `TsigKeyConfig` struct added to `internal/config/config.go` with yaml tags; `Config.TsigKeys` field added
- `server.Config.TsigKeys` and `Server.tsigKeyRing` field; `New()` builds key ring before creating `dns.Server` instances
- All UDP and TCP `dns.Server` instances have `TsigSecret` populated, enabling automatic TSIG verification by miekg/dns on incoming messages
- 9 unit tests pass including sign/verify round-trip, algorithm rejection, nil guard

## Task Commits

1. **Task 1 (RED): Failing TSIG tests** - `d7a7d0c` (test)
2. **Task 1 (GREEN): internal/tsig implementation** - `c30832c` (feat)
3. **Task 2: TsigKeyConfig + server wiring** - `b6f5a1f` (feat)

**Plan metadata:** (docs commit — next)

_TDD tasks have multiple commits (test → feat)_

## Files Created/Modified

- `internal/tsig/tsig.go` - KeyRing, Verify (dns.TsigVerify), Sign (dns.TsigGenerate), ValidateAlgorithm
- `internal/tsig/tsig_test.go` - 9 unit tests covering all public API entry points
- `internal/config/config.go` - TsigKeyConfig struct; Config.TsigKeys []TsigKeyConfig field
- `internal/server/server.go` - tsig import; server.Config.TsigKeys; Server.tsigKeyRing; tsigSecretMap(); GetTsigKeyRing(); TsigSecret wired on all dns.Server instances

## Decisions Made

- `server.Config.TsigKeys` uses `yaml:"-"` because the field is populated by main.go (converting `config.TsigKeyConfig` to `tsig.KeyConfig`) rather than decoded from the `server:` yaml stanza directly — avoids circular import between config and tsig packages
- TSIG key ring initialized before UDP/TCP `dns.Server` struct construction so `TsigSecret` is set at creation time, not patched later
- `GetTsigKeyRing()` accessor exposed so future AXFR/IXFR handlers (Phase 8) can retrieve per-message signing without going through server.Config
- Algorithm whitelist (sha256/384/512 only) implemented at `NewKeyRing` call time — invalid config fails fast before any server traffic

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None - all wiring is live code against miekg/dns primitives. TSIG signing of outgoing responses is not stubbed; the handler layer (Phase 8) will call `Sign()` after AXFR/IXFR zone enumeration.

## Threat Flags

No new threat surface beyond what was modeled in the plan's `<threat_model>`. All T-06-15 through T-06-19 mitigations implemented as specified.

## Issues Encountered

None.

## TDD Gate Compliance

- RED gate: `test(06-05)` commit `d7a7d0c` — failing tests with undefined symbols
- GREEN gate: `feat(06-05)` commit `c30832c` — implementation making all 9 tests pass
- REFACTOR gate: not needed (code is clean as written)

## Next Phase Readiness

- `internal/tsig` package is ready for Phase 8 AXFR/IXFR TSIG signing
- `GetTsigKeyRing()` provides handler access to key ring for response signing
- `config.TsigKeys` yaml field ready for operator configuration
- Pre-existing test failure in `internal/dnssec` (build error, pre-dates this phase) is unrelated

---
*Phase: 06-admin-api-stubs-registration*
*Completed: 2026-05-16*
