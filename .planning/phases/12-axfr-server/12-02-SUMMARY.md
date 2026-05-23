---
phase: 12-axfr-server
plan: 02
subsystem: dns
tags: [axfr, zone-transfer, tsig, acl, config-wiring, main]

requires:
  - phase: 12-axfr-server/12-01
    provides: ZoneTransferCIDRs and TsigKeys fields on server.Config

provides:
  - ZoneTransferCIDRs populated from config.Zones[].AllowTransfer with FQDN normalization
  - TsigKeys populated from config.TsigKeys via field-by-field conversion
  - AXFR handler now receives per-zone ACLs and TSIG KeyRing from config file at runtime

affects:
  - phase 13 (dynamic DNS updates — same config wiring pattern applies for allow_update)

tech-stack:
  added: []
  patterns:
    - "FQDN normalization via strings.HasSuffix trailing dot check (T-12-09: prevents ACL bypass via zone name mismatch)"
    - "Field-by-field struct conversion (config.TsigKeyConfig -> tsig.KeyConfig) to avoid import cycle with yaml:-"

key-files:
  created: []
  modified:
    - cmd/dnsscienced/main.go

key-decisions:
  - "Zone names normalized to FQDN (trailing dot) using strings.HasSuffix — avoids adding miekg/dns import just for dns.Fqdn(); strings already imported"
  - "TsigKeys wiring uses field-by-field copy (not struct cast) — server.Config.TsigKeys yaml:- so it bypasses YAML decode; this is the only path from config file to KeyRing"
  - "No raw secret logging — Secret field only copied into tsig.KeyConfig struct, never printed or logged (T-12-08 mitigated)"

requirements-completed: [XFER-01, XFER-02, XFER-03]

metrics:
  duration: 5min
  completed: 2026-05-23
  tasks: 2
  files_modified: 1
---

# Phase 12 Plan 02: Config Wiring (ZoneTransferCIDRs + TsigKeys) Summary

**Config-to-server bridge: zone allow_transfer CIDRs and TSIG keys from config.yaml now reach the AXFR handler at runtime via two wiring blocks added to cmd/dnsscienced/main.go**

## Performance

- **Duration:** ~5 min
- **Completed:** 2026-05-23
- **Tasks:** 2 (1 code task + 1 build gate)
- **Files modified:** 1

## Accomplishments

- `cfg.ZoneTransferCIDRs` populated by iterating `loadedCfg.Zones`, normalizing each zone name to FQDN (trailing dot), and mapping to `zc.AllowTransfer` — the AXFR handler's per-zone ACL now has real data at runtime
- `cfg.TsigKeys` populated by field-by-field conversion from `[]config.TsigKeyConfig` to `[]tsig.KeyConfig` — TSIG KeyRing is now seeded from `tsig_keys:` in config.yaml at startup
- Full build (`go build ./...`) passes
- All server, dsync, and tsig tests pass (`go test ./internal/server/... ./internal/dsync/... ./internal/tsig/... -count=1` all exit 0)
- `go vet ./internal/server/... ./cmd/dnsscienced/...` clean

## Task Commits

1. **Task 1: Wire ZoneTransferCIDRs and TsigKeys from config into server.Config** - `564d208` (feat)
2. **Task 2: Full build gate and regression check** - no code changes; verified by build + test runs

## Files Created/Modified

- `cmd/dnsscienced/main.go` — two wiring blocks added inside the `if *configFile != ""` branch, after defensive manager init and before DHCP check

## Decisions Made

- FQDN normalization via `strings.HasSuffix(zoneName, ".")` — avoids adding `miekg/dns` import; `strings` already imported; equivalent to `dns.Fqdn()`
- Field-by-field copy for TsigKeyConfig → tsig.KeyConfig — `server.Config.TsigKeys` has `yaml:"-"` so YAML decode bypasses it; this wiring is the only path from config file to the live KeyRing
- TSIG secret never logged — only moved from one struct to another; no log statement added near Secret field (T-12-08 mitigated)

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — wiring is complete; AXFR handler receives real ACL data and TSIG keys from config at runtime.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. This plan adds config→runtime wiring only.

Threat mitigations applied:
- T-12-08 (Tampering — TsigKeys wiring): field-by-field copy, no secret logging
- T-12-09 (Info Disclosure — zone name normalization): FQDN trailing dot ensures map lookup matches between config and server
- T-12-10 (EoP — missing TsigKeys wiring): wiring now present; AXFR no longer starts with empty KeyRing

## Self-Check

- [x] `cmd/dnsscienced/main.go` modified and committed as `564d208`
- [x] `go build ./...` exits 0
- [x] `go test ./internal/server/... -count=1` exits 0
- [x] `go test ./internal/dsync/... ./internal/tsig/... -count=1` exits 0
- [x] `go vet ./internal/server/... ./cmd/dnsscienced/...` clean

## Self-Check: PASSED

---
*Phase: 12-axfr-server*
*Completed: 2026-05-23*
