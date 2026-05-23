# Phase 14: v1.3 Gap Closure - Context

**Gathered:** 2026-05-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the three blockers found by the v1.3 milestone audit (v1.3-MILESTONE-AUDIT.md) plus housekeeping tasks. No new features — purely audit-driven fixes and traceability cleanup.

**Concrete deliverables:**
1. Fix `server.DefaultConfig()` to embed `resolver.DefaultConfig()` (RESOLVE-01/02/03 config wiring)
2. Fix YAML keys in `config.example.yaml` and `config.production.yaml` (wrong `enable_qname_min:` → `qname_minimization:`)
3. Fix `TestGetTTL "no answers - default"` expected value (3600 → 300)
4. Re-verify Phase 10 VERIFICATION.md (stale `human_needed` predates Plan 03)
5. Update REQUIREMENTS.md RRTYPE-01..08 checkboxes to match actual status
6. Nyquist validation for phases 10 and 11

This phase does NOT include new features, new RFC implementations, or any changes to the server's query handling path beyond the DefaultConfig fix.

</domain>

<decisions>
## Implementation Decisions

### Config Fix (RESOLVE-01/02/03)

- **D-01:** Fix `server.DefaultConfig()` at `internal/server/server.go:127` — replace the partial `resolver.Config{...}` literal with a call to `resolver.DefaultConfig()`. This is a one-line change.
- **D-02:** Update `config.example.yaml` and `config.production.yaml` to replace `enable_qname_min: true` with `qname_minimization: true`, and add `aggressive_nsec: true`, `serve_stale: true`, `stale_ttl: 86400` entries under the recursive config block. Match the exact YAML keys from `resolver.Config` struct tags (`qname_minimization`, `aggressive_nsec`, `serve_stale`, `stale_ttl`).
- **D-03:** After the DefaultConfig fix, run `go test ./internal/resolver/... ./internal/config/...` to confirm the resolver features are now enabled by default.

### Test Fix (TestGetTTL)

- **D-04:** Fix `internal/resolver/recursive_test.go` — the `"no answers - default"` case expects `3600` but `getTTL()` now returns `300` (changed by Phase 11 WR-01 for RFC 2308 §5 compliance). Change expected value from `3600` to `300`. This is a one-line change.
- **D-05:** Verify `go test ./internal/resolver/... -count=1` passes (excluding pre-existing `TestFindGlue` and `TestResolver_Resolve` failures which are documented as network-dependent and pre-existing).

### Phase 10 Re-verification

- **D-06:** Re-run the verifier agent against Phase 10 (`internal/zone/...` packages). VERIFICATION.md currently shows `human_needed` which predates Plan 03 (TLSA/HTTPS/SVCB tests added 2026-05-21). The re-verification should produce `passed` — Plan 03's SUMMARY confirms 9 new tests pass. Write a new VERIFICATION.md that reflects the complete Phase 10 state including Plan 03 results.
- **D-07:** RRTYPE-01 and RRTYPE-02 should be marked satisfied in the new VERIFICATION.md — both are confirmed by Plan 03 SUMMARY (TestParseBIND_TLSA/HTTPS/SVCB + TestParseDNSZone_TLSA/HTTPS/SVCB + TestRoundTrip_TLSA/HTTPS/SVCB all pass).

### REQUIREMENTS.md Cleanup

- **D-08:** Update `REQUIREMENTS.md` checkboxes:
  - RRTYPE-01: `[ ]` → `[x]` (confirmed satisfied by Phase 10 Plan 03)
  - RRTYPE-02: `[ ]` → `[x]` (confirmed satisfied by Phase 10 Plan 03)
  - RRTYPE-03 through RRTYPE-08: `[ ]` → `[x]` (all confirmed by Phase 10 VERIFICATION.md `passed` status)
  - RESOLVE-01/02/03: keep `[x]` — they are implemented; gap was config wiring only (fixed by D-01/D-02)

### Nyquist Validation

- **D-09:** Nyquist for phases 10 and 11 requires running `/gsd-validate-phase 10` and `/gsd-validate-phase 11`. The nyquist-auditor agent checks each VALIDATION.md row's test command, marks rows ✅, and sets `nyquist_compliant: true`. **No new tests need to be written** — the tests exist from Phase 10 and 11 execution. The VALIDATION.md rows are stale (`⬜ pending` / `❌ W0`) because they weren't updated during execution.
- **D-10:** If the nyquist-auditor finds test name mismatches (e.g., `TestSSHFP` vs the actual test name in the codebase), the plan should include a task to update the VALIDATION.md row with the correct test name. The fix is a documentation update, not new test code.
- **D-11:** Nyquist for Phase 13 (Dynamic DNS Updates) is out of scope for this phase — Phase 13 just completed and its VALIDATION.md needs to be created separately (not a blocker for v1.3 gap closure).

### Wave Strategy

- **D-12:** Two waves:
  - **Wave 1** (parallel-safe): Config fix (D-01/D-02) + TestGetTTL fix (D-04) + REQUIREMENTS.md cleanup (D-08) — these are independent file edits
  - **Wave 2** (depends on Wave 1): Phase 10 re-verification (D-06/D-07) + Nyquist for phases 10 and 11 (D-09/D-10) — verification tasks that should run after code fixes are committed

### Claude's Discretion

- Exact placement of `qname_minimization:` / `aggressive_nsec:` / `serve_stale:` in the example config files — match existing section structure
- Whether to combine REQUIREMENTS.md cleanup into the same commit as the config fix or keep separate

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Audit Source (primary driver for this phase)
- `.planning/v1.3-MILESTONE-AUDIT.md` — Full gap analysis; all 6 fixes derive from this document

### Files Being Modified
- `internal/server/server.go` — `DefaultConfig()` at line 119; `RecursiveConfig` field at line 127
- `internal/resolver/recursive.go` — `DefaultConfig()` at line 107; YAML field names at lines 74-82
- `internal/resolver/recursive_test.go` — `TestGetTTL "no answers - default"` case
- `config.example.yaml` — wrong `enable_qname_min:` key at line 28
- `config.production.yaml` — same wrong key pattern
- `.planning/REQUIREMENTS.md` — RRTYPE-01..08 checkboxes

### Phase Verification Targets
- `.planning/phases/10-record-type-expansion/10-VERIFICATION.md` — stale `human_needed`; needs re-run
- `.planning/phases/10-record-type-expansion/10-VALIDATION.md` — `nyquist_compliant: false`; Wave 0 rows pending
- `.planning/phases/11-resolver-behaviors/11-VALIDATION.md` — `nyquist_compliant: false`; Wave 0 rows pending

### Requirements
- `.planning/REQUIREMENTS.md` §RRTYPE — checkbox audit targets (RRTYPE-01..08)
- `.planning/REQUIREMENTS.md` §RESOLVE — RESOLVE-01/02/03 (implementation correct; config wiring is the gap)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `resolver.DefaultConfig()` at `internal/resolver/recursive.go:107` — returns `QNAMEMinimization: true, AggressiveNSEC: true, ServeStale: true`; this is what `server.DefaultConfig()` should call instead of the partial struct literal

### Established Patterns
- Config fix pattern: `server.DefaultConfig()` already calls `rrl.DefaultConfig()` and `experimental.DefaultConfig()` — add `resolver.DefaultConfig()` in the same pattern (line 146/148 area)
- YAML key names are the struct field tags on `resolver.Config` — always use those, not invented names

### Integration Points
- `server.DefaultConfig()` → `cfg.RecursiveConfig` → `resolver.NewRecursive()` at line 215 — fix flows through automatically once DefaultConfig() is corrected
- Pre-existing test failures to exclude: `TestFindGlue` (IPv6 bracket formatting), `TestResolver_Resolve` (network-dependent) — documented in STATE.md, not regressions

</code_context>

<specifics>
## Specific Ideas

- User confirmed: Nyquist validation for phases 10 and 11 should NOT require writing new tests — the auditor just needs to verify existing tests pass and update tracking
- Nyquist for Phase 13 is explicitly out of scope for this phase

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 14-v1.3-gap-closure*
*Context gathered: 2026-05-23*
