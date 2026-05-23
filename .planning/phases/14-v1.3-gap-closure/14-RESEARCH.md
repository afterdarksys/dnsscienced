# Phase 14: v1.3 Gap Closure — Config Fixes & Validation - Research

**Researched:** 2026-05-23
**Domain:** Go config wiring, DNS resolver feature flags, test suite hygiene, Nyquist compliance
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01:** Fix `server.DefaultConfig()` at `internal/server/server.go:127` — replace the partial `resolver.Config{...}` literal with a call to `resolver.DefaultConfig()`. This is a one-line change.

**D-02:** Update `config.example.yaml` and `config.production.yaml` to replace `enable_qname_min: true` with `qname_minimization: true`, and add `aggressive_nsec: true`, `serve_stale: true`, `stale_ttl: 86400` entries under the recursive config block. Match the exact YAML keys from `resolver.Config` struct tags.

**D-03:** After the DefaultConfig fix, run `go test ./internal/resolver/... ./internal/config/...` to confirm the resolver features are now enabled by default.

**D-04:** Fix `internal/resolver/recursive_test.go` — the `"no answers - default"` case expects `3600` but `getTTL()` now returns `300`. Change expected value from `3600` to `300`. One-line change.

**D-05:** Verify `go test ./internal/resolver/... -count=1` passes (excluding pre-existing `TestFindGlue` and `TestResolver_Resolve` failures).

**D-06:** Re-run the verifier agent against Phase 10 (`internal/zone/...`). VERIFICATION.md currently shows `human_needed` which predates Plan 03. The re-verification should produce `passed`.

**D-07:** RRTYPE-01 and RRTYPE-02 should be marked satisfied in the new VERIFICATION.md — confirmed by Plan 03 SUMMARY.

**D-08:** Update `REQUIREMENTS.md` checkboxes:
- RRTYPE-01: `[ ]` → `[x]`
- RRTYPE-02: `[ ]` → `[x]`
- RRTYPE-03 through RRTYPE-08: `[ ]` → `[x]`
- RESOLVE-01/02/03: keep `[x]`

**D-09:** Nyquist for phases 10 and 11 requires running `/gsd-validate-phase 10` and `/gsd-validate-phase 11`. No new tests need to be written.

**D-10:** If the nyquist-auditor finds test name mismatches, update VALIDATION.md rows with correct test names. Fix is documentation only, not new test code.

**D-11:** Nyquist for Phase 13 is out of scope.

**D-12:** Two waves:
- Wave 1 (parallel-safe): Config fix (D-01/D-02) + TestGetTTL fix (D-04) + REQUIREMENTS.md cleanup (D-08)
- Wave 2 (depends on Wave 1): Phase 10 re-verification (D-06/D-07) + Nyquist for phases 10 and 11 (D-09/D-10)

### Claude's Discretion

- Exact placement of `qname_minimization:` / `aggressive_nsec:` / `serve_stale:` in the example config files — match existing section structure
- Whether to combine REQUIREMENTS.md cleanup into the same commit as the config fix or keep separate

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope. Phase 13 Nyquist explicitly out of scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RESOLVE-01 | Recursive resolver sends minimized QNAME in outgoing queries (RFC 7816 / RFC 9156) | Implementation confirmed correct in Phase 11; gap is config wiring — `server.DefaultConfig()` must call `resolver.DefaultConfig()` |
| RESOLVE-02 | Resolver synthesizes NXDOMAIN / NOERROR from cached NSEC/NSEC3 records (RFC 8198) | Same config wiring gap; `AggressiveNSEC=false` in all config-file deployments until D-01/D-02 applied |
| RESOLVE-03 | Resolver serves stale cached records when upstream unreachable (RFC 8767) | Same config wiring gap; `ServeStale=false` in all config-file deployments until D-01/D-02 applied |
| RRTYPE-01 | Server parses and serves HTTPS/SVCB records from BIND and .dnszone zone files | Confirmed by Plan 03: `TestParseBIND_HTTPS/SVCB` and `TestParseDNSZone_HTTPS/SVCB` and `TestRoundTrip_HTTPS/SVCB` all PASS; checkbox just needs updating |
| RRTYPE-02 | Server parses and serves TLSA/DANE records from BIND and .dnszone zone files | Confirmed by Plan 03: `TestParseBIND_TLSA`, `TestParseDNSZone_TLSA`, `TestRoundTrip_TLSA` all PASS; checkbox just needs updating |
</phase_requirements>

---

## Summary

Phase 14 is a gap-closure phase with no new feature development. Three audit-driven blockers must be resolved, plus housekeeping tasks. All required code already exists — the phase is about wiring, documentation, and traceability rather than implementation.

The three blockers are: (1) `server.DefaultConfig()` in `internal/server/server.go` constructs `RecursiveConfig` with all resolver feature flags at Go zero-value (`false`), because `resolver.DefaultConfig()` is never called — a one-line fix. (2) `config.example.yaml` and `config.production.yaml` use `enable_qname_min: true` which is a nonexistent YAML key, silently ignored by `yaml.v3` — a YAML key rename. (3) `TestGetTTL "no answers - default"` expects `3600` but Phase 11 WR-01 changed `getTTL()` to return `300` — a one-line test fix.

The housekeeping tasks are: re-running verification for Phase 10 (whose VERIFICATION.md predates Plan 03 that added TLSA/HTTPS/SVCB tests), updating REQUIREMENTS.md checkboxes for RRTYPE-01..08, and running Nyquist validation for phases 10 and 11 (VALIDATION.md rows are stale `pending` status, but the underlying tests already exist and pass).

**Primary recommendation:** Execute Wave 1 tasks as parallel file edits (independent), then Wave 2 as sequential verification tasks that consume Wave 1 results.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Resolver feature flags (QNAME min, Aggressive NSEC, Serve Stale) | API / Backend (server config layer) | — | Config defaults are set in `server.DefaultConfig()`; resolver package provides `resolver.DefaultConfig()` as the canonical source |
| YAML config key correctness | API / Backend (config loading) | — | `yaml.v3` silently ignores unknown keys; correctness must be enforced at the YAML file level against struct tags |
| Test suite hygiene (TestGetTTL fix) | API / Backend (resolver package tests) | — | Unit test expectation stale relative to implementation change from Phase 11 |
| Traceability / documentation | — (docs layer) | — | VERIFICATION.md, VALIDATION.md, REQUIREMENTS.md are planning artifacts consumed by the verifier and Nyquist agents |

---

## Standard Stack

This phase uses only the existing project stack. No new libraries are introduced.

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go standard library | 1.21+ | All edits are Go source or YAML | Already in use |
| `gopkg.in/yaml.v3` | existing | YAML parsing — understanding silent-ignore behavior | Already in use |
| `github.com/miekg/dns` | existing | DNS types — no changes needed | Already in use |

### No New Dependencies
This phase adds zero new dependencies. All changes are:
1. Single-line Go source edit (`server.go`)
2. YAML key renames in two config files
3. Single-line test expectation fix (`recursive_test.go`)
4. Checkbox updates in `REQUIREMENTS.md`
5. Re-running existing verification and validation agents

---

## Architecture Patterns

### Pattern 1: DefaultConfig Composition
**What:** `server.DefaultConfig()` composes sub-package defaults by calling their `DefaultConfig()` functions, not by constructing struct literals.
**When to use:** Every time a sub-package has its own `DefaultConfig()`.
**Established pattern in codebase:**
```go
// internal/server/server.go — existing pattern (lines 146/148)
EnableRRL: true,
RRLConfig: rrl.DefaultConfig(),    // calls sub-package DefaultConfig
Experimental: experimental.DefaultConfig(), // calls sub-package DefaultConfig
```
**Fix to apply (line 127 area):**
```go
// BEFORE (broken):
RecursiveConfig: resolver.Config{
    CacheConfig: cache.Config{
        ShardCount: 256,
        MaxEntries: 100000,
    },
    Workers:       1000,
    QueryTimeout:  5 * time.Second,
    MaxIterations: 20,
},

// AFTER (correct — preserves server-level overrides on top of resolver defaults):
RecursiveConfig: func() resolver.Config {
    cfg := resolver.DefaultConfig()
    cfg.CacheConfig = cache.Config{
        ShardCount: 256,
        MaxEntries: 100000,
    }
    cfg.Workers = 1000
    cfg.QueryTimeout = 5 * time.Second
    cfg.MaxIterations = 20
    return cfg
}(),
```
**Alternative simpler form** — inline struct override works if resolver.DefaultConfig() fields don't conflict:
```go
rcfg := resolver.DefaultConfig()
rcfg.CacheConfig = cache.Config{ShardCount: 256, MaxEntries: 100000}
rcfg.Workers = 1000
rcfg.QueryTimeout = 5 * time.Second
rcfg.MaxIterations = 20
// Then: RecursiveConfig: rcfg,
```
The planner should choose the simpler two-step approach (assign then mutate fields) to keep DefaultConfig() readable. The CONTEXT.md says "one-line change" — the cleanest form uses an inline `func()` wrapper or moves the assignment to a helper. Either approach is valid; the planner decides exact form per Claude's discretion.

[VERIFIED: codebase grep — `rrl.DefaultConfig()` at line 146, `experimental.DefaultConfig()` at line 148 confirmed in `internal/server/server.go`]

### Pattern 2: YAML Key Correctness
**What:** `yaml.v3` silently drops unknown keys; the Go struct tag is the authoritative key name.
**Struct tags verified:**
```go
// internal/resolver/recursive.go lines 75-86
QNAMEMinimization bool      `yaml:"qname_minimization"`
AggressiveNSEC    bool      `yaml:"aggressive_nsec"`
ServeStale        bool      `yaml:"serve_stale"`
StaleTTL          time.Duration `yaml:"stale_max_ttl"`
```
**Config files to update:**
- `config.example.yaml` line 28: `enable_qname_min: true` → `qname_minimization: true`; add `aggressive_nsec: true`, `serve_stale: true`, `stale_max_ttl: 86400s`
- `config.production.yaml` line 22: same `enable_qname_min: true` → `qname_minimization: true`; add `aggressive_nsec: true`, `serve_stale: true`

Note: D-02 in CONTEXT.md says `stale_ttl: 86400` but the actual struct tag is `stale_max_ttl`. Use `stale_max_ttl: 86400s` (or `24h`). The `time.Duration` YAML unmarshal in this codebase expects string format matching Go duration strings.

[VERIFIED: codebase read — `internal/resolver/recursive.go` lines 75-86]

### Pattern 3: Test Expectation Update
**What:** When `getTTL()` default changed from 3600 to 300 (Phase 11 WR-01), the test was not updated.
**File:** `internal/resolver/recursive_test.go` line 289
```go
// BEFORE (failing):
{
    name: "no answers - default",
    msg: &dns.Msg{Answer: []dns.RR{}},
    expected: 3600,  // ← stale; change to 300
},
// AFTER:
    expected: 300,
```
[VERIFIED: live test run — `go test ./internal/resolver/... -run TestGetTTL` returns `getTTL() = 300, want 3600` confirming the mismatch]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Resolver feature defaults | Duplicate flag values | `resolver.DefaultConfig()` | Single source of truth; already implemented correctly |
| YAML key discovery | String search | Read struct tags directly | `yaml.v3` is authoritative — struct tag is the key |
| Verification | Manual test enumeration | `/gsd-verify-work` agent | Agent has systematic coverage checking |
| Nyquist compliance | Manual VALIDATION.md editing | `/gsd-validate-phase` agent | Nyquist auditor runs test commands and marks rows |

---

## Common Pitfalls

### Pitfall 1: stale_ttl vs stale_max_ttl YAML key mismatch
**What goes wrong:** CONTEXT.md D-02 says add `stale_ttl: 86400` but the struct tag is `stale_max_ttl` (line 86 of recursive.go). Using `stale_ttl` would be silently ignored — the same class of bug this phase is fixing.
**Why it happens:** CONTEXT.md was written from memory; the audit cited the field name, not the struct tag.
**How to avoid:** Always read the struct tag in `resolver.Config` before writing YAML. Confirmed tag: `yaml:"stale_max_ttl"`.
**Warning signs:** `yaml.v3` decoder doesn't warn on unknown keys; wrong key means feature stays at default.

[VERIFIED: codebase read — `internal/resolver/recursive.go` line 86: `StaleTTL time.Duration \`yaml:"stale_max_ttl"\``]

### Pitfall 2: Partial DefaultConfig override drops server-specific cache config
**What goes wrong:** If `server.DefaultConfig()` sets `RecursiveConfig: resolver.DefaultConfig()` without preserving the server-level cache settings (ShardCount: 256, MaxEntries: 100000, Workers: 1000, etc.), those larger production-appropriate values are lost and the resolver defaults (smaller values) take over.
**Why it happens:** Simple assignment replaces the entire struct.
**How to avoid:** Start from `resolver.DefaultConfig()`, then override the fields that server.DefaultConfig() intentionally sets differently. Do not write `RecursiveConfig: resolver.DefaultConfig()` as a single assignment — always override the server-specific fields afterwards.

[VERIFIED: codebase read — current server.go RecursiveConfig literal sets Workers=1000, QueryTimeout=5s, MaxIterations=20, ShardCount=256, MaxEntries=100000; resolver.DefaultConfig() sets Workers=100, QueryTimeout=5s, MaxIterations=20, no cache config]

### Pitfall 3: TestFindGlue failure masking TestGetTTL fix verification
**What goes wrong:** Running `go test ./internal/resolver/...` fails on both `TestFindGlue` (pre-existing) and `TestGetTTL` (the regression). After fixing TestGetTTL, developers might think the test suite is still broken because TestFindGlue still fails.
**Why it happens:** Two distinct failures; one pre-existing, one the regression being fixed.
**How to avoid:** Verify specifically: `go test ./internal/resolver/... -run TestGetTTL -count=1` must pass. `TestFindGlue` failure is documented pre-existing (STATE.md). The plan should use targeted `-run` flags in verify commands.

[VERIFIED: live test run — `go test ./internal/resolver/... -count=1` fails on both TestFindGlue (IPv6 bracket format, pre-existing) and TestGetTTL (regression)]

### Pitfall 4: Phase 10 VALIDATION.md test name mismatches require DOCUMENTATION fixes, not new tests
**What goes wrong:** The Nyquist auditor reads VALIDATION.md row commands and runs them. If the command pattern doesn't match any tests, it fails even though the tests exist under different names.
**Specific mismatches found:**

Phase 10 VALIDATION.md uses these patterns — some don't match actual test names:
| VALIDATION.md command | Actual test names | Match? |
|----------------------|-------------------|--------|
| `-run TestSSHFP` | `TestParseDNSZone_SSHFP`, `TestParseBIND_SSHFP` | No — prefix mismatch |
| `-run TestNAPTR` | `TestParseDNSZone_NAPTR`, `TestParseBIND_NAPTR` | No — prefix mismatch |
| `-run TestSMIMEA` | `TestParseDNSZone_SMIMEA`, `TestParseBIND_SMIMEA` | No — prefix mismatch |
| `-run TestLOC` | `TestParseDNSZone_LOC`, `TestParseBIND_LOC` | No — prefix mismatch |
| `-run TestRoundTrip` | `TestRoundTrip_SSHFP`, `TestRoundTrip_NAPTR`, etc. | **YES** |
| `-run TestQuery` | (none matching) | No — no TestQuery* in zone package |

Phase 11 VALIDATION.md uses:
| VALIDATION.md command | Actual test names | Match? |
|----------------------|-------------------|--------|
| `-run TestQNAMEMin` | `TestQNAMEMinimization_ConfigFlag`, `TestQNAMEMinimization_DisabledByDefault` | **YES** (prefix match works) |
| `-run TestNSEC` | `TestNSECCache_SynthesizeNXDOMAIN_NSEC`, etc. | **YES** (prefix match works) |
| `-run TestServeStale` | `TestServeStale_ExpiredEntry`, etc. | **YES** |
| `-run TestStaleWindow` | (none matching — `TestServeStale_BeyondMaxStaleTTL` covers this behavior) | No — name doesn't exist |

**How to avoid:** The Nyquist task (D-10) must update VALIDATION.md rows with patterns that actually match Go test names. The fix is purely in VALIDATION.md — no new test code needed.

[VERIFIED: live test runs — confirmed matching behavior of each pattern]

### Pitfall 5: REQUIREMENTS.md Traceability table is also stale
**What goes wrong:** REQUIREMENTS.md has both a checkbox section AND a Traceability table at the bottom. The checkbox section for RRTYPE-01/02 shows `[ ]` and the Traceability table says "Pending" for Phase 14. After D-08 checkbox fixes, the Traceability table still says "Pending" unless also updated.
**How to avoid:** D-08 should update both the checkbox section AND the Traceability table for RRTYPE-01/02 to reflect "Complete" status under Phase 10.

[VERIFIED: codebase read — REQUIREMENTS.md lines 79-84 show Traceability table; RRTYPE-01/02 listed as "Phase 14, Pending"]

---

## Code Examples

### Correct DefaultConfig composition (server.go)
```go
// Source: internal/server/server.go — existing rrl pattern at line 146
// Apply same pattern for resolver:

// In DefaultConfig():
rcfg := resolver.DefaultConfig()
rcfg.CacheConfig = cache.Config{
    ShardCount: 256,
    MaxEntries: 100000,
}
rcfg.Workers = 1000
rcfg.QueryTimeout = 5 * time.Second
rcfg.MaxIterations = 20
// ...then in Config struct:
RecursiveConfig: rcfg,
```

### Correct YAML block (config.example.yaml)
```yaml
# recursive: section
recursive:
  upstreams:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 2s
  retries: 2
  enable_0x20: true
  enable_scrubbing: true
  qname_minimization: true       # was: enable_qname_min (wrong key, silently ignored)
  aggressive_nsec: true          # new
  serve_stale: true              # new
  stale_max_ttl: 24h             # new (struct tag: stale_max_ttl, NOT stale_ttl)
  validate_dnssec: true
```

### TestGetTTL fix (recursive_test.go line 289)
```go
// BEFORE:
expected: 3600,
// AFTER:
expected: 300,
```

### REQUIREMENTS.md checkbox format
```markdown
- [x] **RRTYPE-01**: Server parses and serves HTTPS/SVCB records (RFC 9460) from BIND and .dnszone zone files
- [x] **RRTYPE-02**: Server parses and serves TLSA/DANE records (RFC 6698) from BIND and .dnszone zone files
```

### REQUIREMENTS.md Traceability table fix
```markdown
| RRTYPE-01 | Phase 10 | Complete |
| RRTYPE-02 | Phase 10 | Complete |
```

### Phase 10 VALIDATION.md corrected commands (Wave 1 row updates)
```markdown
| 10-01-01 | 01 | 1 | RRTYPE-03 | Parse SSHFP | unit | `go test ./internal/zone/... -run TestParseDNSZone_SSHFP\|TestParseBIND_SSHFP -count=1` | ✅ | ✅ |
| 10-01-02 | 01 | 1 | RRTYPE-04 | Parse NAPTR | unit | `go test ./internal/zone/... -run TestParseDNSZone_NAPTR\|TestParseBIND_NAPTR -count=1` | ✅ | ✅ |
```

### Phase 11 VALIDATION.md corrected command for TestStaleWindow
```markdown
# Change: -run TestStaleWindow → -run TestServeStale_BeyondMaxStaleTTL
# or broaden to: -run TestServeStale (matches all stale tests including boundary)
```

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | go test (built-in) |
| Config file | none |
| Quick run command | `go test ./internal/resolver/... ./internal/zone/... -count=1` |
| Full suite command | `go test ./... -count=1` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RESOLVE-01 | QNAME minimization enabled by default | unit | `go test ./internal/resolver/... -run TestQNAMEMinimization -count=1` | ✅ (existing) |
| RESOLVE-02 | Aggressive NSEC enabled by default | unit | `go test ./internal/cache/... -run TestNSEC -count=1` | ✅ (existing) |
| RESOLVE-03 | Serve stale enabled by default | unit | `go test ./internal/resolver/... -run TestServeStale -count=1` | ✅ (existing) |
| RRTYPE-01 | HTTPS/SVCB parse and round-trip | unit | `go test ./internal/zone/... -run TestParseBIND_HTTPS\|TestParseBIND_SVCB\|TestParseDNSZone_HTTPS\|TestParseDNSZone_SVCB\|TestRoundTrip_HTTPS\|TestRoundTrip_SVCB -count=1` | ✅ (existing) |
| RRTYPE-02 | TLSA parse and round-trip | unit | `go test ./internal/zone/... -run TestParseBIND_TLSA\|TestParseDNSZone_TLSA\|TestRoundTrip_TLSA -count=1` | ✅ (existing) |

### Sampling Rate
- Per task commit: `go test ./internal/resolver/... ./internal/zone/... -count=1`
- Per wave merge: `go test ./... -count=1`
- Phase gate: Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
None — all tests exist. The Nyquist validation work (D-09/D-10) updates VALIDATION.md rows to reference existing passing tests, not create new ones.

---

## Environment Availability

Step 2.6: SKIPPED (no external tool dependencies — all work is Go source edits, YAML edits, and planning document updates against existing tests).

---

## Runtime State Inventory

Step 2.5: This is not a rename/refactor phase. No runtime state inventory required.

---

## Open Questions

1. **`stale_ttl` vs `stale_max_ttl` in CONTEXT.md D-02**
   - What we know: CONTEXT.md D-02 says add `stale_ttl: 86400`; the actual struct tag is `yaml:"stale_max_ttl"` (verified at `recursive.go:86`).
   - What's unclear: Whether to add `stale_ttl:` (which would be silently ignored, perpetuating the bug pattern) or `stale_max_ttl:`.
   - Recommendation: Use `stale_max_ttl: 24h` — this matches the struct tag and sets the correct field. This is unambiguous and within Claude's discretion per CONTEXT.md.

2. **DefaultConfig override — inline func vs two-step assignment**
   - What we know: CONTEXT.md says "one-line change" but the actual fix requires preserving 4 server-specific config overrides (ShardCount, MaxEntries, Workers, QueryTimeout, MaxIterations) on top of resolver defaults.
   - What's unclear: Exact syntactic form of the fix.
   - Recommendation: Two-step assignment (assign resolver.DefaultConfig() then override fields). Clean, readable, avoids inline func complexity. The planner should specify this exact form.

3. **Phase 10 VALIDATION.md Task 10-02-02 `TestQuery` pattern**
   - What we know: Row 10-02-02 uses `-run TestQuery` but no `TestQuery*` test exists in `./internal/zone/...`. The behavior it covers (RRTYPE-08: NOERROR for missing records) is verified via `server.go:790-793` code path, not a zone-package test.
   - What's unclear: Whether to delete row 10-02-02, map it to a different test, or keep it as a manual-only row.
   - Recommendation: The Nyquist task should update 10-02-02 to reference the full-suite command that exercises the server path, or mark it manual-only with rationale. This is a decision for the Nyquist validation task in Wave 2.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `time.Duration` YAML unmarshal accepts `24h` string format for `stale_max_ttl` | Code Examples | If it expects integer seconds, `24h` would fail; use `86400s` instead. Low risk — Go duration string format is standard. | [ASSUMED] |
| A2 | The Nyquist auditor agent runs VALIDATION.md commands verbatim and checks for test output | Don't Hand-Roll | If the auditor has different behavior, D-10 task design may need adjustment | [ASSUMED] |

---

## Sources

### Primary (HIGH confidence)
- `internal/server/server.go` lines 119-157 — DefaultConfig() implementation, confirmed partial struct literal for RecursiveConfig
- `internal/resolver/recursive.go` lines 74-117 — struct tag names and DefaultConfig() return values, confirmed
- `internal/resolver/recursive_test.go` line 289 — stale expected value `3600`, confirmed failing
- `config.example.yaml` line 28 — `enable_qname_min: true` confirmed present
- `config.production.yaml` line 22 — `enable_qname_min: true` confirmed present
- `.planning/phases/10-record-type-expansion/10-VALIDATION.md` — confirmed stale `⬜ pending` rows, test name mismatches
- `.planning/phases/11-resolver-behaviors/11-VALIDATION.md` — confirmed stale `⬜ pending` rows, one missing test name
- `.planning/phases/10-record-type-expansion/10-VERIFICATION.md` — confirmed `human_needed` status predating Plan 03
- `.planning/REQUIREMENTS.md` — confirmed `[ ]` checkboxes for RRTYPE-01/02 and stale Traceability table
- Live `go test` runs confirming: TestGetTTL failure, all Phase 10 RRTYPE tests passing, Phase 11 QNAME/NSEC/ServeStale tests passing

### Secondary (MEDIUM confidence)
- `.planning/v1.3-MILESTONE-AUDIT.md` — gap analysis used as primary driver; authored by gsd-audit-milestone agent
- `.planning/phases/10-record-type-expansion/10-03-SUMMARY.md` — Plan 03 test confirmations (not re-read, but STATE.md records conclusions)

---

## Metadata

**Confidence breakdown:**
- Config fix mechanics: HIGH — verified via live code read and test run
- YAML key correctness: HIGH — read struct tags directly
- Test name mapping: HIGH — verified via `go test -list` and targeted test runs
- Nyquist VALIDATION.md row updates: HIGH — verified which patterns match/don't match actual test names
- Wave strategy: HIGH — dependencies between tasks are clear and verified

**Research date:** 2026-05-23
**Valid until:** N/A — this is a one-time gap closure phase; research is specific to current codebase state
