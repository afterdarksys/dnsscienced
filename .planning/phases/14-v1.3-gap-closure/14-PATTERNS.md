# Phase 14: v1.3 Gap Closure - Pattern Map

**Mapped:** 2026-05-23
**Files analyzed:** 7 (5 source/config files + 2 planning docs)
**Analogs found:** 7 / 7

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/server/server.go` | config | request-response | `internal/server/server.go` (rrl/experimental pattern at lines 146-148) | exact (self-analog) |
| `internal/resolver/recursive_test.go` | test | CRUD | existing test cases in same file (lines 260-290) | exact (self-analog) |
| `config.example.yaml` | config | — | `config.production.yaml` (parallel structure) | role-match |
| `config.production.yaml` | config | — | `config.example.yaml` (parallel structure) | role-match |
| `.planning/REQUIREMENTS.md` | docs | — | existing checkbox rows in same file (lines 14-19) | exact (self-analog) |
| `.planning/phases/10-record-type-expansion/10-VALIDATION.md` | docs | — | `.planning/phases/11-resolver-behaviors/11-VALIDATION.md` | role-match |
| `.planning/phases/10-record-type-expansion/10-VERIFICATION.md` | docs | — | Phase 11 VERIFICATION.md (same verifier output format) | role-match |

---

## Pattern Assignments

### `internal/server/server.go` (config, DefaultConfig composition)

**Analog:** Self — existing `rrl.DefaultConfig()` and `experimental.DefaultConfig()` call pattern at lines 145-148.

**Problem:** Lines 127-135 construct `RecursiveConfig` with a bare struct literal, setting all resolver feature flags to Go zero-value (`false`). The fix must start from `resolver.DefaultConfig()` then override the server-specific size/concurrency fields.

**Existing correct pattern** (`internal/server/server.go` lines 145-148):
```go
EnableRRL: true,
RRLConfig: rrl.DefaultConfig(),

Experimental: experimental.DefaultConfig(),
```

**Current broken code** (`internal/server/server.go` lines 126-135):
```go
EnableRecursive: true,
RecursiveConfig: resolver.Config{
    CacheConfig: cache.Config{
        ShardCount: 256,
        MaxEntries: 100000,
    },
    Workers:       1000,
    QueryTimeout:  5 * time.Second,
    MaxIterations: 20,
},
```

**Fix pattern — two-step assignment** (consistent with rrl/experimental style; preserves server-specific overrides):
```go
// In DefaultConfig(), before the return Config{...} statement:
rcfg := resolver.DefaultConfig()
rcfg.CacheConfig = cache.Config{
    ShardCount: 256,
    MaxEntries: 100000,
}
rcfg.Workers = 1000
rcfg.QueryTimeout = 5 * time.Second
rcfg.MaxIterations = 20

// Then in the Config{...} return literal, replace RecursiveConfig: resolver.Config{...}  with:
RecursiveConfig: rcfg,
```

**Key constraint:** `resolver.DefaultConfig()` returns `Workers: 100`, so the server-level `Workers: 1000` must be explicitly overridden after calling it. Do not use `RecursiveConfig: resolver.DefaultConfig()` as a bare assignment — this would silently drop the server-specific cache sizing.

---

### `internal/resolver/recursive_test.go` (test, unit)

**Analog:** Self — surrounding test cases in the `TestGetTTL` table at lines 260-290.

**Test table structure** (`internal/resolver/recursive_test.go` lines 284-290):
```go
{
    name: "no answers - default",
    msg: &dns.Msg{
        Answer: []dns.RR{},
    },
    expected: 3600,  // CHANGE THIS TO 300
},
```

**Fix:** Change `expected: 3600` to `expected: 300` at line 289. One token change.

**Why:** Phase 11 WR-01 changed `getTTL()` to return `300` (RFC 2308 §5 compliance). The test expectation was not updated at that time.

**Verify with:** `go test ./internal/resolver/... -run TestGetTTL -count=1`
Do NOT use `go test ./internal/resolver/... -count=1` for verification — `TestFindGlue` is a pre-existing failure (IPv6 bracket format, documented in STATE.md) that will make the suite appear broken even after this fix is correct.

---

### `config.example.yaml` (config, YAML key correctness)

**Analog:** `config.production.yaml` — parallel structure, same `recursive:` section.

**Current broken block** (`config.example.yaml` lines 14-29):
```yaml
recursive:
  upstreams:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 2s
  retries: 2
  enable_0x20: true
  enable_scrubbing: true
  enable_qname_min: true       # WRONG KEY — silently ignored by yaml.v3
  validate_dnssec: true
```

**Corrected block:**
```yaml
recursive:
  upstreams:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 2s
  retries: 2
  enable_0x20: true
  enable_scrubbing: true
  qname_minimization: true     # was: enable_qname_min (wrong key)
  aggressive_nsec: true        # new — struct tag: aggressive_nsec
  serve_stale: true            # new — struct tag: serve_stale
  stale_max_ttl: 24h           # new — struct tag: stale_max_ttl (NOT stale_ttl)
  validate_dnssec: true
```

**Authoritative struct tags** (`internal/resolver/recursive.go` lines 74-86):
```go
QNAMEMinimization bool         `yaml:"qname_minimization"`
AggressiveNSEC    bool         `yaml:"aggressive_nsec"`
ServeStale        bool         `yaml:"serve_stale"`
StaleTTL          time.Duration `yaml:"stale_max_ttl"`
```

**Critical pitfall:** CONTEXT.md D-02 says `stale_ttl: 86400` but the actual struct tag is `stale_max_ttl`. Using `stale_ttl` would be silently ignored — the same class of bug this phase is fixing. Use `stale_max_ttl: 24h`.

---

### `config.production.yaml` (config, YAML key correctness)

**Analog:** `config.example.yaml` — same fix, same section.

**Current broken block** (`config.production.yaml` lines 13-23):
```yaml
recursive:
  upstreams:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 2s
  retries: 2
  enable_0x20: true
  enable_scrubbing: true
  enable_qname_min: true       # WRONG KEY
```

**Corrected block:**
```yaml
recursive:
  upstreams:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 2s
  retries: 2
  enable_0x20: true
  enable_scrubbing: true
  qname_minimization: true     # was: enable_qname_min (wrong key)
  aggressive_nsec: true        # new
  serve_stale: true            # new
  stale_max_ttl: 24h           # new — NOT stale_ttl
```

---

### `.planning/REQUIREMENTS.md` (docs, checkbox update)

**Analog:** Self — existing satisfied checkbox rows at lines 14-19 show the `[x]` format.

**Current state** (lines 12-25):
```markdown
- [ ] **RRTYPE-01**: Server parses and serves HTTPS/SVCB records (RFC 9460)...
- [ ] **RRTYPE-02**: Server parses and serves TLSA/DANE records (RFC 6698)...
- [x] **RRTYPE-03**: ...
```

**Corrected state (checkbox section):**
```markdown
- [x] **RRTYPE-01**: Server parses and serves HTTPS/SVCB records (RFC 9460) from BIND and .dnszone zone files
- [x] **RRTYPE-02**: Server parses and serves TLSA/DANE records (RFC 6698) from BIND and .dnszone zone files
```

**Traceability table also needs updating** (lines 74-75 — pitfall from RESEARCH.md):
```markdown
| RRTYPE-01 | Phase 10 | Complete |
| RRTYPE-02 | Phase 10 | Complete |
```
(Currently says `Phase 14 | Pending` — must change to `Phase 10 | Complete`.)

**Evidence for changes:** Plan 03 SUMMARY — `TestParseBIND_HTTPS/SVCB`, `TestParseDNSZone_HTTPS/SVCB`, `TestRoundTrip_HTTPS/SVCB`, `TestParseBIND_TLSA`, `TestParseDNSZone_TLSA`, `TestRoundTrip_TLSA` all PASS.

RESOLVE-01/02/03 keep `[x]` — they are implemented; the gap was config wiring (now fixed by D-01/D-02 in same wave).

---

### `.planning/phases/10-record-type-expansion/10-VALIDATION.md` (docs, Nyquist row correction)

**Analog:** `.planning/phases/11-resolver-behaviors/11-VALIDATION.md` (same format — Phase 11 rows use matching `-run` prefixes that actually work).

**Current broken rows** (lines 41-46):
```markdown
| 10-01-01 | ... | `go test ./internal/zone/... -run TestSSHFP -count=1` | ❌ W0 | ⬜ pending |
| 10-01-02 | ... | `go test ./internal/zone/... -run TestNAPTR -count=1` | ❌ W0 | ⬜ pending |
| 10-01-03 | ... | `go test ./internal/zone/... -run TestSMIMEA -count=1` | ❌ W0 | ⬜ pending |
| 10-01-04 | ... | `go test ./internal/zone/... -run TestLOC -count=1` | ❌ W0 | ⬜ pending |
| 10-02-01 | ... | `go test ./internal/zone/... -run TestRoundTrip -count=1` | ❌ W0 | ⬜ pending |
| 10-02-02 | ... | `go test ./... -run TestQuery -count=1` | ❌ W0 | ⬜ pending |
```

**Corrected commands** (actual test names verified via live runs per RESEARCH.md):

| Row | Broken pattern | Correct pattern | Why |
|-----|---------------|-----------------|-----|
| 10-01-01 | `-run TestSSHFP` | `-run TestParseDNSZone_SSHFP\|TestParseBIND_SSHFP` | Tests use `TestParseDNSZone_*` / `TestParseBIND_*` naming |
| 10-01-02 | `-run TestNAPTR` | `-run TestParseDNSZone_NAPTR\|TestParseBIND_NAPTR` | Same naming pattern |
| 10-01-03 | `-run TestSMIMEA` | `-run TestParseDNSZone_SMIMEA\|TestParseBIND_SMIMEA` | Same naming pattern |
| 10-01-04 | `-run TestLOC` | `-run TestParseDNSZone_LOC\|TestParseBIND_LOC` | Same naming pattern |
| 10-02-01 | `-run TestRoundTrip` | `-run TestRoundTrip` | Already matches — no change needed |
| 10-02-02 | `-run TestQuery` | See note below | No `TestQuery*` test exists in zone package |

**Row 10-02-02 note (open question from RESEARCH.md):** No `TestQuery*` test exists in `./internal/zone/...`. The behavior (RRTYPE-08: NOERROR for missing records) is exercised through the server path at `server.go:790-793`. Decision for the Nyquist task: mark as manual-only with rationale, or map to a broader integration command. This is a documentation decision with no new test code required.

**After correcting commands, all rows should be marked:** `✅` (file exists) and status updated from `⬜ pending` to `✅ green` once the Nyquist auditor runs them.

---

### `.planning/phases/10-record-type-expansion/10-VERIFICATION.md` (docs, re-verification)

**Analog:** No direct file analog to read — this is agent output from `/gsd-verify-work`. Pattern comes from what a correct VERIFICATION.md looks like after the verifier runs.

**Current state:** `human_needed` — predates Phase 10 Plan 03 (TLSA/HTTPS/SVCB tests, added 2026-05-21).

**Expected output after re-verification:** `passed` — Plan 03 SUMMARY confirms 9 new tests pass covering RRTYPE-01/02 (HTTPS, SVCB, TLSA).

**Action:** Run `/gsd-verify-work` against Phase 10 (`internal/zone/...`). The verifier agent writes the new VERIFICATION.md; no manual editing of this file.

---

## Shared Patterns

### DefaultConfig Composition (sub-package delegation)
**Source:** `internal/server/server.go` lines 145-148 (rrl and experimental pattern)
**Apply to:** The `RecursiveConfig` field in `DefaultConfig()`
```go
// Pattern: call sub-package DefaultConfig(), then override server-specific fields
RRLConfig:    rrl.DefaultConfig(),
Experimental: experimental.DefaultConfig(),
// Apply same pattern: rcfg := resolver.DefaultConfig(); override fields; RecursiveConfig: rcfg
```

### YAML Key Authority: Always Use Struct Tags
**Source:** `internal/resolver/recursive.go` lines 74-86
**Apply to:** Both config file edits (`config.example.yaml`, `config.production.yaml`)
```go
// Struct tags are authoritative. yaml.v3 silently drops unknown keys.
QNAMEMinimization bool         `yaml:"qname_minimization"`   // NOT enable_qname_min
AggressiveNSEC    bool         `yaml:"aggressive_nsec"`
ServeStale        bool         `yaml:"serve_stale"`
StaleTTL          time.Duration `yaml:"stale_max_ttl"`        // NOT stale_ttl
```

### Test Verify Command Pattern (targeted -run flag)
**Apply to:** All test verification steps in this phase
```bash
# Use targeted -run flag to avoid pre-existing failures masking the fix
go test ./internal/resolver/... -run TestGetTTL -count=1     # not: ./internal/resolver/...
go test ./internal/zone/... -run TestParseDNSZone_SSHFP\|TestParseBIND_SSHFP -count=1
```

---

## No Analog Found

All files have analogs or are self-referential. No files require falling back to RESEARCH.md patterns exclusively.

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `10-VERIFICATION.md` (output) | docs | — | Produced by `/gsd-verify-work` agent, not hand-authored; no analog to copy from |

---

## Metadata

**Analog search scope:** `internal/server/`, `internal/resolver/`, `config.*.yaml`, `.planning/`
**Files scanned:** 7 source + planning files read directly
**Pattern extraction date:** 2026-05-23

**Wave alignment:**
- Wave 1 (parallel): `server.go` + `recursive_test.go` + `config.example.yaml` + `config.production.yaml` + `REQUIREMENTS.md`
- Wave 2 (sequential, depends on Wave 1 commit): `10-VERIFICATION.md` re-run + `10-VALIDATION.md` Nyquist row fixes + `11-VALIDATION.md` Nyquist row fixes
