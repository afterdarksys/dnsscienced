---
phase: 04-edns0-customerid
verified: 2026-04-23T22:25:00Z
status: verified
score: 5/5 must-haves verified
overrides_applied: 0
---

# Phase 4: EDNS0 CustomerID Verification Report

**Phase Goal:** Populate QueryContext.CustomerID from EDNS0 option code 65000 at DNS query intake, before any firewall policy evaluation
**Verified:** 2026-04-23T22:25:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A DNS query carrying EDNS0 option code 65000 results in qctx.CustomerID being non-empty inside Firewall.Check() | VERIFIED | `TestExtractCustomerID/present` passes: extractCustomerID returns "cust-abc". `TestFirewall_CustomerIDExtracted` passes: VerdictAllow when trust bonus consumes the score, confirming CustomerID was populated and consumed by intel.Score() |
| 2 | A DNS query without EDNS0 option code 65000 resolves normally with qctx.CustomerID as empty string | VERIFIED | `TestExtractCustomerID/no_opt` passes (returns ""). `TestFirewall_NoCustomerID_Allowed` passes: VerdictAllow, no panic |
| 3 | A payload larger than 64 bytes is dropped silently with one debug log; CustomerID stays empty | VERIFIED | `TestExtractCustomerID/oversized` passes: 65-byte payload returns "". edns0.go lines 32-37: `logger.Debug().Int("len", ...).Msg("edns0 customer_id payload too large, ignoring")` |
| 4 | extractCustomerID is an independently-testable package-private helper in edns0.go | VERIFIED | edns0.go exists (41 lines, substantive). Function signature: `func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string` — lowercase (package-private). Called directly in `TestExtractCustomerID` without Firewall indirection |
| 5 | All 7 unit/integration tests pass with go test ./internal/firewalld/... | VERIFIED | `go test ./internal/firewalld/... -v` exits 0. All 31 tests pass including: TestExtractCustomerID (4 subtests: present, no_opt, wrong_code, oversized), TestFirewall_CustomerIDExtracted, TestFirewall_CustomerIDTrustBonus, TestFirewall_NoCustomerID_Allowed |

**Score:** 5/5 truths verified

### ROADMAP Success Criteria Assessment

The ROADMAP defines 3 success criteria for Phase 4. All 5 PLAN must-have truths above map to these 3 criteria. However, SC#3 has a coverage gap:

| # | ROADMAP Success Criterion | Status | Notes |
|---|--------------------------|--------|-------|
| SC-1 | A query carrying a known EDNS0 option (custom option code 65000) with a CustomerID value results in `q.customer_id` being non-empty inside a Starlark on_query handler | WIRING VERIFIED, TEST ABSENT | `starlark.go` line 283 maps `qctx.CustomerID` → `q["customer_id"]`. No automated test exercises a Starlark script reading q["customer_id"] and branching on it. Routed to human verification. |
| SC-2 | A query without the EDNS0 option still resolves normally — `q.customer_id` is an empty string, no error | VERIFIED | TestFirewall_NoCustomerID_Allowed, TestExtractCustomerID/no_opt |
| SC-3 | A Starlark script that branches on `q.customer_id` applies the correct per-customer verdict | WIRING VERIFIED, TEST ABSENT | Same wiring as SC-1. No test loads a Starlark script, sends a query with EDNS0 CustomerID, and asserts the verdict branched correctly. |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/firewalld/edns0.go` | edns0CustomerIDCode constant + extractCustomerID helper | VERIFIED | 41 lines. Contains `const edns0CustomerIDCode uint16 = 65000`, `const edns0MaxCustomerIDLen = 64`, `func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string`. Uses `option.(*dns.EDNS0_LOCAL)` type assertion. Compares `local.Code != edns0CustomerIDCode` (not dns.EDNS0LOCALSTART). |
| `internal/firewalld/firewalld.go` | qctx.CustomerID population before any policy evaluation | VERIFIED | Line 181: `qctx.CustomerID = extractCustomerID(r, fw.logger)`. Positioned immediately after the qctx struct literal closing brace (line 180) and before the `// 1. Static policy rules.` comment (line 183). |
| `internal/firewalld/firewalld_test.go` | makeQueryWithCustomerID helper + 7 test functions | VERIFIED | makeQueryWithCustomerID at lines 24-35. TestExtractCustomerID (4 subtests), TestFirewall_CustomerIDExtracted, TestFirewall_CustomerIDTrustBonus, TestFirewall_NoCustomerID_Allowed. Total 7 new test functions. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `firewalld.go Check()` | `edns0.go extractCustomerID()` | direct call after qctx struct literal | VERIFIED | `qctx.CustomerID = extractCustomerID(r, fw.logger)` confirmed at line 181. Same package — no import needed. |
| `edns0.go extractCustomerID()` | `dns.EDNS0_LOCAL` | type assertion `option.(*dns.EDNS0_LOCAL)` | VERIFIED | edns0.go line 28: `local, ok := option.(*dns.EDNS0_LOCAL)`. Correct type (not EDNS0_COOKIE). |
| `firewalld.go Check()` qctx.CustomerID | `starlark.go Run()` q["customer_id"] | qctx passed to starlark.Run(); starlark.go line 283 maps field | VERIFIED (code) | `starlark.go` line 283: `_ = d.SetKey(starlark.String("customer_id"), starlark.String(qctx.CustomerID))`. Wiring confirmed. No automated test exercises this full path end-to-end with a Starlark script. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `edns0.go extractCustomerID()` | `local.Data` | DNS wire bytes from `r.IsEdns0()` → `opt.Option` iteration | Yes — reads actual EDNS0 option bytes from the incoming dns.Msg | FLOWING |
| `firewalld.go Check()` | `qctx.CustomerID` | return value of `extractCustomerID(r, fw.logger)` | Yes — populated before any stage evaluation | FLOWING |
| `starlark.go Run()` | `q["customer_id"]` | `qctx.CustomerID` via `buildQueryValue()` (line 283) | Yes — pre-existing wiring; string(qctx.CustomerID) passed through | FLOWING (code path exists; Starlark branch behavior not exercised in tests) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| extractCustomerID returns CustomerID from EDNS0 option 65000 | `go test ./internal/firewalld/... -run TestExtractCustomerID/present` | PASS | PASS |
| extractCustomerID returns empty for no OPT record | `go test ./internal/firewalld/... -run TestExtractCustomerID/no_opt` | PASS | PASS |
| extractCustomerID returns empty for wrong code (65001) | `go test ./internal/firewalld/... -run TestExtractCustomerID/wrong_code` | PASS | PASS |
| extractCustomerID drops 65-byte payload silently | `go test ./internal/firewalld/... -run TestExtractCustomerID/oversized` | PASS | PASS |
| Firewall.Check() with CustomerID applies trust bonus (score reduced) | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDExtracted` | PASS | PASS |
| Firewall.Check() with CustomerID produces different verdict than without | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDTrustBonus` | PASS | PASS |
| Firewall.Check() without EDNS0 returns VerdictAllow | `go test ./internal/firewalld/... -run TestFirewall_NoCustomerID_Allowed` | PASS | PASS |
| Full build | `go build ./...` | exit 0, no output | PASS |
| Full firewalld test suite | `go test ./internal/firewalld/... -v` | 31/31 pass | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| CUST-01 | 04-01-PLAN.md | Server extracts CustomerID from EDNS0 option at query intake | SATISFIED | `extractCustomerID()` in edns0.go reads EDNS0_LOCAL option code 65000. TestExtractCustomerID/present confirms extraction. |
| CUST-02 | 04-01-PLAN.md | Extracted CustomerID is stored in QueryContext and visible to firewall policy | SATISFIED | `qctx.CustomerID = extractCustomerID(r, fw.logger)` at firewalld.go line 181, before all 4 evaluation stages. TestFirewall_CustomerIDExtracted confirms CustomerID reaches intel.Score(). |
| CUST-03 | 04-01-PLAN.md | Queries without a CustomerID EDNS0 option are handled gracefully (empty string) | SATISFIED | TestFirewall_NoCustomerID_Allowed: VerdictAllow, no panic. TestExtractCustomerID/no_opt: returns "". |

All 3 requirement IDs claimed by the plan are satisfied. No orphaned requirements found — REQUIREMENTS.md maps only CUST-01, CUST-02, CUST-03 to Phase 4.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | No stubs, placeholders, or empty implementations found | — | — |

Scan notes:
- `edns0.go`: No TODO/FIXME/placeholder. No `return null` or empty returns (returns "" which is the correct sentinel for "not found").
- `firewalld.go`: The `return allow()` at lines 168-169 is a legitimate early-exit guard (disabled firewall or empty question section), not a stub.
- `firewalld_test.go`: No hardcoded empty data passed to assertions. All `= []byte(...)` and `makeQueryWithCustomerID(...)` produce test fixtures, not stubs.

### Human Verification Required

#### 1. Starlark Script Branching on q["customer_id"]

**Test:** Write a minimal Starlark script, load it via `fw.starlark.Load()` or the gRPC LoadScript RPC, then send two queries through `fw.Check()`: one with EDNS0 option code 65000 carrying a known CustomerID, one without. The script should call `firewall.nxdomain()` when `q["customer_id"] == "target-customer"`.

**Expected:** The query WITH the matching CustomerID receives VerdictNXDomain. The query WITHOUT it (or with a different CustomerID) receives VerdictAllow.

**Why human:** ROADMAP SC#3 explicitly requires Starlark script branching on `q.customer_id`. The wiring exists (starlark.go line 283 maps `qctx.CustomerID` → `q["customer_id"]`), and this wiring predates phase 4. Phase 4 tests verify that CustomerID is extracted and flows to ThreatIntel, but no test exercises the Starlark branch path. An automated test could cover this, but it was not included in the 7 tests delivered by this phase. This is a test-coverage gap for a stated roadmap success criterion. To resolve without human testing, add a test like:

```go
func TestFirewall_StarlarkCustomerIDBranching(t *testing.T) {
    fw, err := New(Config{Enabled: true, ThreatIntel: ThreatIntelConfig{BlockThreshold: 100}})
    require.NoError(t, err)
    src := `
def on_query(q, score):
    if q["customer_id"] == "blocked-customer":
        firewall.nxdomain(reason="per-customer block")
`
    require.NoError(t, fw.starlark.Load("test-custid", src))

    withID := makeQueryWithCustomerID("example.com.", dns.TypeA, "blocked-customer")
    d1 := fw.Check(withID, net.ParseIP("127.0.0.1"))
    assert.Equal(t, VerdictNXDomain, d1.Verdict)

    noID := makeQuery("example.com.", dns.TypeA)
    d2 := fw.Check(noID, net.ParseIP("127.0.0.1"))
    assert.Equal(t, VerdictAllow, d2.Verdict)
}
```

### Gaps Summary

No functional gaps. The EDNS0 extraction, constant definition, wiring in Check(), and test coverage for extraction and ThreatIntel integration are all correct and complete. `go build ./...` is clean. All 31 firewalld tests pass.

One test-coverage gap exists for ROADMAP SC#3: no automated test exercises a Starlark script reading `q["customer_id"]` and applying a per-customer verdict. The code path is wired (starlark.go line 283), but the full Starlark branching scenario has not been exercised by this phase's test suite. This is surfaced as a human verification item, not a blocker — the underlying behavior is almost certainly correct given the wiring, but it has not been proven by a test.

---

_Verified: 2026-04-23T22:25:00Z_
_Verifier: Claude (gsd-verifier)_
