---
status: complete
phase: 11-resolver-behaviors
source: [11-01-SUMMARY.md, 11-02-SUMMARY.md]
started: 2026-05-23T11:09:42Z
updated: 2026-05-23T11:17:37Z
---

## Current Test

[testing complete]

## Tests

### 1. Build passes
expected: `go build ./...` completes with no errors.
result: pass

### 2. New resolver behavior tests pass
expected: |
  6 tests pass: TestServeStale_ExpiredEntry, TestServeStale_TTLRewrittenToZero,
  TestServeStale_BeyondMaxStaleTTL, TestServeStale_Disabled,
  TestQNAMEMinimization_ConfigFlag, TestQNAMEMinimization_DisabledByDefault
result: pass

### 3. NSEC/NSEC3 cache tests pass
expected: |
  8 tests pass: TestNSECCache_SynthesizeNXDOMAIN_NSEC, TestNSECCache_SynthesizeNXDOMAIN_NoMatch,
  TestNSECCache_Store_NSEC3, TestNSECCache_SynthesizeNXDOMAIN_NSEC3,
  TestNSECCache_Store_NSEC3_SkipNonSHA1, TestNSECCache_Store_NSEC3_SkipOptOut,
  TestNSECCache_Flush_NSEC3, TestNSECCache_Flush_NSEC
result: pass

### 4. DefaultConfig() enables all three features
expected: DefaultConfig() exists and sets QNAMEMinimization/AggressiveNSEC/ServeStale=true; Config{} leaves them false.
result: pass
note: Code-review fix commits (CR-02) were orphaned outside main branch — cherry-picked onto main during UAT. Test updated to match new semantics.

### 5. Explicit serve_stale: false is respected
expected: TestServeStale_Disabled passes; DefaultConfig() is sole source of feature defaults; no all-false guard.
result: pass

## Summary

total: 5
passed: 5
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
