# Deferred Items — Phase 06

## Pre-existing Issues (Out of Scope)

### internal/protective/engine.go line 410
- **Issue:** `go vet` reports "return copies lock value: Statistics contains sync.RWMutex"
- **Introduced by:** Pre-Phase-6 commit (9b79959 "Add BIND-style config, DNSSEC validation, and Protective DNS")
- **Status:** Out of scope for Phase 06 — not introduced by any Phase 06 plan
- **Action needed:** Fix in a future maintenance pass — change Statistics.GetStats() or similar to return pointer or remove embedded mutex
