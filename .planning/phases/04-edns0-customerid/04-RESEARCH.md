# Phase 4: EDNS0 CustomerID — Research

**Researched:** 2026-04-23
**Domain:** DNS / miekg/dns EDNS0 option parsing; Go package-internal test patterns
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Option code **65000** for the CustomerID EDNS0 option.
- **D-02:** Named constant (e.g. `edns0CustomerIDCode = 65000`) with a doc comment citing RFC 6891 §6.1.3.1 (private-use range).
- **D-03:** Extraction inside `Firewall.Check()` — no signature change. No changes to `server.go`.
- **D-04:** Read `r.IsEdns0()`, iterate options, find code 65000, set `qctx.CustomerID` before any policy/junk/intel evaluation runs.
- **D-05:** Payload bytes treated as raw UTF-8 string. No special encoding.
- **D-06:** Max payload 64 bytes. Oversized → `CustomerID = ""`.
- **D-07:** Absent OPT or missing option code 65000 → `CustomerID = ""`, silent.
- **D-08:** Absent or malformed option → `CustomerID = ""`, silent. Query proceeds normally.
- **D-09:** Oversized payload → `CustomerID = ""` + one debug-level log: `"edns0 customer_id payload too large, ignoring"` with actual length.

### Claude's Discretion

- Exact constant name and file placement within the `firewalld` package (inline in `firewalld.go` vs. new `edns0.go`).
- Whether to write a helper function `extractCustomerID(r *dns.Msg) string` or inline the extraction in `Check()`.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CUST-01 | Server extracts CustomerID from EDNS0 option at query intake | `*dns.EDNS0_LOCAL` deserialization (below); insertion point is `Check()` lines 175–180 in firewalld.go |
| CUST-02 | Extracted CustomerID stored in QueryContext and visible to firewall policy | `QueryContext.CustomerID` field already exists (firewalld.go:81); `buildQueryValue()` in starlark.go:283 already reads it; `threat_intel.go:105–106` already uses it |
| CUST-03 | Queries without a CustomerID EDNS0 option handled gracefully (empty string) | Zero-value of Go string is `""`; struct literal initialisation leaves the field empty; nil-guard on `IsEdns0()` covers the absent-OPT path |
</phase_requirements>

---

## Summary

Phase 4 is a narrow plumbing task: populate `QueryContext.CustomerID` inside `Firewall.Check()` from a custom EDNS0 option. The field, the downstream consumers (Starlark, ThreatIntel), and the insertion point all exist. Nothing new needs to be designed; the work is: (1) define a constant, (2) write the extraction loop (three to six lines), (3) write three to four tests.

The miekg/dns library (v1.1.72) deserialises every unrecognised EDNS0 option code through the `default` branch of its factory switch, producing `*dns.EDNS0_LOCAL` with `.Code` set to the option code and `.Data` holding the raw wire bytes. Code 65000 (0xFDE8) is one below the library's `EDNS0LOCALSTART` constant (0xFDE9 = 65001), but it is still handled by the same `default` branch and arrives as `*dns.EDNS0_LOCAL` — the type assertion `option.(*dns.EDNS0_LOCAL)` succeeds. The pattern is identical to the cookie extraction in `server.go:448–460` and can be copied verbatim (replacing `*dns.EDNS0_COOKIE` with `*dns.EDNS0_LOCAL` and the matching code check).

All downstream integration points already handle a non-empty `CustomerID` correctly; this phase requires no changes to `starlark.go`, `threat_intel.go`, or `server.go`.

**Primary recommendation:** Add `extractCustomerID(r *dns.Msg) string` as a package-private helper in a new `internal/firewalld/edns0.go` file. Call it once in `Check()` immediately after the `qctx` struct literal. This keeps `Check()` readable and the helper independently testable.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| EDNS0 option extraction | API / Backend (`firewalld` package) | — | Firewall package already owns query parsing; extraction is encapsulated per D-03 |
| CustomerID population | API / Backend (`firewalld` package) | — | `QueryContext` is the firewall's per-query state carrier |
| CustomerID exposure to policy | API / Backend (`starlark.go`) | — | Already implemented; no change required |
| CustomerID exposure to scoring | API / Backend (`threat_intel.go`) | — | Already implemented; no change required |

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/miekg/dns` | v1.1.72 | DNS message parsing, EDNS0 option access | Already the project's DNS library [VERIFIED: go.mod] |
| `github.com/rs/zerolog` | (existing) | Debug-level logging of oversized payload | Already the project's logger [VERIFIED: firewalld.go imports] |

No new dependencies are required for this phase.

**Installation:** none — all libraries already in `go.mod`.

---

## Architecture Patterns

### System Architecture Diagram

```
Incoming *dns.Msg
        |
        v
Firewall.Check(r *dns.Msg, clientIP net.IP)
        |
        +--> qctx := &QueryContext{Msg, ClientIP, Name, Qtype}
        |
        +--> qctx.CustomerID = extractCustomerID(r)  ← NEW
        |          |
        |          +--> r.IsEdns0() == nil  --> return ""
        |          |
        |          +--> iterate opt.Option
        |                   |
        |                   +--> *dns.EDNS0_LOCAL, .Code == 65000?
        |                             |
        |                             +--> len(Data) > 64  --> log debug, return ""
        |                             |
        |                             +--> return string(Data)
        |
        +--> 1. policy.Evaluate(qctx)
        +--> 2. junk.Detect(qctx)
        +--> 3. intel.Score(qctx)   [uses qctx.CustomerID already]
        +--> 4. starlark.Run(qctx)  [exposes q["customer_id"] already]
        +--> 5. default action
```

### Recommended File Structure

No new directories required. Choices for file placement (Claude's discretion):

```
internal/firewalld/
├── firewalld.go       — QueryContext, Firewall, Check() — modify to call extractCustomerID
├── edns0.go           — NEW: edns0CustomerIDCode const + extractCustomerID helper (preferred)
└── firewalld_test.go  — existing tests; add EDNS0 extraction tests here
```

Alternatively, the constant and helper can be placed inline in `firewalld.go` if the team prefers fewer files.

### Pattern 1: EDNS0_LOCAL Type Assertion (the extraction loop)

This is the canonical miekg/dns pattern for any unregistered EDNS0 option. Code 65000 is
unregistered and arrives via the `default` branch of the library's factory, making it a
`*dns.EDNS0_LOCAL`.

```go
// Source: miekg/dns@v1.1.72 edns.go (default branch), modelled on server.go:448-460

// edns0CustomerIDCode is the private-use EDNS0 option code carrying the
// customer identifier.  RFC 6891 §6.1.3.1 reserves codes 65000–65534 for
// private use / local experimentation.
const edns0CustomerIDCode uint16 = 65000

// edns0MaxCustomerIDLen is the maximum accepted payload size in bytes.
// Chosen to accommodate UUID-prefixed variants (36 bytes for a bare UUID,
// headroom for short prefixes).
const edns0MaxCustomerIDLen = 64

// extractCustomerID returns the customer identifier from the EDNS0 option with
// code 65000, or "" if the option is absent or invalid.
func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string {
    opt := r.IsEdns0()
    if opt == nil {
        return ""
    }
    for _, option := range opt.Option {
        local, ok := option.(*dns.EDNS0_LOCAL)
        if !ok || local.Code != edns0CustomerIDCode {
            continue
        }
        if len(local.Data) > edns0MaxCustomerIDLen {
            logger.Debug().
                Int("len", len(local.Data)).
                Msg("edns0 customer_id payload too large, ignoring")
            return ""
        }
        return string(local.Data)
    }
    return ""
}
```

Call site in `Check()` immediately after the `qctx` struct literal (firewalld.go:175–180):

```go
qctx := &QueryContext{
    Msg:      r,
    ClientIP: clientIP,
    Name:     strings.ToLower(q.Name),
    Qtype:    q.Qtype,
}
qctx.CustomerID = extractCustomerID(r, fw.logger)   // ← INSERT HERE (line ~181)

// 1. Static policy rules.
if d := fw.policy.Evaluate(qctx); d.Verdict != VerdictAllow {
```

### Pattern 2: Building EDNS0 Test Messages

For tests that exercise the extraction path, attach an OPT record with the custom option using `dns.EDNS0_LOCAL` — the same type the library uses for unknown codes at parse time.

```go
// Source: miekg/dns@v1.1.72 edns.go doc comment example (EDNS0_LOCAL usage)

func makeQueryWithCustomerID(name string, qtype uint16, customerID string) *dns.Msg {
    m := makeQuery(name, qtype)          // reuse existing helper
    opt := new(dns.OPT)
    opt.Hdr.Name = "."
    opt.Hdr.Rrtype = dns.TypeOPT
    opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
        Code: edns0CustomerIDCode,
        Data: []byte(customerID),
    })
    m.Extra = append(m.Extra, opt)
    return m
}
```

### Anti-Patterns to Avoid

- **Type-asserting to a named EDNS0 type other than `*dns.EDNS0_LOCAL`:** Code 65000 does not match any named constant in the miekg library — the factory returns `*dns.EDNS0_LOCAL`. Asserting to any other type silently misses the option.
- **Checking `local.Code != dns.EDNS0LOCALSTART`:** `EDNS0LOCALSTART` is 0xFDE9 (65001); our code is 0xFDE8 (65000). Always compare against the project constant `edns0CustomerIDCode`, not the library constant.
- **Mutating the `*dns.Msg` to strip the option:** Not required and risks corrupting responses that echo back the OPT record. Leave the OPT record intact.
- **Placing extraction after any evaluation stage:** D-04 is explicit — extraction must precede all evaluation. If called after `policy.Evaluate`, `CustomerID` is empty for the policy stage and the trust bonus in `threat_intel.Score` is also unavailable.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Parsing EDNS0 wire format | Custom OPT record parser | `r.IsEdns0()` + `*dns.EDNS0_LOCAL` | miekg/dns handles RFC 6891 framing, length fields, and option iteration |
| UTF-8 conversion | `encoding` package import | `string(local.Data)` | Go's built-in conversion is correct; raw bytes interpreted as UTF-8 is what D-05 requires |
| Logging infrastructure | Custom log levels | `fw.logger.Debug()` (zerolog) | Already initialised in `Firewall`; debug level matches D-09 exactly |

**Key insight:** The entire extraction is three to six lines of idiomatic Go using already-imported packages. There is nothing custom to build.

---

## Common Pitfalls

### Pitfall 1: Confusing Option Code 65000 with EDNS0LOCALSTART

**What goes wrong:** Developer uses `dns.EDNS0LOCALSTART` (65001) as the option code constant or as the match value in the loop, so the option is never found.

**Why it happens:** The miekg/dns constant is named "LOCAL START" and the value 65001 looks plausible when you see 65000 in the decision doc.

**How to avoid:** Define `edns0CustomerIDCode = 65000` explicitly (D-01/D-02). Add a comment: `// Note: dns.EDNS0LOCALSTART = 65001; this code is 65000 (one below)`.

**Warning signs:** Tests that send code 65000 always return `""`.

### Pitfall 2: Loop exits after first EDNS0_LOCAL regardless of Code

**What goes wrong:** A `break` or early return fires after matching `*dns.EDNS0_LOCAL` before checking `.Code`, so a different local option (e.g., a vendor option at code 65001) causes early exit.

**How to avoid:** Gate on BOTH the type assertion AND the code check before acting: `if !ok || local.Code != edns0CustomerIDCode { continue }`.

### Pitfall 3: Missing the nil-guard on IsEdns0()

**What goes wrong:** Code dereferences `opt.Option` directly. If the message has no OPT record, `r.IsEdns0()` returns `nil` and the dereference panics.

**How to avoid:** Always check `if opt == nil { return "" }` immediately after `r.IsEdns0()`.

**Warning signs:** Panic on queries from clients that send no EDNS0 support.

### Pitfall 4: Calling extractCustomerID after an evaluation stage

**What goes wrong:** `qctx.CustomerID` is `""` during `policy.Evaluate()` and `intel.Score()`, so customer-specific rules and trust bonuses are skipped even when the option is present.

**How to avoid:** The call must be the first statement after the `qctx` struct literal, before the comment `// 1. Static policy rules.`

---

## Code Examples

### Full extraction helper (reference implementation)

```go
// Source: pattern derived from server.go:448-460 [VERIFIED: codebase] and
//         miekg/dns@v1.1.72 edns.go EDNS0_LOCAL doc [VERIFIED: module cache]

const edns0CustomerIDCode uint16 = 65000
// Note: dns.EDNS0LOCALSTART = 0xFDE9 (65001); this code is 0xFDE8 (65000).
// RFC 6891 §6.1.3.1 designates both as private-use / local experimentation.

const edns0MaxCustomerIDLen = 64

func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string {
    opt := r.IsEdns0()
    if opt == nil {
        return ""
    }
    for _, option := range opt.Option {
        local, ok := option.(*dns.EDNS0_LOCAL)
        if !ok || local.Code != edns0CustomerIDCode {
            continue
        }
        if len(local.Data) > edns0MaxCustomerIDLen {
            logger.Debug().
                Int("len", len(local.Data)).
                Msg("edns0 customer_id payload too large, ignoring")
            return ""
        }
        return string(local.Data)
    }
    return ""
}
```

### Test helper for EDNS0-bearing queries

```go
// Source: miekg/dns@v1.1.72 edns.go EDNS0_LOCAL example [VERIFIED: module cache]

func makeQueryWithCustomerID(name string, qtype uint16, customerID string) *dns.Msg {
    m := makeQuery(name, qtype)
    opt := new(dns.OPT)
    opt.Hdr.Name = "."
    opt.Hdr.Rrtype = dns.TypeOPT
    opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
        Code: edns0CustomerIDCode,
        Data: []byte(customerID),
    })
    m.Extra = append(m.Extra, opt)
    return m
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-----------------|--------------|--------|
| miekg/dns unknown options: panic | Fall through to `*dns.EDNS0_LOCAL` via `default` branch | Long-standing | Custom option codes are safe to parse without library registration |

No deprecated patterns apply to this phase.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `string(local.Data)` interprets raw bytes as UTF-8 without error (D-05) | Code Examples | Go does not validate UTF-8 on `string()` conversion — invalid sequences pass through as replacement characters. Low risk: any downstream Starlark/ThreatIntel comparison would simply fail to match, effectively treating invalid UTF-8 as "no matching customer." The user's intent (raw bytes → string) is satisfied. [ASSUMED — but consistent with Go spec] |

---

## Open Questions

1. **Logger parameter vs. field access in helper**
   - What we know: `fw.logger` is a `zerolog.Logger` value on the `Firewall` struct.
   - Options: (a) pass `zerolog.Logger` as a parameter to `extractCustomerID`; (b) make `extractCustomerID` a method on `*Firewall`; (c) inline the logic directly in `Check()`.
   - Recommendation: Pass the logger as a parameter — keeps the helper a pure function and simplifies testing. If the planner prefers the method form, either works.

2. **Exact constant name**
   - `edns0CustomerIDCode` vs. `customerIDOptionCode` vs. `edns0OptionCustomerID` — all are Claude's discretion (D-02 only requires a named constant with doc comment).
   - Recommendation: `edns0CustomerIDCode` — reads clearly in the loop: `local.Code != edns0CustomerIDCode`.

---

## Environment Availability

Step 2.6: SKIPPED — this phase is purely code changes within the existing Go module with no external service or CLI dependencies beyond what is already present.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `testing` (stdlib) + `testify` v1 |
| Config file | none — `go test ./...` |
| Quick run command | `go test ./internal/firewalld/... -v -run TestEdns0` |
| Full suite command | `go test ./internal/firewalld/...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CUST-01 | `extractCustomerID` returns correct string when option 65000 is present | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_Present` | Wave 0 |
| CUST-01 | `extractCustomerID` returns `""` when OPT record is absent | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_NoOPT` | Wave 0 |
| CUST-01 | `extractCustomerID` returns `""` when option 65000 is absent (other codes present) | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_WrongCode` | Wave 0 |
| CUST-01 | `extractCustomerID` returns `""` for oversized payload (>64 bytes) | unit | `go test ./internal/firewalld/... -run TestExtractCustomerID_Oversized` | Wave 0 |
| CUST-02 | `Firewall.Check()` populates `qctx.CustomerID` before evaluation | integration | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDExtracted` | Wave 0 |
| CUST-02 | CustomerID visible to ThreatIntel trust bonus (end-to-end in Check) | integration | `go test ./internal/firewalld/... -run TestFirewall_CustomerIDTrustBonus` | Wave 0 |
| CUST-03 | `Firewall.Check()` proceeds normally when no EDNS0 option present | integration | `go test ./internal/firewalld/... -run TestFirewall_NoCustomerID_Allowed` | Wave 0 |

### Sampling Rate

- **Per task commit:** `go test ./internal/firewalld/... -run TestEdns0\|TestExtractCustomerID\|TestFirewall_CustomerID`
- **Per wave merge:** `go test ./internal/firewalld/...`
- **Phase gate:** Full suite green (`go test ./...`) before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] Tests for `extractCustomerID` helper — add to `internal/firewalld/firewalld_test.go` (or `edns0_test.go` if helper is in `edns0.go`)
- [ ] Integration test: `TestFirewall_CustomerIDExtracted` — verifies `qctx.CustomerID` is set via `Firewall.Check()` using the customer_id Starlark key or ThreatIntel bonus
- [ ] Test helper `makeQueryWithCustomerID` — add to `firewalld_test.go` alongside existing `makeQuery`

*(No framework installation needed — `go test` and `testify` are already present.)*

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | Length cap (64 bytes); no parsing beyond raw bytes |
| V6 Cryptography | no | — |

### Known Threat Patterns for DNS/EDNS0 Intake

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Oversized EDNS0 payload to exhaust memory or amplify log volume | Denial of Service | 64-byte hard cap (D-06); oversized → discard + one debug log (D-09) |
| Malformed UTF-8 in CustomerID to confuse downstream string matching | Tampering | Go's `string()` conversion passes bytes through — mismatched UTF-8 simply fails to match any known customer, no crash |
| Option code confusion (attacker sends code 65001 instead of 65000) | Spoofing | Exact-code check in the loop; wrong code silently ignored |
| CustomerID injection to gain elevated trust bonus | Elevation of Privilege | CustomerID is operator-controlled via DNS query; if trust bonus is sensitive, operators should not rely on unauthenticated EDNS0 for access control (out of scope for this phase — noted for awareness) |

---

## Sources

### Primary (HIGH confidence)

- `go.mod` in project root — confirmed miekg/dns v1.1.72 [VERIFIED: go.mod]
- `/Users/ryan/go/pkg/mod/github.com/miekg/dns@v1.1.72/edns.go` — EDNS0_LOCAL struct definition, factory default branch, EDNS0LOCALSTART constant, doc example [VERIFIED: module cache]
- `internal/firewalld/firewalld.go` — QueryContext struct (line 81), Check() insertion point (lines 175–180) [VERIFIED: Read]
- `internal/server/server.go:448–460` — reference EDNS0 iteration pattern [VERIFIED: Read]
- `internal/firewalld/starlark.go:283` — customer_id already exposed [VERIFIED: Read]
- `internal/firewalld/threat_intel.go:105–106` — CustomerID already consumed [VERIFIED: Read]
- `internal/firewalld/firewalld_test.go` — test style, `makeQuery` helper, package `firewalld` [VERIFIED: Read]

### Secondary (MEDIUM confidence)

- RFC 6891 §6.1.3.1 — EDNS0 private-use range 65000–65534 [CITED: RFC 6891, corroborated by miekg/dns comments]

### Tertiary (LOW confidence)

None.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all libraries verified in go.mod and module cache
- Architecture: HIGH — insertion point verified by reading firewalld.go; pattern verified by reading server.go
- Pitfalls: HIGH — derived from direct inspection of miekg/dns source code
- Tests: HIGH — test style verified by reading firewalld_test.go

**Research date:** 2026-04-23
**Valid until:** 2026-05-23 (miekg/dns API is stable; no fast-moving changes expected)
