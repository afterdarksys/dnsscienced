---
phase: 04-edns0-customerid
reviewed: 2026-04-23T00:00:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - internal/firewalld/edns0.go
  - internal/firewalld/firewalld.go
  - internal/firewalld/firewalld_test.go
findings:
  critical: 0
  warning: 3
  info: 3
  total: 6
status: issues_found
---

# Phase 04: Code Review Report — EDNS0 CustomerID

**Reviewed:** 2026-04-23
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

Phase 4 added EDNS0 CustomerID extraction via a new `edns0.go` helper, a one-line
wire-up in `firewalld.go`, and 7 new tests in `firewalld_test.go`. The implementation
is clean and the core logic is correct: option code filtering, type assertion to
`*dns.EDNS0_LOCAL`, and the 64-byte cap all work as intended. The integration into
the `Check()` pipeline (line 181, after `r.Question[0]` is confirmed present) is
safe.

Three warnings are raised: a latent nil-dereference in `Check()` that predates this
phase but is made slightly more visible by the new call, a misleading comment about
the forwarder timeout multiplier, and the absence of a boundary test at exactly the
64-byte cap. Three info items cover missing edge-case tests, an unvalidated byte
payload, and a minor doc gap.

No critical (security or data-loss) issues were found. The threat model requirements
T-04-01 through T-04-04 are satisfied by the implementation.

---

## Warnings

### WR-01: Nil `*dns.Msg` panics before any guard in `Check()`

**File:** `internal/firewalld/firewalld.go:167`

**Issue:** The nil guard reads `len(r.Question)` before checking whether `r` itself is
nil. If a caller passes `r == nil`, the expression `len(r.Question)` panics with a
nil pointer dereference. This predates Phase 4 but is now slightly more exposed:
`extractCustomerID(r, ...)` is called at line 181 and calls `r.IsEdns0()` — a second
panic site if `r` ever reaches line 181 as nil (it cannot in the current flow, but the
function contract is undocumented).

**Fix:** Add an explicit nil guard at the top of `Check()`:

```go
func (fw *Firewall) Check(r *dns.Msg, clientIP net.IP) *Decision {
    if r == nil || !fw.enabled.Load() || len(r.Question) == 0 {
        return allow()
    }
    // ...
}
```

---

### WR-02: Forwarder timeout multiplier comment is wrong (1500× vs 3×)

**File:** `internal/firewalld/firewalld.go:148`

**Issue:** The comment says "generous: 3× script timeout" but the actual multiplier is
`1500`. If `ScriptTimeout` is a `time.Duration` in nanoseconds (standard Go), then
`cfg.ScriptTimeout * 1500` is 1500× — e.g., a 2s script timeout produces a 3000s
(50-minute) forwarder timeout. The intent appears to be 3× but the code applies 1500×.
This is almost certainly a latent bug from a unit mismatch or a transcription error.

**Fix:** Determine the intended multiplier. If the goal is 3× the script timeout:

```go
forwarder: NewForwarder(cfg.ScriptTimeout * 3), // 3× script timeout
```

If `NewForwarder` expects milliseconds and `ScriptTimeout` is in seconds, use explicit
conversion rather than a bare integer multiplication.

---

### WR-03: Missing boundary test at exactly 64 bytes for the cap

**File:** `internal/firewalld/firewalld_test.go:453`

**Issue:** `TestExtractCustomerID` tests 65-byte (oversized, rejected) and short strings
(accepted), but not exactly 64 bytes. The guard is `len(local.Data) > 64` (strictly
greater than), so 64 bytes must be accepted. The absence of this case leaves the
boundary condition untested; a future change from `>` to `>=` would silently break
valid 64-byte customer IDs without a failing test.

**Fix:** Add a table entry:

```go
{
    name:       "exactly_64_bytes",
    msg:        makeQueryWithCustomerID("example.com.", dns.TypeA, strings.Repeat("x", 64)),
    wantResult: strings.Repeat("x", 64),
},
```

---

## Info

### IN-01: `string(local.Data)` accepts arbitrary binary bytes without validation

**File:** `internal/firewalld/edns0.go:38`

**Issue:** `local.Data` is raw bytes from the network. Converting it directly with
`string(local.Data)` may produce non-UTF-8 strings. While Go strings are byte strings
and this causes no immediate crash, if `CustomerID` is ever serialized to JSON, logged
as a structured field, or compared against config keys with Unicode normalization, the
binary data could produce unexpected behaviour. The current usage (map key lookup in
`ThreatIntel.Score`) is safe, but the lack of validation is a latent issue.

**Fix (optional hardening):** If customer IDs are always printable ASCII, validate
before returning:

```go
for _, b := range local.Data {
    if b < 0x20 || b > 0x7E {
        logger.Debug().Msg("edns0 customer_id contains non-printable bytes, ignoring")
        return ""
    }
}
return string(local.Data)
```

---

### IN-02: No test for OPT present but empty options list

**File:** `internal/firewalld/firewalld_test.go`

**Issue:** There is no test for a message that carries an OPT record with an empty
`Option` slice (valid EDNS0 with no local options). `extractCustomerID` handles this
correctly (the `for range` loop does nothing), but there is no test asserting it.
This edge case is common — many resolvers send bare EDNS0 for buffer-size negotiation.

**Fix:** Add a table entry to `TestExtractCustomerID`:

```go
{
    name: "opt_present_no_options",
    msg: func() *dns.Msg {
        m := makeQuery("example.com.", dns.TypeA)
        opt := new(dns.OPT)
        opt.Hdr.Name = "."
        opt.Hdr.Rrtype = dns.TypeOPT
        // No opt.Option entries — bare EDNS0.
        m.Extra = append(m.Extra, opt)
        return m
    }(),
    wantResult: "",
},
```

---

### IN-03: `extractCustomerID` doc comment does not mention nil-message behaviour

**File:** `internal/firewalld/edns0.go:19-21`

**Issue:** The function comment says "returns '' if the option is absent or invalid"
but does not mention what happens if `r` is nil. `r.IsEdns0()` will panic on a nil
receiver. The function signature accepts `*dns.Msg` which is nullable. Documenting the
precondition (or adding a nil guard) makes the contract explicit.

**Fix:** Add a nil guard or extend the comment:

```go
// extractCustomerID returns the customer identifier from the EDNS0 option with
// code 65000, or "" if the option is absent or invalid.
// r must not be nil.
func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string {
    if r == nil {
        return ""
    }
    // ...
}
```

---

_Reviewed: 2026-04-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
