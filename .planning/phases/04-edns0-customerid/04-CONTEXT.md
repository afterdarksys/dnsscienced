# Phase 4: EDNS0 CustomerID — Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Extract a CustomerID from a custom EDNS0 option on each incoming DNS query and populate `QueryContext.CustomerID` before any firewall evaluation runs. The field already exists in the struct; the only missing piece is the extraction and population.

No new user-facing behavior, no config changes, no new firewall verdicts. This phase is purely intake plumbing.

</domain>

<decisions>
## Implementation Decisions

### EDNS0 Option Code
- **D-01:** Use option code **65000** for the CustomerID EDNS0 option.
- **D-02:** Define a named constant (e.g. `edns0CustomerIDCode = 65000`) with a doc comment citing the private-use range: RFC 6891 §6.1.3.1 (65000–65534 are private use / local experimentation).

### Extraction Location
- **D-03:** Extraction happens **inside `Firewall.Check()`** — it already receives the full `*dns.Msg` and constructs `qctx`. No signature change to `Check()`. All firewall-related extraction stays encapsulated in the firewall package.
- **D-04:** The extraction reads `r.IsEdns0()`, iterates options, finds code 65000, and sets `qctx.CustomerID` before any policy/junk/intel evaluation runs.

### Payload Format & Validation
- **D-05:** Payload bytes are treated as a raw UTF-8 string. No special encoding or escaping.
- **D-06:** Maximum payload length is **64 bytes**. Payloads exceeding this are dropped (CustomerID stays `""`).
- **D-07:** If EDNS0 OPT record is absent or option code 65000 is not present, `CustomerID` remains `""` — no action taken.

### Error Handling
- **D-08:** **Absent or malformed option** → `CustomerID = ""`, silent. Query proceeds normally.
- **D-09:** **Oversized payload (> 64 bytes)** → `CustomerID = ""`, log one **debug-level** message (e.g. `"edns0 customer_id payload too large, ignoring"` with the actual length). This helps diagnose misconfigured DNS clients without polluting normal traffic logs.

### Claude's Discretion
- Exact constant name and file placement within the `firewalld` package (e.g. inline in `firewalld.go` or a new small `edns0.go` file).
- Whether to write a helper function `extractCustomerID(r *dns.Msg) string` or inline the extraction directly in `Check()`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing Codebase — Key Files
- `internal/firewalld/firewalld.go` — `QueryContext` struct (line 70–82), `Firewall.Check()` (line 165–), `qctx` construction (line 175–180). This is the primary insertion point.
- `internal/firewalld/starlark.go` — `buildQueryValue()` (line 277–) already exposes `q.customer_id` to Starlark scripts. No changes needed here.
- `internal/firewalld/threat_intel.go` — `Score()` (line 75–) already uses `qctx.CustomerID` for customer-specific score bonuses (lines 105–106). No changes needed here.
- `internal/server/server.go` — `s.firewall.Check(r, clientIP)` call site (line 411). EDNS0 cookie parsing pattern (lines 448–460) — shows how the codebase reads `r.IsEdns0()` and iterates options.

### Standards
- RFC 6891 §6.1.3.1 — EDNS0 private-use option code range (65000–65534)

### Requirements
- `CUST-01`: Extract CustomerID from EDNS0 option at query intake
- `CUST-02`: Extracted CustomerID stored in QueryContext and visible to firewall policy
- `CUST-03`: Queries without a CustomerID EDNS0 option handled gracefully (empty string)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dns.EDNS0` interface and `r.IsEdns0()` from the `github.com/miekg/dns` package — already used in `server.go` for cookie parsing; same pattern applies here.
- `QueryContext.CustomerID string` (firewalld.go:81) — field exists, just never set.

### Established Patterns
- `qctx` is constructed in `Check()` with a struct literal (lines 175–180). The CustomerID extraction and assignment belongs immediately after the struct literal, before any evaluation chain.
- Zerolog debug logging: `fw.logger.Debug().Int("len", len(data)).Msg("edns0 customer_id payload too large, ignoring")` — matches the zerolog usage style in firewalld.go.
- Pre-existing test coverage: `internal/firewalld/firewalld_test.go` — new tests should follow the same package-internal style.

### Integration Points
- `Firewall.Check()` is the only required change in production code.
- `server.go` is NOT modified — the extraction is fully encapsulated in the firewall package per D-03.

</code_context>

<specifics>
## Specific Ideas

- User noted they selected all 4 areas "because the use cases are different" — implying each decision is meaningful to them, not a rubber-stamp. Plan should treat all four as first-class constraints, not defaults.
- 64-byte cap was chosen with UUID-length identifiers in mind (36 chars for a standard UUID, leaving headroom for prefixed variants).

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 04-edns0-customerid*
*Context gathered: 2026-04-23*
