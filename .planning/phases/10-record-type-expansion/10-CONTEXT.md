# Phase 10: Record Type Expansion - Context

**Gathered:** 2026-05-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Add SSHFP, NAPTR, SMIMEA, and LOC record type support to the `.dnszone` YAML parser (`internal/zone/parser_dnszone.go`). The BIND parser already handles all six new types via `miekg/dns` library delegation — no changes needed there. The DZC compiler/decompiler is fully type-agnostic (`dns.PackRR`/`dns.UnpackRR`) and handles any type that miekg can represent — no changes needed there either. The authoritative query server already returns `NOERROR + empty answer` for in-zone names with no matching records — RRTYPE-08 is already satisfied at the server level.

The work is concentrated in the YAML parser: add four new record types to `RecordSection`, add parse functions, wire them into `ParseDNSZone` and `parseIncludeFile`, and write round-trip tests.

HTTPS and SVCB already exist in `RecordSection` and have parse functions. TLSA already exists. The four missing types are: **SSHFP**, **NAPTR**, **SMIMEA**, **LOC**.

</domain>

<decisions>
## Implementation Decisions

### LOC Record YAML Format
- **D-01:** String passthrough — `LOC: ["42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m"]`. Operators write the RFC 1876 BIND text format directly as a YAML string; the parser passes it to `dns.NewRR()`. No structured fields.
- **D-02:** List-only format (consistent with TLSA, HTTPS, SVCB). A single LOC is written as a one-element list.

### SSHFP Record YAML Format
- **D-03:** Integer field codes — `algorithm: 3` (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519), `fingerprint_type: 2` (1=SHA-1, 2=SHA-256). Matches RFC 4255 and `ssh-keygen -r` output. Operators copy-paste directly without translation.
- **D-04:** List format (multiple keys per owner). Struct fields: `algorithm`, `fingerprint_type`, `fingerprint`.

### SMIMEA Record YAML Format
- **D-05:** Separate `SMIMEA:` key in `RecordSection`, reusing the `TLSARecord` struct (same four fields: `usage`, `selector`, `matching`, `data`). The parser builds an SMIMEA RR using `dns.NewRR()` with type `SMIMEA` instead of `TLSA`. Not handled via generic `TYPE53` fallback.

### NAPTR Record YAML Format
- **D-06:** Structured map with named fields: `order`, `preference`, `flags`, `service`, `regexp`, `replacement`. Consistent with TLSA/SRV pattern.
- **D-07:** Absent `regexp:` field defaults to empty string `""` — operators do not need to write `regexp: ""` for replacement-mode records. This matches BIND zone file convention.
- **D-08:** Integer fields (`order`, `preference`) accept both `int` and `float64` from the YAML parser — consistent with existing TLSA/HTTPS/CAA parsers.

### Integer Field Coercion
- **D-09:** All new integer fields (SSHFP `algorithm`/`fingerprint_type`, NAPTR `order`/`preference`) accept both `int` and `float64` from the YAML parser — consistent with existing TLSA, HTTPS, CAA parsers.

### Test Strategy
- **D-10:** Round-trip tests: parse zone file → compile to DZC → decompile → verify packed wire bytes match. Wire equality only — no field-level struct assertions.
- **D-11:** Test data uses real-world examples: actual ECDSA SSHFP fingerprints, real NAPTR E2U+sip patterns, a real LOC value, a real SMIMEA cert hash. Tests read like documentation.

### Claude's Discretion
- Whether SMIMEA parsing function is a new `parseSMIMEARecords()` or the existing `parseTLSARecords()` is extended with a type argument
- File organization — new file vs extending `parser_dnszone.go`
- Whether SSHFP builds via `dns.NewRR()` string or direct `dns.SSHFP` struct (both work)
- Order of plans/waves

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Zone Parser (primary work area)
- `internal/zone/parser_dnszone.go` — YAML parser; add SSHFP/NAPTR/SMIMEA/LOC to `RecordSection`, add parse functions, wire into `ParseDNSZone` and `parseIncludeFile`
- `internal/zone/parser_bind.go` — BIND parser; delegates to `miekg/dns` — no changes needed but read to understand existing patterns

### DZC Compiler/Decompiler (round-trip)
- `internal/zone/compiler.go` — uses `dns.PackRR()` — type-agnostic, no changes needed
- `internal/zone/loader.go` — uses `dns.UnpackRR()` — type-agnostic, no changes needed

### Existing Record Type Patterns
- `internal/zone/parser_dnszone.go` — `parseTLSARecords()`, `parseSVCBHTTPRecords()`, `parseCAARecords()` — established pattern: structured struct → build zone-file string → `dns.NewRR()`
- `internal/zone/parser_dnszone.go` — `RecordSection` struct (lines 120–143) — where new fields must be added

### Tests
- `internal/zone/parser_dnszone_test.go` — existing YAML parser tests; extend here
- `internal/zone/parser_bind_test.go` — existing BIND parser tests; add BIND round-trip tests for all 6 types

### RFCs (for wire format reference)
- RFC 4255 — SSHFP record format
- RFC 3403 — NAPTR record format  
- RFC 8162 — SMIMEA record format (identical wire encoding to TLSA/RFC 6698)
- RFC 1876 — LOC record format

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `TLSARecord` struct — reuse directly for SMIMEA parsing (same fields: `usage`, `selector`, `matching`, `data`)
- `parseTLSARecords()` — template for SMIMEA parser; only change is RR type string from `"TLSA"` to `"SMIMEA"` in the `dns.NewRR()` format string
- `parseSVCBHTTPRecords()` — template for multi-value list parsing with struct extraction from `map[string]interface{}`
- `parseGenericTypes()` — already handles LOC via `TYPE29` as a fallback, but LOC needs a proper `LOC:` key

### Established Patterns
- **struct → string → `dns.NewRR()`**: All complex types (TLSA, HTTPS, CAA) build a BIND-style text string and delegate final parsing to `dns.NewRR()`. New types should follow this pattern.
- **int + float64 coercion**: `if val, ok := m["field"].(int); ok { ... } else if valF, ok := m["field"].(float64); ok { ... }` — must be applied to all integer fields.
- **`parseIncludeFile` must be updated** whenever `ParseDNSZone` is updated — they share the same per-owner record parsing loop and must stay in sync.

### Integration Points
- `RecordSection` struct (`parser_dnszone.go:120`) — add `SSHFP`, `NAPTR`, `SMIMEA`, `LOC` fields
- `ParseDNSZone` inner loop (`parser_dnszone.go:252–296`) — add calls to new parse functions
- `parseIncludeFile` inner loop (`parser_dnszone.go:984–1024`) — add same calls (keep in sync with `ParseDNSZone`)
- BIND parser requires no changes — `miekg/dns` ZoneParser handles all types natively

</code_context>

<specifics>
## Specific Ideas

- SSHFP YAML example (from discussion):
  ```yaml
  SSHFP:
    - algorithm: 3        # 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
      fingerprint_type: 2 # 1=SHA-1, 2=SHA-256
      fingerprint: "abc123...deadbeef"
  ```

- NAPTR YAML example (from discussion):
  ```yaml
  NAPTR:
    - order: 100
      preference: 10
      flags: "u"
      service: "E2U+sip"
      regexp: "!^.*$!sip:info@example.com!"
      replacement: "."
  ```

- SMIMEA YAML example (from discussion):
  ```yaml
  "_smimecert._tcp.user":
    SMIMEA:
      - usage: 3
        selector: 1
        matching: 1
        data: "abc123..."
  ```

- LOC YAML example (from discussion):
  ```yaml
  LOC:
    - "42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m"
  ```

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 10-record-type-expansion*
*Context gathered: 2026-05-21*
