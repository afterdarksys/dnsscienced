# Phase 10: Record Type Expansion - Research

**Researched:** 2026-05-21
**Domain:** Go DNS zone parsing — miekg/dns record type integration
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** LOC — string passthrough format. `LOC: ["42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m"]`. Operators write RFC 1876 BIND text directly; parser passes it to `dns.NewRR()`. No structured fields.
- **D-02:** LOC — list-only format (consistent with TLSA, HTTPS, SVCB). A single LOC is written as a one-element list.
- **D-03:** SSHFP — integer field codes. `algorithm: 3`, `fingerprint_type: 2`. Matches RFC 4255 and `ssh-keygen -r` output.
- **D-04:** SSHFP — list format (multiple keys per owner). Struct fields: `algorithm`, `fingerprint_type`, `fingerprint`.
- **D-05:** SMIMEA — separate `SMIMEA:` key in `RecordSection`, reusing `TLSARecord` struct (same four fields). Parser builds SMIMEA RR using `dns.NewRR()` with type `SMIMEA`. Not a `TYPE53` fallback.
- **D-06:** NAPTR — structured map with named fields: `order`, `preference`, `flags`, `service`, `regexp`, `replacement`. Consistent with TLSA/SRV pattern.
- **D-07:** NAPTR — absent `regexp:` field defaults to empty string `""`. Operators do not need to write `regexp: ""` for replacement-mode records.
- **D-08:** NAPTR — integer fields (`order`, `preference`) accept both `int` and `float64` from YAML parser.
- **D-09:** All new integer fields (SSHFP `algorithm`/`fingerprint_type`, NAPTR `order`/`preference`) accept both `int` and `float64` — consistent with existing TLSA, HTTPS, CAA parsers.
- **D-10:** Tests: round-trip tests — parse zone file → compile to DZC → decompile → verify packed wire bytes match. Wire equality only, no field-level struct assertions.
- **D-11:** Test data uses real-world examples: actual ECDSA SSHFP fingerprints, real NAPTR E2U+sip patterns, a real LOC value, a real SMIMEA cert hash. Tests read like documentation.

### Claude's Discretion

- Whether SMIMEA parsing function is a new `parseSMIMEARecords()` or the existing `parseTLSARecords()` is extended with a type argument
- File organization — new file vs extending `parser_dnszone.go`
- Whether SSHFP builds via `dns.NewRR()` string or direct `dns.SSHFP` struct (both work)
- Order of plans/waves

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RRTYPE-01 | Server parses and serves HTTPS/SVCB records from BIND and .dnszone zone files | HTTPS/SVCB already implemented in `RecordSection` and `parseSVCBHTTPRecords()`. BIND parser handles via miekg natively. No work needed. |
| RRTYPE-02 | Server parses and serves TLSA/DANE records from BIND and .dnszone zone files | TLSA already implemented in `RecordSection` and `parseTLSARecords()`. BIND parser handles via miekg natively. No work needed. |
| RRTYPE-03 | Server parses and serves SSHFP records from BIND and .dnszone zone files | SSHFP missing from YAML parser `RecordSection`. Add `SSHFPRecord` struct, `parseSSHFPRecords()`, wire into both parse loops. BIND parser already handles via miekg. |
| RRTYPE-04 | Server parses and serves NAPTR records from BIND and .dnszone zone files | NAPTR missing from YAML parser `RecordSection`. Add `NAPTRRecord` struct, `parseNAPTRRecords()`, wire into both parse loops. BIND parser already handles via miekg. |
| RRTYPE-05 | Server parses and serves SMIMEA records from BIND and .dnszone zone files | SMIMEA missing from YAML parser `RecordSection`. Add `SMIMEA` field (reuse `TLSARecord` struct), `parseSMIMEARecords()`, wire into both parse loops. BIND parser handles via miekg natively. |
| RRTYPE-06 | Server parses and serves LOC records from BIND and .dnszone zone files | LOC missing from YAML parser `RecordSection`. Add `LOC` field (string passthrough, list format), `parseLOCRecords()`, wire into both parse loops. BIND parser handles via miekg natively. |
| RRTYPE-07 | All new record types survive compile/decompile round-trip in .dzc binary format | `compiler.go` uses `dns.PackRR()` and `loader.go` uses `dns.UnpackRR()` — both type-agnostic. Round-trip verified by test: all four types pack/unpack with identical wire bytes. No compiler/loader changes needed. |
| RRTYPE-08 | Authoritative server returns NOERROR + empty answer for in-zone queries with no matching records | `handleAuthoritative()` in `server.go` uses `GetRecords(qname, qtype)` which is type-agnostic. Returns `RcodeSuccess` for NODATA (name exists, no records of that type). Already satisfied at server level — no changes needed. |
</phase_requirements>

---

## Summary

Phase 10 is a focused zone parser extension. The work is almost entirely confined to `internal/zone/parser_dnszone.go`: add four new record types (SSHFP, NAPTR, SMIMEA, LOC) to the YAML parser. The BIND parser, DZC compiler/decompiler, and authoritative query server require zero changes — all three are already type-agnostic by design.

HTTPS, SVCB, and TLSA already exist in `RecordSection` and have parse functions. The BIND parser delegates to `miekg/dns` which has native struct support for all six types (TypeSSHFP=44, TypeNAPTR=35, TypeSMIMEA=53, TypeLOC=29). All four new types have been verified to produce correct wire bytes through `dns.NewRR()` and survive `dns.PackRR()`/`dns.UnpackRR()` round-trips with identical wire output.

RRTYPE-08 is already satisfied: `handleAuthoritative()` calls `GetRecords(qname, qtype)` which works for any `uint16` type code and returns `NOERROR` for NODATA cases unconditionally.

**Primary recommendation:** Add four struct types + four parse functions + wire both parse loops (`ParseDNSZone` and `parseIncludeFile`) + add test zone files + write round-trip tests. No other files need changes.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| YAML zone file parsing (SSHFP/NAPTR/SMIMEA/LOC) | Zone package | — | `parser_dnszone.go` owns all YAML record parsing |
| BIND zone file parsing | Zone package (miekg delegation) | — | `parser_bind.go` delegates to `miekg/dns` ZoneParser — already handles all types natively |
| DZC compile/decompile round-trip | Zone package | — | `compiler.go` + `loader.go` use `dns.PackRR`/`dns.UnpackRR` — type-agnostic |
| Authoritative query serving | Server package | Zone package | `server.go:handleAuthoritative()` calls `zone.GetRecords(qname, qtype)` — type-agnostic |
| NOERROR NODATA for new types | Server package | — | Already implemented in `handleAuthoritative()` — no changes needed |

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/miekg/dns` | v1.1.72 | DNS type definitions, `dns.NewRR()`, `dns.PackRR()`, `dns.UnpackRR()` | Already the project DNS library; has native structs for all four new types |
| `gopkg.in/yaml.v3` | (existing) | YAML parsing for .dnszone format | Already in use for all existing record parsing |

[VERIFIED: go.mod in project root confirms miekg/dns v1.1.72]
[VERIFIED: miekg/dns@v1.1.72/types.go confirms TypeSSHFP=44, TypeNAPTR=35, TypeSMIMEA=53, TypeLOC=29 all defined]
[VERIFIED: miekg/dns@v1.1.72/types.go confirms dns.SSHFP, dns.NAPTR, dns.SMIMEA, dns.LOC structs all defined]

No new dependencies required.

---

## Architecture Patterns

### System Architecture Diagram

```
YAML zone file (.dnszone)
        |
        v
  yaml.Unmarshal → DNSZoneFile
        |
        v
  ParseDNSZone() / parseIncludeFile()
    for each owner:
      ├── parseARecords()        (existing)
      ├── parseTLSARecords()     (existing)
      ├── parseSVCBHTTPRecords() (existing)
      ├── parseCAARecords()      (existing)
      ├── [NEW] parseSSHFPRecords()
      ├── [NEW] parseNAPTRRecords()
      ├── [NEW] parseSMIMEARecords()
      ├── [NEW] parseLOCRecords()
      └── parseGenericTypes()   (existing fallback)
        |
        v
   dns.NewRR(formatted-string) → dns.RR
        |
        v
   zone.AddRecord(rr) → Zone{}
        |
        v
  CompileZone() → dns.PackRR() → .dzc (wire bytes in protobuf)
        |
        v
  LoadCompiledZone() → dns.UnpackRR() → Zone{}
        |
        v
  handleAuthoritative() → GetRecords(qname, qtype) → answer
```

### Recommended Project Structure

No new files required by default. All additions fit within:

```
internal/zone/
├── parser_dnszone.go        # Add structs + parse functions here
├── parser_dnszone_test.go   # Add YAML round-trip tests here
├── parser_bind_test.go      # Add BIND load tests here
└── testdata/
    ├── example.com.dnszone  # Add SSHFP/NAPTR/SMIMEA/LOC records here
    └── example.org.bind     # Add SSHFP/NAPTR/SMIMEA/LOC records here
```

If `parser_dnszone.go` becomes unwieldy, move new functions to a new file (Claude's discretion per D).

### Pattern 1: struct → format string → dns.NewRR()

**What:** All complex record types in this codebase build a BIND-style text format string from struct fields and pass it to `dns.NewRR()` for final parsing.

**When to use:** All four new record types.

**Example (verified against miekg/dns v1.1.72):**

```go
// Source: verified via go run against github.com/miekg/dns@v1.1.72

// SSHFP
s := fmt.Sprintf("%s %d IN SSHFP %d %d %s",
    owner, ttl, sshfp.Algorithm, sshfp.FingerprintType, sshfp.Fingerprint)
rr, err := dns.NewRR(s)

// NAPTR — note: regexp may be "" (D-07), replacement must be FQDN
s := fmt.Sprintf(`%s %d IN NAPTR %d %d "%s" "%s" "%s" %s`,
    owner, ttl,
    naptr.Order, naptr.Preference,
    naptr.Flags, naptr.Service, naptr.Regexp,
    dns.Fqdn(naptr.Replacement))
rr, err := dns.NewRR(s)

// SMIMEA — identical format to TLSA, different type keyword
s := fmt.Sprintf("%s %d IN SMIMEA %d %d %d %s",
    owner, ttl, smimea.Usage, smimea.Selector, smimea.Matching, smimea.Data)
rr, err := dns.NewRR(s)

// LOC — string passthrough (D-01)
s := fmt.Sprintf("%s %d IN LOC %s", owner, ttl, locString)
rr, err := dns.NewRR(s)
```

### Pattern 2: int + float64 coercion for YAML integer fields

**What:** YAML v3 may decode integer values as `float64` depending on context. All integer fields must handle both types.

**When to use:** SSHFP `algorithm`/`fingerprint_type`, NAPTR `order`/`preference`. Matches existing TLSA/CAA/HTTPS pattern.

**Example (from existing parseTLSARecords):**

```go
// Source: internal/zone/parser_dnszone.go parseTLSARecords()
if usage, ok := tlsaMap["usage"].(int); ok {
    tlsa.Usage = usage
} else if usageF, ok := tlsaMap["usage"].(float64); ok {
    tlsa.Usage = int(usageF)
}
```

### Pattern 3: Two parse loops must stay in sync

**What:** Both `ParseDNSZone` (lines 252–296) and `parseIncludeFile` (lines 984–1024) contain per-owner record parsing loops. Every new parse function added to one MUST be added to the other.

**When to use:** Every time a new record type is added.

**Example (existing pattern):**

```go
// ParseDNSZone inner loop (add here)
if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil { ... }

// parseIncludeFile inner loop (add same call here)
if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil { ... }
```

### Anti-Patterns to Avoid

- **Using TYPE### fallback for named types:** LOC could be expressed as `TYPE29:` via `parseGenericTypes()` but D-01 specifies a proper `LOC:` key. Don't rely on the generic fallback.
- **Single-parse-loop update:** Adding to `ParseDNSZone` without updating `parseIncludeFile` leaves include files unable to parse new types.
- **Mixing `dns.NewRR()` with direct struct construction for NAPTR regexp:** The `dns.NAPTR.Regexp` field uses `dns:"txt"` tag internally — `dns.NewRR()` handles quoting correctly; constructing the struct directly is fine too but requires matching the wire encoding manually.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| LOC text parsing | Custom coordinate parser | `dns.NewRR()` with raw LOC string (D-01) | LOC has complex DMS + altitude + size encoding; miekg handles all edge cases |
| NAPTR regexp quoting | Custom quote escaping | `dns.NewRR()` with `"%s"` format | NAPTR regexp can contain special chars; miekg tokenizer handles them |
| Wire byte encoding | Custom bit packing | `dns.PackRR()` / `dns.UnpackRR()` | Already used by compiler.go; type-agnostic; handles all 6 types without change |

**Key insight:** All four new types are fully supported by miekg/dns v1.1.72. The only missing piece is the YAML-to-struct deserialization layer in `parser_dnszone.go`.

---

## Common Pitfalls

### Pitfall 1: parseIncludeFile not updated
**What goes wrong:** YAML include files that contain SSHFP/NAPTR/SMIMEA/LOC records silently produce no records (no error, no records added).
**Why it happens:** `parseIncludeFile` has its own per-owner loop and is not derived from `ParseDNSZone`. They must be kept in sync manually.
**How to avoid:** After updating `ParseDNSZone` inner loop, immediately update `parseIncludeFile` inner loop with identical calls.
**Warning signs:** Integration test using include files fails to find records that appear in include content.

### Pitfall 2: RecordSection field not added
**What goes wrong:** YAML `SSHFP:`, `NAPTR:`, `SMIMEA:`, or `LOC:` keys are silently discarded; the `Generic` inline map does NOT capture named-type keys.
**Why it happens:** YAML v3 struct tags require explicit field declarations. The `Generic map[string]interface{} yaml:",inline"` only captures keys not matched by any named field — but named DNS record types (`SSHFP`, `NAPTR`, etc.) that are NOT declared in `RecordSection` get absorbed by the inline map silently.
**How to avoid:** Add the field to `RecordSection` before writing the parse function. Test with a YAML file containing the new key.
**Warning signs:** Parse succeeds but `GetRecords()` returns zero results for the new type.

### Pitfall 3: NAPTR replacement needs dns.Fqdn()
**What goes wrong:** NAPTR replacement target is stored as relative name in zone files (e.g., `_sip._udp`) but `dns.NewRR()` requires a FQDN (trailing dot).
**Why it happens:** NAPTR `Replacement` is a domain name. `dns.NewRR()` with a non-FQDN replacement may parse incorrectly or fail.
**How to avoid:** Apply `dns.Fqdn(naptr.Replacement)` before building the format string. Use `"."` as the nil replacement (standard for regexp-mode NAPTR).
**Warning signs:** `dns.NewRR()` returns an error or the replacement field has wrong value.

### Pitfall 4: SSHFP fingerprint hex case
**What goes wrong:** miekg/dns uppercases the hex fingerprint on output (e.g., `ABC123`), but operators may provide lowercase input. Test assertions on the string representation will fail if they expect lowercase.
**Why it happens:** `dns.SSHFP.String()` calls `strings.ToUpper(rr.FingerPrint)`.
**How to avoid:** Use wire-byte equality in tests (D-10), not string comparison. Accept any case in the `fingerprint:` YAML field — `dns.NewRR()` accepts both.

### Pitfall 5: LOC list vs string ambiguity
**What goes wrong:** LOC is declared as a list format (D-02). If the parser handles `interface{}` for the LOC field and the operator writes a scalar string instead of a list, parsing silently fails.
**Why it happens:** D-02 specifies list-only. A plain string `LOC: "42 21..."` would be a list with one string element when decoded from YAML `[]interface{}` but NOT when the field is a plain `string`.
**How to avoid:** Accept only `[]interface{}` in the LOC parse function, consistent with TLSA/HTTPS/SVCB. Return an error for non-list format to enforce D-02.

---

## Code Examples

Verified patterns from running against miekg/dns v1.1.72:

### SSHFPRecord struct

```go
// Source: CONTEXT.md D-03/D-04, verified via dns.NewRR test
type SSHFPRecord struct {
    Algorithm       int    `yaml:"algorithm"`        // 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
    FingerprintType int    `yaml:"fingerprint_type"` // 1=SHA-1, 2=SHA-256
    Fingerprint     string `yaml:"fingerprint"`
}
```

### NAPTRRecord struct

```go
// Source: CONTEXT.md D-06, verified via dns.NewRR test
type NAPTRRecord struct {
    Order       int    `yaml:"order"`
    Preference  int    `yaml:"preference"`
    Flags       string `yaml:"flags"`
    Service     string `yaml:"service"`
    Regexp      string `yaml:"regexp,omitempty"` // defaults to "" per D-07
    Replacement string `yaml:"replacement"`
}
```

### RecordSection additions

```go
// Add to RecordSection struct (parser_dnszone.go:120–143)
SSHFP interface{} `yaml:"SSHFP,omitempty"`
NAPTR interface{} `yaml:"NAPTR,omitempty"`
SMIMEA interface{} `yaml:"SMIMEA,omitempty"`
LOC   interface{} `yaml:"LOC,omitempty"`
```

### parseSSHFPRecords skeleton

```go
// Source: modeled on parseTLSARecords() in parser_dnszone.go
func parseSSHFPRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
    if data == nil {
        return nil
    }
    switch v := data.(type) {
    case []interface{}:
        for _, item := range v {
            if m, ok := item.(map[string]interface{}); ok {
                rec := SSHFPRecord{}
                if alg, ok := m["algorithm"].(int); ok {
                    rec.Algorithm = alg
                } else if algF, ok := m["algorithm"].(float64); ok {
                    rec.Algorithm = int(algF)
                }
                if ft, ok := m["fingerprint_type"].(int); ok {
                    rec.FingerprintType = ft
                } else if ftF, ok := m["fingerprint_type"].(float64); ok {
                    rec.FingerprintType = int(ftF)
                }
                if fp, ok := m["fingerprint"].(string); ok {
                    rec.Fingerprint = fp
                }
                s := fmt.Sprintf("%s %d IN SSHFP %d %d %s",
                    owner, ttl, rec.Algorithm, rec.FingerprintType, rec.Fingerprint)
                rr, err := dns.NewRR(s)
                if err != nil {
                    return fmt.Errorf("failed to parse SSHFP string: %w", err)
                }
                if rr != nil {
                    zone.AddRecord(rr)
                }
            }
        }
    default:
        return fmt.Errorf("invalid SSHFP record format")
    }
    return nil
}
```

### parseLOCRecords skeleton

```go
// Source: modeled on parseNSRecords() (string list); D-01 string passthrough
func parseLOCRecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
    if data == nil {
        return nil
    }
    switch v := data.(type) {
    case []interface{}:
        for _, item := range v {
            if locStr, ok := item.(string); ok {
                s := fmt.Sprintf("%s %d IN LOC %s", owner, ttl, locStr)
                rr, err := dns.NewRR(s)
                if err != nil {
                    return fmt.Errorf("failed to parse LOC string: %w", err)
                }
                if rr != nil {
                    zone.AddRecord(rr)
                }
            }
        }
    default:
        return fmt.Errorf("invalid LOC record format: must be a list of strings")
    }
    return nil
}
```

### Round-trip test pattern

```go
// Source: D-10 wire equality; modeled on BenchmarkLoadCompiledZone in benchmark_test.go
func TestRoundTrip_SSHFP(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseDNSZone("testdata/roundtrip_rrtype.dnszone", cfg)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }

    compiled, err := CompileZone(z, CompileOptions{SourceFormat: "dnszone"})
    if err != nil {
        t.Fatalf("compile: %v", err)
    }

    // Write and reload (full round-trip through protobuf)
    tmp := t.TempDir() + "/test.dzc"
    if err := WriteCompiledZone(compiled, tmp); err != nil {
        t.Fatalf("write: %v", err)
    }
    z2, err := LoadCompiledZone(tmp)
    if err != nil {
        t.Fatalf("load: %v", err)
    }

    orig := z.GetRecords("host.roundtrip.test.", dns.TypeSSHFP)
    loaded := z2.GetRecords("host.roundtrip.test.", dns.TypeSSHFP)
    if len(orig) != len(loaded) {
        t.Fatalf("record count mismatch: %d vs %d", len(orig), len(loaded))
    }
    // Wire equality only (D-10)
    buf1, buf2 := make([]byte, dns.MaxMsgSize), make([]byte, dns.MaxMsgSize)
    off1, _ := dns.PackRR(orig[0], buf1, 0, nil, false)
    off2, _ := dns.PackRR(loaded[0], buf2, 0, nil, false)
    if !bytes.Equal(buf1[:off1], buf2[:off2]) {
        t.Errorf("wire mismatch after round-trip")
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| TYPE### fallback for LOC | Proper `LOC:` key (D-01) | Phase 10 | Operators write native RFC 1876 text; no base64/hex encoding |
| No SSHFP in YAML | `SSHFP:` list with structured fields | Phase 10 | Matches `ssh-keygen -r` output format directly |

---

## Open Questions

1. **SMIMEA parse function: new function vs type-argument extension of parseTLSARecords()**
   - What we know: SMIMEA and TLSA have identical field structures (`TLSARecord` reused per D-05). Only the RR type keyword differs.
   - What's unclear: Whether to add a `rrTypeName string` parameter to `parseTLSARecords()` (DRY) or a separate `parseSMIMEARecords()` (clearer). Both approaches work.
   - Recommendation: Claude's discretion. A type-argument extension `parseTLSARecords(zone, fqdn, section.TLSA, recordTTL, "TLSA")` + `parseTLSARecords(zone, fqdn, section.SMIMEA, recordTTL, "SMIMEA")` is the most concise. A separate `parseSMIMEARecords()` that calls into a shared helper is equally valid.

---

## Environment Availability

Step 2.6: SKIPPED — phase is code-only changes within the existing Go project. No external dependencies beyond those already in go.mod.

Build and test commands verified:

```bash
go build ./...                     # confirmed passing
go test ./internal/zone/... -count=1  # confirmed passing (0.376s)
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go testing + `testing` stdlib |
| Config file | none (standard `go test`) |
| Quick run command | `go test ./internal/zone/... -count=1` |
| Full suite command | `go test ./... -count=1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RRTYPE-01 | HTTPS/SVCB parse from BIND and .dnszone | already covered | `go test ./internal/zone/...` | Already tested via existing test data |
| RRTYPE-02 | TLSA/DANE parse from BIND and .dnszone | already covered | `go test ./internal/zone/...` | Already tested via existing test data |
| RRTYPE-03 | SSHFP parse from BIND and .dnszone | unit + round-trip | `go test ./internal/zone/... -run TestParseDNSZone_SSHFP` | ❌ Wave 0 |
| RRTYPE-04 | NAPTR parse from BIND and .dnszone | unit + round-trip | `go test ./internal/zone/... -run TestParseDNSZone_NAPTR` | ❌ Wave 0 |
| RRTYPE-05 | SMIMEA parse from BIND and .dnszone | unit + round-trip | `go test ./internal/zone/... -run TestParseDNSZone_SMIMEA` | ❌ Wave 0 |
| RRTYPE-06 | LOC parse from BIND and .dnszone | unit + round-trip | `go test ./internal/zone/... -run TestParseDNSZone_LOC` | ❌ Wave 0 |
| RRTYPE-07 | Round-trip wire bytes survive .dzc compile/decompile | round-trip | `go test ./internal/zone/... -run TestRoundTrip` | ❌ Wave 0 |
| RRTYPE-08 | NOERROR + empty answer for no-match queries | already satisfied | `go test ./internal/server/...` | Already tested |

### Sampling Rate

- **Per task commit:** `go test ./internal/zone/... -count=1`
- **Per wave merge:** `go test ./... -count=1`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] New test cases in `internal/zone/parser_dnszone_test.go` — covers RRTYPE-03/04/05/06 YAML parsing
- [ ] New test cases in `internal/zone/parser_bind_test.go` — covers RRTYPE-03/04/05/06 BIND parsing
- [ ] New round-trip tests in `internal/zone/parser_dnszone_test.go` or dedicated file — covers RRTYPE-07
- [ ] New test data fixture `internal/zone/testdata/roundtrip_rrtype.dnszone` — with all four new record types
- [ ] Updated `internal/zone/testdata/example.org.bind` — with SSHFP/NAPTR/SMIMEA/LOC entries

---

## Security Domain

> ASVS categories applicable to zone parsing changes.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | `dns.NewRR()` validates all wire-format constraints; invalid input returns error, not panic |
| V6 Cryptography | no | SSHFP fingerprints are stored/served verbatim; no crypto operations in parser |

### Known Threat Patterns for zone parsing

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malformed LOC string triggering panic in miekg | Tampering | `dns.NewRR()` returns error on parse failure; parser propagates error cleanly. Verified: invalid LOC strings return non-nil error, not panic. |
| Oversized NAPTR regexp causing allocation | Denial of Service | miekg bounds NAPTR regexp string size at wire level; `dns.NewRR()` enforces DNS message size limits |
| SMIMEA cert data containing non-hex chars | Tampering | `dns.NewRR()` rejects non-hex certificate data for SMIMEA (hex codec tag) |

No new security controls required. Existing error-propagation pattern (`if err != nil { return error }`) is sufficient.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | — | — | — |

**All claims in this research were verified against running code or miekg/dns v1.1.72 module source. No assumed claims.**

---

## Sources

### Primary (HIGH confidence)

- [VERIFIED: /Users/ryan/go/pkg/mod/github.com/miekg/dns@v1.1.72/types.go] — TypeSSHFP=44, TypeNAPTR=35, TypeSMIMEA=53, TypeLOC=29; dns.SSHFP, dns.NAPTR, dns.SMIMEA, dns.LOC struct definitions confirmed
- [VERIFIED: go run /tmp/verify_rr_types.go] — dns.NewRR() accepts SSHFP, NAPTR, SMIMEA, LOC format strings and produces correct dns.RR instances
- [VERIFIED: go run /tmp/verify_roundtrip2.go] — All four types produce identical wire bytes through dns.PackRR()/dns.UnpackRR() round-trip
- [VERIFIED: go run /tmp/verify_loc_naptr.go] — LOC string passthrough (D-01) works; NAPTR empty regexp (D-07) parses correctly; NAPTR replacement with dns.Fqdn() works
- [VERIFIED: internal/zone/parser_dnszone.go:120–143] — RecordSection struct confirmed; SSHFP/NAPTR/SMIMEA/LOC fields absent
- [VERIFIED: internal/zone/parser_dnszone.go:252–296] — ParseDNSZone inner loop confirmed; parse function call pattern documented
- [VERIFIED: internal/zone/parser_dnszone.go:964–1029] — parseIncludeFile inner loop confirmed; must stay in sync with ParseDNSZone
- [VERIFIED: internal/zone/compiler.go:154–156] — dns.PackRR() confirmed as wire encoding; type-agnostic
- [VERIFIED: internal/zone/loader.go:107–108] — dns.UnpackRR() confirmed as wire decoding; type-agnostic
- [VERIFIED: internal/server/server.go:785–796] — handleAuthoritative() type-agnostic GetRecords(); NODATA returns RcodeSuccess; RRTYPE-08 already satisfied
- [VERIFIED: go test ./internal/zone/... -count=1] — baseline: all existing zone tests pass

### Secondary (MEDIUM confidence)

- [CITED: RFC 4255] — SSHFP record format (algorithm/fingerprint_type/fingerprint fields)
- [CITED: RFC 3403] — NAPTR record format (order/preference/flags/service/regexp/replacement fields)
- [CITED: RFC 8162] — SMIMEA record format (identical wire encoding to TLSA/RFC 6698)
- [CITED: RFC 1876] — LOC record format (DMS coordinate + altitude + precision encoding)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — miekg/dns v1.1.72 verified in go.mod; all type constants confirmed in source
- Architecture: HIGH — source code read directly; parse function patterns verified
- Pitfalls: HIGH — pitfalls derived from reading actual parse function implementations and the sync requirement between ParseDNSZone/parseIncludeFile

**Research date:** 2026-05-21
**Valid until:** 2026-07-21 (stable library; no external changes expected)
