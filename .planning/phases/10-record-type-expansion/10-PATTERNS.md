# Phase 10: Record Type Expansion - Pattern Map

**Mapped:** 2026-05-21
**Files analyzed:** 5 (2 modified source files, 2 modified test files, 2 new test data fixtures)
**Analogs found:** 5 / 5

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/zone/parser_dnszone.go` | parser/model | transform | self (existing `parseTLSARecords`, `parseCAARecords`, `parseSVCBHTTPRecords`) | exact |
| `internal/zone/parser_dnszone_test.go` | test | request-response | `internal/zone/parser_bind_test.go` + existing `parser_dnszone_test.go` | exact |
| `internal/zone/parser_bind_test.go` | test | request-response | self (existing `TestParseBIND_*` functions) | exact |
| `internal/zone/testdata/roundtrip_rrtype.dnszone` | test fixture | — | `internal/zone/testdata/example.com.dnszone` | exact |
| `internal/zone/testdata/example.org.bind` | test fixture | — | self (existing BIND zone file) | exact |

---

## Pattern Assignments

### `internal/zone/parser_dnszone.go` — RecordSection additions

**Analog:** `internal/zone/parser_dnszone.go` lines 120–143 (RecordSection struct)

**Existing RecordSection pattern** (lines 121–143):
```go
type RecordSection struct {
    A       interface{} `yaml:"A,omitempty"`
    AAAA    interface{} `yaml:"AAAA,omitempty"`
    CNAME   string      `yaml:"CNAME,omitempty"`
    MX      interface{} `yaml:"MX,omitempty"`
    NS      interface{} `yaml:"NS,omitempty"`
    TXT     interface{} `yaml:"TXT,omitempty"`
    SRV     interface{} `yaml:"SRV,omitempty"`
    PTR     string      `yaml:"PTR,omitempty"`
    TLSA    interface{} `yaml:"TLSA,omitempty"`
    HTTPS   interface{} `yaml:"HTTPS,omitempty"`
    SVCB    interface{} `yaml:"SVCB,omitempty"`
    CAA     interface{} `yaml:"CAA,omitempty"`

    Generic map[string]interface{} `yaml:",inline"`

    TTL     int    `yaml:"ttl,omitempty"`
    Comment string `yaml:"comment,omitempty"`
    Reverse bool   `yaml:"reverse,omitempty"`
}
```

**Add four fields** after the `CAA` line, before `Generic`:
```go
    SSHFP  interface{} `yaml:"SSHFP,omitempty"`
    NAPTR  interface{} `yaml:"NAPTR,omitempty"`
    SMIMEA interface{} `yaml:"SMIMEA,omitempty"`
    LOC    interface{} `yaml:"LOC,omitempty"`
```

---

### `internal/zone/parser_dnszone.go` — New struct types

**Analog:** `TLSARecord` struct (lines 160–165), `CAARecord` (lines 175–179), `SRVRecord` (lines 151–157)

**TLSARecord pattern** (lines 160–165) — reuse directly for SMIMEA:
```go
type TLSARecord struct {
    Usage     int    `yaml:"usage"`
    Selector  int    `yaml:"selector"`
    Matching  int    `yaml:"matching"`
    Data      string `yaml:"data"`
}
```

**New structs to add** (modeled on TLSARecord / CAARecord style):
```go
// SSHFPRecord represents an SSHFP record (RFC 4255)
type SSHFPRecord struct {
    Algorithm       int    `yaml:"algorithm"`        // 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
    FingerprintType int    `yaml:"fingerprint_type"` // 1=SHA-1, 2=SHA-256
    Fingerprint     string `yaml:"fingerprint"`
}

// NAPTRRecord represents a NAPTR record (RFC 3403)
type NAPTRRecord struct {
    Order       int    `yaml:"order"`
    Preference  int    `yaml:"preference"`
    Flags       string `yaml:"flags"`
    Service     string `yaml:"service"`
    Regexp      string `yaml:"regexp,omitempty"` // defaults to "" per D-07
    Replacement string `yaml:"replacement"`
}
```

SMIMEA reuses `TLSARecord` directly (D-05). LOC uses a plain string — no struct needed.

---

### `internal/zone/parser_dnszone.go` — parseTLSARecords (primary analog for all four new parse functions)

**Analog:** `parseTLSARecords` (lines 738–786) — the canonical "struct → format string → dns.NewRR()" pattern

**Full parseTLSARecords for copy reference** (lines 738–786):
```go
func parseTLSARecords(zone *Zone, owner string, data interface{}, ttl uint32) error {
    if data == nil {
        return nil
    }

    tlsaList := []TLSARecord{}
    switch v := data.(type) {
    case []interface{}:
        for _, item := range v {
            if tlsaMap, ok := item.(map[string]interface{}); ok {
                tlsa := TLSARecord{}
                if usage, ok := tlsaMap["usage"].(int); ok {
                    tlsa.Usage = usage
                } else if usageF, ok := tlsaMap["usage"].(float64); ok {
                    tlsa.Usage = int(usageF)
                }
                if selector, ok := tlsaMap["selector"].(int); ok {
                    tlsa.Selector = selector
                } else if selectorF, ok := tlsaMap["selector"].(float64); ok {
                    tlsa.Selector = int(selectorF)
                }
                if matching, ok := tlsaMap["matching"].(int); ok {
                    tlsa.Matching = matching
                } else if matchingF, ok := tlsaMap["matching"].(float64); ok {
                    tlsa.Matching = int(matchingF)
                }
                if d, ok := tlsaMap["data"].(string); ok {
                    tlsa.Data = d
                }
                tlsaList = append(tlsaList, tlsa)
            }
        }
    default:
        return fmt.Errorf("invalid TLSA record format")
    }

    for _, tlsa := range tlsaList {
        s := fmt.Sprintf("%s %d IN TLSA %d %d %d %s", owner, ttl, tlsa.Usage, tlsa.Selector, tlsa.Matching, tlsa.Data)
        rr, err := dns.NewRR(s)
        if err != nil {
            return fmt.Errorf("failed to parse TLSA string: %w", err)
        }
        if rr != nil {
            zone.AddRecord(rr)
        }
    }
    return nil
}
```

**What changes per new type:**
- `parseSMIMEARecords`: identical to `parseTLSARecords`; change `"TLSA"` → `"SMIMEA"` in format string and error messages. (Alternatively: add `rrTypeName string` parameter to `parseTLSARecords` and call with `"TLSA"` / `"SMIMEA"` — planner's discretion per D.)
- `parseSSHFPRecords`: same switch/loop shape; extract `algorithm`, `fingerprint_type`, `fingerprint` fields; format: `"%s %d IN SSHFP %d %d %s"`
- `parseNAPTRRecords`: same switch/loop shape; extract 6 fields; apply `dns.Fqdn(naptr.Replacement)`; format: ``"%s %d IN NAPTR %d %d \"%s\" \"%s\" \"%s\" %s"``
- `parseLOCRecords`: same switch shape but `case []interface{}` extracts `string` items (not maps); format: `"%s %d IN LOC %s"`

**parseCAARecords — secondary analog** (lines 694–736): shows exact int+float64 coercion pattern and format string approach with `dns.NewRR()`:
```go
if flags, ok := caaMap["flags"].(int); ok {
    caa.Flags = flags
} else if flagsF, ok := caaMap["flags"].(float64); ok {
    caa.Flags = int(flagsF)
}
// ...
s := fmt.Sprintf("%s %d IN CAA %d %s \"%s\"", owner, ttl, caa.Flags, caa.Tag, caa.Value)
rr, err := dns.NewRR(s)
if err != nil {
    return fmt.Errorf("failed to parse CAA string: %w", err)
}
if rr != nil {
    zone.AddRecord(rr)
}
```

**parseSVCBHTTPRecords — type-argument analog** (lines 788–851): shows how a single function handles two record types via a `recType string` parameter. Apply this same approach to SMIMEA if planner extends `parseTLSARecords` with a type argument:
```go
func parseSVCBHTTPRecords(zone *Zone, owner string, data interface{}, ttl uint32, recType string) error {
    // ...
    s := fmt.Sprintf("%s %d IN %s %d %s%s", owner, ttl, recType, ...)
    rr, err := dns.NewRR(s)
    if err != nil {
        return fmt.Errorf("failed to parse %s string: %w: %s", recType, err, s)
    }
    // ...
}
```

**parseNSRecords — string-list analog** (lines 530–564): shows the pattern for LOC (list of plain strings, not maps):
```go
case []interface{}:
    for _, ns := range v {
        if nsStr, ok := ns.(string); ok {
            nameservers = append(nameservers, nsStr)
        }
    }
```

---

### `internal/zone/parser_dnszone.go` — ParseDNSZone inner loop (lines 252–296)

**Wire-in pattern** (lines 282–297) — add four new calls after the existing SVCB call and before `parseGenericTypes`:
```go
// Existing calls (lines 284–291):
if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil {
    return nil, fmt.Errorf("parse TLSA records for %s: %w", owner, err)
}
if err := parseSVCBHTTPRecords(zone, fqdn, section.HTTPS, recordTTL, "HTTPS"); err != nil {
    return nil, fmt.Errorf("parse HTTPS records for %s: %w", owner, err)
}
if err := parseSVCBHTTPRecords(zone, fqdn, section.SVCB, recordTTL, "SVCB"); err != nil {
    return nil, fmt.Errorf("parse SVCB records for %s: %w", owner, err)
}

// Add after SVCB, before parseGenericTypes:
if err := parseSSHFPRecords(zone, fqdn, section.SSHFP, recordTTL); err != nil {
    return nil, fmt.Errorf("parse SSHFP records for %s: %w", owner, err)
}
if err := parseNAPTRRecords(zone, fqdn, section.NAPTR, recordTTL); err != nil {
    return nil, fmt.Errorf("parse NAPTR records for %s: %w", owner, err)
}
if err := parseSMIMEARecords(zone, fqdn, section.SMIMEA, recordTTL); err != nil {
    return nil, fmt.Errorf("parse SMIMEA records for %s: %w", owner, err)
}
if err := parseLOCRecords(zone, fqdn, section.LOC, recordTTL); err != nil {
    return nil, fmt.Errorf("parse LOC records for %s: %w", owner, err)
}
```

---

### `internal/zone/parser_dnszone.go` — parseIncludeFile inner loop (lines 977–1028)

**CRITICAL:** Must mirror `ParseDNSZone` inner loop exactly. **Analog:** lines 1015–1026.

**Existing tail** (lines 1015–1026):
```go
if err := parseTLSARecords(zone, fqdn, section.TLSA, recordTTL); err != nil {
    return fmt.Errorf("TLSA records for %s: %w", owner, err)
}
if err := parseSVCBHTTPRecords(zone, fqdn, section.HTTPS, recordTTL, "HTTPS"); err != nil {
    return fmt.Errorf("HTTPS records for %s: %w", owner, err)
}
if err := parseSVCBHTTPRecords(zone, fqdn, section.SVCB, recordTTL, "SVCB"); err != nil {
    return fmt.Errorf("SVCB records for %s: %w", owner, err)
}
if err := parseGenericTypes(zone, fqdn, section.Generic, recordTTL); err != nil {
    return fmt.Errorf("generic types for %s: %w", owner, err)
}
```

**Add four calls before `parseGenericTypes`** (same pattern, shorter error message prefix to match include file style):
```go
if err := parseSSHFPRecords(zone, fqdn, section.SSHFP, recordTTL); err != nil {
    return fmt.Errorf("SSHFP records for %s: %w", owner, err)
}
if err := parseNAPTRRecords(zone, fqdn, section.NAPTR, recordTTL); err != nil {
    return fmt.Errorf("NAPTR records for %s: %w", owner, err)
}
if err := parseSMIMEARecords(zone, fqdn, section.SMIMEA, recordTTL); err != nil {
    return fmt.Errorf("SMIMEA records for %s: %w", owner, err)
}
if err := parseLOCRecords(zone, fqdn, section.LOC, recordTTL); err != nil {
    return fmt.Errorf("LOC records for %s: %w", owner, err)
}
```

---

### `internal/zone/parser_dnszone_test.go` — New YAML parse tests

**Analog:** `internal/zone/parser_dnszone_test.go` — `TestParseDNSZone_ARecords` pattern (lines 99–130); `internal/zone/parser_bind_test.go` — `TestParseBIND` pattern (lines 11–25)

**Existing test structure** (lines 99–120):
```go
func TestParseDNSZone_ARecords(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseDNSZone("testdata/example.com.dnszone", cfg)
    if err != nil {
        t.Fatalf("ParseDNSZone() error = %v", err)
    }

    aRecords := z.GetRecords("www.example.com.", dns.TypeA)
    if len(aRecords) != 2 {
        t.Errorf("www has %d A records, want 2", len(aRecords))
    }
    // ...
}
```

**New tests copy this shape** (parse testdata → GetRecords → assert count > 0):
```go
func TestParseDNSZone_SSHFP(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseDNSZone("testdata/roundtrip_rrtype.dnszone", cfg)
    if err != nil {
        t.Fatalf("ParseDNSZone() error = %v", err)
    }
    recs := z.GetRecords("host.roundtrip.test.", dns.TypeSSHFP)
    if len(recs) == 0 {
        t.Fatal("expected SSHFP records, got none")
    }
}
```

Repeat for NAPTR (`dns.TypeNAPTR`), SMIMEA (`dns.TypeSMIMEA`), LOC (`dns.TypeLOC`).

**Round-trip test shape** — import `bytes` in addition to `testing` and `github.com/miekg/dns`:
```go
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
    buf1, buf2 := make([]byte, dns.MaxMsgSize), make([]byte, dns.MaxMsgSize)
    off1, _ := dns.PackRR(orig[0], buf1, 0, nil, false)
    off2, _ := dns.PackRR(loaded[0], buf2, 0, nil, false)
    if !bytes.Equal(buf1[:off1], buf2[:off2]) {
        t.Errorf("wire mismatch after round-trip")
    }
}
```

---

### `internal/zone/parser_bind_test.go` — New BIND parse tests

**Analog:** `TestParseBIND_ARecords` pattern (lines 80+) — parse BIND file, call `GetRecords`, assert length:
```go
func TestParseBIND_ARecords(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
    if err != nil {
        t.Fatalf("ParseBIND() error = %v", err)
    }
    // ...
    aRecs := z.GetRecords("www.example.org.", dns.TypeA)
    if len(aRecs) != 2 {
        t.Errorf(...)
    }
}
```

**New tests** (one per type, using `example.org.bind` after fixture is extended):
```go
func TestParseBIND_SSHFP(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
    if err != nil {
        t.Fatalf("ParseBIND() error = %v", err)
    }
    recs := z.GetRecords("host.example.org.", dns.TypeSSHFP)
    if len(recs) == 0 {
        t.Fatal("expected SSHFP records, got none")
    }
}
```

Repeat for NAPTR, SMIMEA, LOC with appropriate owner names matching fixture data.

---

### `internal/zone/testdata/roundtrip_rrtype.dnszone` — New fixture (YAML)

**Analog:** `internal/zone/testdata/example.com.dnszone` — zone/soa/records structure

**Minimal fixture structure** (copy zone/soa header from example.com.dnszone, add one owner per new type):
```yaml
zone:
  name: roundtrip.test
  ttl: 300

soa:
  primary_ns: ns1.roundtrip.test
  contact: admin@roundtrip.test
  serial: auto
  refresh: 3600
  retry: 900
  expire: 604800
  negative_ttl: 300

records:
  "@":
    NS:
      - ns1.roundtrip.test

  ns1:
    A: 192.0.2.1

  host:
    SSHFP:
      - algorithm: 3
        fingerprint_type: 2
        fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    LOC:
      - "42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m"

  "*.sip._tcp":
    NAPTR:
      - order: 100
        preference: 10
        flags: "u"
        service: "E2U+sip"
        regexp: "!^.*$!sip:info@roundtrip.test!"
        replacement: "."

  "_smimecert._tcp.user":
    SMIMEA:
      - usage: 3
        selector: 1
        matching: 1
        data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

---

### `internal/zone/testdata/example.org.bind` — Modified fixture (BIND)

**Analog:** existing file — add BIND-syntax records for all four types at end of file:
```bind
; SSHFP record
host  IN  SSHFP  3 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

; NAPTR record
_sip._tcp  IN  NAPTR  100 10 "u" "E2U+sip" "!^.*$!sip:info@example.org!" .

; SMIMEA record
_smimecert._tcp.user  IN  SMIMEA  3 1 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

; LOC record
host  IN  LOC  42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m
```

---

## Shared Patterns

### int + float64 coercion for YAML integer fields
**Source:** `internal/zone/parser_dnszone.go` — `parseCAARecords` lines 707–711 and `parseTLSARecords` lines 750–763
**Apply to:** `parseSSHFPRecords` (algorithm, fingerprint_type), `parseNAPTRRecords` (order, preference), `parseSMIMEARecords` (usage, selector, matching)
```go
if flags, ok := caaMap["flags"].(int); ok {
    caa.Flags = flags
} else if flagsF, ok := caaMap["flags"].(float64); ok {
    caa.Flags = int(flagsF)
}
```

### dns.NewRR() error propagation
**Source:** `internal/zone/parser_dnszone.go` — `parseTLSARecords` lines 777–784
**Apply to:** all four new parse functions
```go
rr, err := dns.NewRR(s)
if err != nil {
    return fmt.Errorf("failed to parse TLSA string: %w", err)
}
if rr != nil {
    zone.AddRecord(rr)
}
```

### dns.Fqdn() for domain name fields
**Source:** `internal/zone/parser_dnszone.go` — `parseSVCBHTTPRecords` line 841, `parseNSRecords` line 558
**Apply to:** `parseNAPTRRecords` replacement field
```go
dns.Fqdn(rec.Target)  // ensures trailing dot
```

### Two-loop sync requirement
**Source:** `internal/zone/parser_dnszone.go` — `ParseDNSZone` loop (lines 252–297), `parseIncludeFile` loop (lines 984–1026)
**Apply to:** every new parse function call must appear in **both** loops
**Pitfall:** omitting from `parseIncludeFile` silently drops records in include files with no error

### Test package declaration
**Source:** `internal/zone/parser_dnszone_test.go` line 1, `parser_bind_test.go` line 1
**Apply to:** all new test functions (same package, white-box tests)
```go
package zone
```

---

## No Analog Found

None — all five files have exact or role-match analogs within `internal/zone/`.

---

## Metadata

**Analog search scope:** `internal/zone/` (parser_dnszone.go, parser_dnszone_test.go, parser_bind_test.go, testdata/)
**Files scanned:** 6
**Pattern extraction date:** 2026-05-21
