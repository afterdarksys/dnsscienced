# Phase 10: Record Type Expansion - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-21
**Phase:** 10-record-type-expansion
**Areas discussed:** LOC YAML format, SSHFP field representation, SMIMEA vs TLSA YAML key, NAPTR structured vs string, Test data strategy, NAPTR empty regexp handling, Float-vs-int YAML coercion

---

## LOC YAML format

| Option | Description | Selected |
|--------|-------------|----------|
| String passthrough | `LOC: ["42 21 43.952 N 71 06 18.910 W 12m 30m 10m 2m"]` — operators copy-paste BIND text format directly | ✓ |
| Partial structure | Split lat/lon as strings but keep altitude + optional precision inline | |
| Full structured map | lat_deg, lat_min, lat_sec, lat_dir, lon_deg, lon_min, lon_sec, lon_dir, altitude, size, horiz_precision, vert_precision | |

**User's choice:** String passthrough
**Notes:** LOC is rare enough that the dense RFC string format is acceptable.

### LOC multi-value format

| Option | Description | Selected |
|--------|-------------|----------|
| List only | `LOC: ["..."]` — consistent with TLSA, HTTPS, SVCB | ✓ |
| String or list | Accept both scalar string and list, like A records | |

**User's choice:** List only — consistent with existing multi-value types.

---

## SSHFP field representation

| Option | Description | Selected |
|--------|-------------|----------|
| Integer codes | `algorithm: 3, fingerprint_type: 2` — matches RFC 4255 and ssh-keygen -r output | ✓ |
| Friendly string names | `algorithm: ecdsa, fingerprint_type: sha256` — requires translation table | |

**User's choice:** Integer codes
**Notes:** Operators copy-paste from `ssh-keygen -r` which outputs codes directly. Consistent with TLSA integer fields.

---

## SMIMEA vs TLSA YAML key

| Option | Description | Selected |
|--------|-------------|----------|
| Separate SMIMEA: key | Add SMIMEA: to RecordSection reusing TLSARecord struct | ✓ |
| Generic TYPE53 fallback | Use existing generic TYPE53: "3 1 1 abc123..." syntax only | |

**User's choice:** Separate SMIMEA: key
**Notes:** Explicit and clear for operators even though the wire format is identical to TLSA.

---

## NAPTR structured vs string

| Option | Description | Selected |
|--------|-------------|----------|
| Structured map | Named fields: order, preference, flags, service, regexp, replacement | ✓ |
| String passthrough | `"100 10 \"u\" \"E2U+sip\" \"!^.*$!...!\" ."` — all quoting on operator | |

**User's choice:** Structured map — consistent with TLSA/SRV pattern.

---

## NAPTR empty regexp handling

| Option | Description | Selected |
|--------|-------------|----------|
| Default to empty string | Absent regexp: field → empty string; no need to write `regexp: ""` for replacement-mode | ✓ |
| Require explicit empty string | Absent regexp: → parse error | |

**User's choice:** Default to empty string — matches BIND zone file convention.

---

## Test data strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Wire equality only | Parse → compile → decompile → verify packed wire bytes match | ✓ |
| Field-level assertions too | Also assert parsed struct fields (e.g., sshfp.Algorithm == 3) | |

**User's choice:** Wire equality only — validates correctness end-to-end without coupling to miekg internals.

| Option | Description | Selected |
|--------|-------------|----------|
| Real-world examples | Actual ECDSA SSHFP fingerprints, real NAPTR patterns | ✓ |
| Minimal synthetic | Simpler values like fingerprint: "aabbcc" | |

**User's choice:** Real-world examples — tests read like documentation.

---

## Float-vs-int YAML coercion

| Option | Description | Selected |
|--------|-------------|----------|
| Lenient — accept int and float64 | Consistent with existing TLSA/HTTPS/CAA parsers | ✓ |
| Strict — int only | Cleaner but diverges from existing pattern | |

**User's choice:** Lenient — match existing parsers exactly.

---

## Claude's Discretion

- Whether SMIMEA parsing is a new `parseSMIMEARecords()` or `parseTLSARecords()` extended with a type argument
- File organization — new file vs extending `parser_dnszone.go`
- Whether SSHFP builds via `dns.NewRR()` string or direct `dns.SSHFP` struct
- Order of plans/waves

## Deferred Ideas

None — discussion stayed within phase scope.
