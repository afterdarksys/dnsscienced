---
phase: 10-record-type-expansion
reviewed: 2026-05-21T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - internal/zone/parser_dnszone.go
  - internal/zone/parser_dnszone_test.go
  - internal/zone/parser_bind_test.go
  - internal/zone/testdata/example.org.bind
  - internal/zone/testdata/roundtrip_rrtype.dnszone
findings:
  critical: 3
  warning: 5
  info: 3
  total: 11
status: issues_found
---

# Phase 10: Code Review Report

**Reviewed:** 2026-05-21
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

This phase adds SSHFP, NAPTR, SMIMEA, and LOC record type support to the dnszone parser,
plus generic TYPE### fallback parsing. The new record parsers follow the established pattern
(list-of-maps for structured records, string-per-item for LOC). Core logic is sound but several
correctness bugs and security gaps were found in the new code.

---

## Critical Issues

### CR-01: Directory traversal guard fails for the base directory itself

**File:** `internal/zone/parser_dnszone.go:345`

**Issue:** The traversal check uses `strings.HasPrefix(cleanInc, baseDir+string(filepath.Separator))`.
This check requires a trailing separator, which means a path that resolves to exactly `baseDir`
(no separator) passes the `HasPrefix` test as `false` and is correctly blocked — but it also
means any absolute path supplied directly for `inc` bypasses the relative-path branch on
line 338 (`!filepath.IsAbs(inc)`) and is handed to `filepath.Clean` without ever being rewritten
relative to `baseDir`. An absolute path like `/etc/passwd` will be cleaned to itself, which does
NOT start with `baseDir + sep`, so it will be blocked — that part is fine. However, if the caller
passes an absolute path whose prefix happens to be `baseDir` (e.g. `baseDir` is `/var/zones` and
the include is `/var/zones-evil/secret.yaml`), the `HasPrefix` guard passes and the file is read.
This is a path-prefix spoofing attack.

**Fix:** Reject all absolute include paths outright before the `filepath.Join` call, and ensure
the comparison appends the separator to `cleanInc` as well:

```go
if filepath.IsAbs(inc) {
    return nil, fmt.Errorf("include %q: absolute paths are not allowed", inc)
}
incPath := filepath.Join(baseDir, inc)
cleanInc := filepath.Clean(incPath)
// Both sides must be normalized with separator to prevent prefix spoofing
if cleanInc != baseDir && !strings.HasPrefix(cleanInc, baseDir+string(filepath.Separator)) {
    return nil, fmt.Errorf("include %q: path escapes zone directory", inc)
}
```

---

### CR-02: SOA serial "auto" silently produces serial 0 when `fmt.Sscanf` fails

**File:** `internal/zone/parser_dnszone.go:393-400`

**Issue:** The auto-serial path uses `fmt.Sscanf(today+"00", "%d", &soa.Serial)` but ignores
both the return values. `time.Now().Format("20060102")` produces an 8-digit string; appending
`"00"` makes a 10-digit integer (e.g. `2026052100 = 0x78D04A04`). The maximum value of
`uint32` is `4294967295` (`0xFFFFFFFF`), so dates up to 2147483647 (year 2147) overflow cleanly
into `uint32` — but `fmt.Sscanf` writes into `soa.Serial` which is typed `uint32`. The Go
`fmt.Sscanf` verb `%d` reads into the pointer target's type; for a `uint32` target it reads an
unsigned 32-bit integer. The specific current concern: if `fmt.Sscanf` returns an error (it will
not for the date format, but any future refactor that changes the format string or target could
silently leave `soa.Serial` at 0). More concretely, the non-auto branch also uses
`fmt.Sscanf(zf.SOA.Serial, "%d", &serial)` with an ignored error return, meaning a malformed
serial string (e.g. `""`, `"abc"`) silently produces serial 0 — a valid but incorrect serial
that causes serving stale data to resolvers.

**Fix:** Check the `fmt.Sscanf` return values (both non-auto and auto paths):

```go
// Non-auto serial
n, err := fmt.Sscanf(zf.SOA.Serial, "%d", &serial)
if n != 1 || err != nil {
    return nil, fmt.Errorf("invalid SOA serial %q: %w", zf.SOA.Serial, err)
}
soa.Serial = uint32(serial)
```

For the auto path, prefer `strconv.ParseUint` for clarity:

```go
today := time.Now().Format("20060102")
serialStr := today + "00"
sv, err := strconv.ParseUint(serialStr, 10, 32)
if err != nil {
    return nil, fmt.Errorf("auto serial overflow: %w", err)
}
soa.Serial = uint32(sv)
```

---

### CR-03: NAPTR Regexp field is user-controlled and injected verbatim into a DNS RR string

**File:** `internal/zone/parser_dnszone.go:908`

**Issue:** The NAPTR record string is constructed as:

```go
s := fmt.Sprintf("%s %d IN NAPTR %d %d \"%s\" \"%s\" \"%s\" %s",
    owner, ttl, rec.Order, rec.Preference, rec.Flags, rec.Service, rec.Regexp, dns.Fqdn(rec.Replacement))
```

The `rec.Regexp` field comes directly from user-supplied YAML and is placed inside a `"..."` pair
in the RR string. If `rec.Regexp` contains a literal `"` character, the resulting string will have
an unbalanced quote and `dns.NewRR` will fail with a parse error — but that is recoverable.
More dangerously, `rec.Regexp` may also contain a newline (`\n`), which would break the single-line
RR format and cause `dns.NewRR` to parse a completely different record type from the injected
second line. The same issue applies to `rec.Flags` and `rec.Service`, and analogously to the
`parseCAARecords` value field (`caa.Value` at line 759).

**Fix:** Sanitize or escape all user-supplied string fields before embedding in the RR string.
At minimum, reject values containing `"` or `\n`:

```go
for _, field := range []string{rec.Flags, rec.Service, rec.Regexp} {
    if strings.ContainsAny(field, "\"\n\r") {
        return fmt.Errorf("NAPTR field contains invalid character")
    }
}
```

Alternatively, build the `dns.NAPTR` struct directly instead of going through `dns.NewRR` with a
manually formatted string, avoiding injection entirely.

---

## Warnings

### WR-01: LOC parser silently drops non-string items in the list

**File:** `internal/zone/parser_dnszone.go:983-986`

**Issue:** In `parseLOCRecords`, when the YAML value is `[]interface{}`, non-string items are
silently ignored:

```go
for _, item := range v {
    if locStr, ok := item.(string); ok {
        locStrings = append(locStrings, locStr)
    }
    // else: silently dropped
}
```

The same pattern exists in `parseSSHFPRecords` (line 831), `parseNAPTRRecords` (line 875), and
`parseSMIMEARecords` (line 932) for map-valued items. This means a YAML typo (e.g. a numeric
LOC value instead of a quoted string) causes the record to be silently omitted from the zone
rather than surfacing an error. In a DNS context silent omission is worse than a hard error.

**Fix:** Return an error when an item in the list is not the expected type:

```go
for i, item := range v {
    locStr, ok := item.(string)
    if !ok {
        return fmt.Errorf("LOC record item %d: expected string, got %T", i, item)
    }
    locStrings = append(locStrings, locStr)
}
```

---

### WR-02: `parseSOA` ignores `parseTime` errors for an empty string

**File:** `internal/zone/parser_dnszone.go:404-416`

**Issue:** If any SOA timing field (Refresh, Retry, Expire, NegativeTTL) is empty in the YAML
(omitted key), `parseTime("")` is called. `parseDuration("")` calls `time.ParseDuration("")`
which returns an error, then the fallback `fmt.Sscanf("", "%d", ...)` also fails, so `parseTime`
returns `(0, error)`. The error propagates to `parseSOA` as a hard failure — which is correct.
However, the legacy conversion in `convertOldFormat` calls `strconv.Itoa(0)` for a zero
`OldSOASection.Refresh`, producing `"0"`. `parseTime("0")` returns `(0, nil)` because the
numeric fallback path succeeds for `"0"`. A zone with unset legacy SOA timers silently gets
`Refresh=0`, `Retry=0`, etc. — these are valid uint32 values but cause immediate re-querying
by secondaries and are almost certainly a data error.

**Fix:** In `parseSOA`, validate that timing values are non-zero after parsing:

```go
if soa.Refresh == 0 {
    return nil, fmt.Errorf("SOA refresh must be non-zero")
}
```

Or add a minimum value check. At minimum document that zero is accepted.

---

### WR-03: `parseTime` accepts large values that silently truncate to uint32

**File:** `internal/zone/parser_dnszone.go:1161-1171`

**Issue:** `parseTime` parses raw seconds via `fmt.Sscanf(s, "%d", &seconds)` where `seconds`
is `uint64`. It then returns `uint32(seconds)`. Values above `4294967295` (about 136 years)
silently truncate. A zone with `expire: 99999999999` would produce a truncated expire value
with no error or warning.

**Fix:** Add a range check before the conversion:

```go
if seconds > math.MaxUint32 {
    return 0, fmt.Errorf("time value %d exceeds maximum uint32", seconds)
}
return uint32(seconds), nil
```

---

### WR-04: `parseDuration` does not handle the `s` suffix (seconds)

**File:** `internal/zone/parser_dnszone.go:1141-1158`

**Issue:** `parseDuration` handles `d` (days) and `w` (weeks) explicitly, then falls through to
`time.ParseDuration`. The test at line 387 passes `"90S"` and expects it to work because `time.ParseDuration`
accepts `s`. But `parseDuration` calls `strings.ToLower` first, so `"90S"` becomes `"90s"` which
`time.ParseDuration` handles. This is fine. However, the function is documented as
"supports 1h, 30m, or raw seconds" but will fail for inputs like `"300"` (no suffix) passed
through `parseDuration` directly — the caller has to use `parseTime` for that. This is a
documentation gap that can cause subtle bugs if the functions are called incorrectly in future
additions.

**Fix:** Add a clear doc comment clarifying that `parseDuration` does NOT accept bare integers —
bare-integer second values must go through `parseTime`. Low risk for current callers but a
maintenance trap.

---

### WR-05: YAML fallback detection is logic-inverted; a valid new-format file that has a YAML error is silently retried as legacy

**File:** `internal/zone/parser_dnszone.go:236-243`

**Issue:** The format detection strategy is:

```go
if err := yaml.Unmarshal(data, &zf); err != nil {
    var ozf OldDNSZoneFile
    if err2 := yaml.Unmarshal(data, &ozf); err2 != nil {
        return nil, fmt.Errorf("parse YAML: %w", err)
    }
    zf = convertOldFormat(ozf)
}
```

`yaml.Unmarshal` into a struct never returns an error for missing keys; it only errors on
malformed YAML syntax. Since both `DNSZoneFile` and `OldDNSZoneFile` accept any valid YAML
document (all fields are optional), the `err != nil` branch is unreachable in practice for any
syntactically valid file, meaning both old and new formats are parsed by the first unmarshal
call. The problem: for a new-format file where `zone:` is a struct (map), unmarshalling into
`OldDNSZoneFile` (where `Zone` is a plain string) would silently produce an empty `Zone.Name`.
This path is never reached but could produce silent data loss if the detection strategy is
ever modified. The format detection approach is fragile.

**Fix:** Distinguish old from new format explicitly — e.g. by checking whether `zone:` is a
string or map type before full unmarshalling, or by using a `yaml.Node` intermediate parse.

---

## Info

### IN-01: `applyTemplates` is a no-op stub

**File:** `internal/zone/parser_dnszone.go:1131-1135`

**Issue:** The function is called in the hot path of `ParseDNSZone` but does nothing. Any
`apply:` section in a zone file is silently ignored. No error is returned, and there is no
log warning. A user who relies on templates will get a zone missing records with no indication
of why.

**Fix:** Either implement template application, or return an error when `zf.Apply` is non-empty:

```go
func applyTemplates(zone *Zone, zf *DNSZoneFile, defaultTTL uint32) error {
    if len(zf.Apply) > 0 {
        return fmt.Errorf("template application (apply:) is not yet implemented")
    }
    return nil
}
```

---

### IN-02: Inconsistent indentation (tabs vs. spaces) in new record parsers

**File:** `internal/zone/parser_dnszone.go:743-744, 765-766, 786-787, 791-792, 795-796, 1020-1021, 1064-1065`

**Issue:** The pre-existing code uses tabs throughout, but the new CAA, TLSA, and SVCB/HTTPS
parsers contain several lines indented with spaces (visible in lines 743-744 inside
`parseCAARecords`, and 1020 inside `parseSVCBHTTPRecords`). This is a minor style inconsistency
but gofmt will flag it, and it indicates the new code was not run through `gofmt` before
submission.

**Fix:** Run `gofmt -w internal/zone/parser_dnszone.go`.

---

### IN-03: No test coverage for SSHFP/NAPTR/SMIMEA/LOC in BIND parser path after round-trip

**File:** `internal/zone/parser_bind_test.go:347-393`

**Issue:** `TestParseBIND_SSHFP`, `TestParseBIND_NAPTR`, `TestParseBIND_SMIMEA`, and
`TestParseBIND_LOC` verify that records are present after BIND parsing, but there are no
corresponding round-trip tests for the BIND path (only the dnszone path has round-trip tests in
`parser_dnszone_test.go`). If BIND export of these record types is broken, no test will catch it.

**Fix:** Add round-trip tests analogous to `TestRoundTrip_SSHFP` etc. that start from the BIND
fixture:

```go
func TestBINDRoundTrip_SSHFP(t *testing.T) {
    cfg := DefaultConfig()
    z, err := ParseBIND("testdata/example.org.bind", "example.org.", cfg)
    // ... compile, reload, assertRoundTrip
}
```

---

_Reviewed: 2026-05-21_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
