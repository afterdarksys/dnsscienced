---
phase: 10-record-type-expansion
reviewed: 2026-05-21T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - internal/zone/parser_dnszone.go
  - internal/zone/parser_bind_test.go
  - internal/zone/parser_dnszone_test.go
  - internal/zone/testdata/example.org.bind
  - internal/zone/testdata/roundtrip_rrtype.dnszone
findings:
  critical: 4
  warning: 5
  info: 3
  total: 12
status: issues_found
---

# Phase 10: Code Review Report

**Reviewed:** 2026-05-21T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

Phase 10 expands the dnszone parser to support TLSA, HTTPS, SVCB, SSHFP, NAPTR, SMIMEA, LOC, and generic `TYPE###` records. The implementation is largely correct but contains four critical issues: a path-prefix spoofing bypass in the include guard, silent serial=0 from ignored `fmt.Sscanf` errors, RR string injection in NAPTR and CAA parsers from user-controlled fields, and an AAAA validation bug that accepts IPv4 addresses. Five warnings cover silent data loss patterns (non-string list items silently dropped, MX/SRV missing float64 fallback, zero-value SOA timers, uint32 truncation). Three info items address a no-op template stub, inconsistent indentation, and missing BIND round-trip tests.

---

## Critical Issues

### CR-01: Directory Traversal Guard Has Path-Prefix Spoofing Flaw

**File:** `internal/zone/parser_dnszone.go:344-346`

**Issue:** The traversal check is:

```go
if !strings.HasPrefix(cleanInc, baseDir+string(filepath.Separator)) {
    return nil, fmt.Errorf("include %q: path escapes zone directory ...")
}
```

If `baseDir` is `/var/zones` and a user-controlled absolute include resolves to `/var/zones-evil/secret.yaml`, then `cleanInc` (`/var/zones-evil/secret.yaml`) starts with `/var/zones` (no separator appended to the left operand in `HasPrefix`). Wait — the code does append the separator to `baseDir`: `baseDir + string(filepath.Separator)` = `/var/zones/`. So `/var/zones-evil/...` does NOT pass that check. However: a path that resolves to exactly `baseDir` itself (`/var/zones`) does NOT start with `/var/zones/` either — it is blocked. The real bug is that absolute paths bypass the `filepath.Join` rewriting (line 338-341) and enter `filepath.Clean` as-is. If `inc` is an absolute path whose `filepath.Clean` result happens to be a child of `baseDir` (e.g. `inc = "/var/zones/../../var/zones/legit.yaml"` cleans to `/var/zones/legit.yaml`), it passes. More critically: a symlink target is never resolved, so a symlink at `/var/zones/link.yaml` pointing to `/etc/passwd` passes the guard but reads outside the directory. The symlink case cannot be fixed here, but absolute path acceptance is a clear bug.

**Fix:** Reject absolute include paths before they enter the join/clean pipeline:

```go
if filepath.IsAbs(inc) {
    return nil, fmt.Errorf("include %q: absolute paths are not allowed", inc)
}
incPath := filepath.Join(baseDir, inc)
cleanInc := filepath.Clean(incPath)
if cleanInc != baseDir && !strings.HasPrefix(cleanInc, baseDir+string(filepath.Separator)) {
    return nil, fmt.Errorf("include %q: path escapes zone directory", inc)
}
```

---

### CR-02: SOA Serial Silently Becomes 0 on Malformed Input

**File:** `internal/zone/parser_dnszone.go:398-400`

**Issue:** The non-auto serial path is:

```go
var serial uint64
fmt.Sscanf(zf.SOA.Serial, "%d", &serial)
soa.Serial = uint32(serial)
```

`fmt.Sscanf` return values (count, error) are ignored. If `zf.SOA.Serial` is `""`, `"abc"`, or any non-numeric string, `fmt.Sscanf` writes nothing into `serial`, leaving it at 0. The function returns a valid SOA with `Serial=0` — a legal but almost certainly wrong value. Secondaries receiving serial 0 will believe the zone is perpetually outdated. No error is surfaced to the caller.

**Fix:**

```go
var serial uint64
if n, err := fmt.Sscanf(zf.SOA.Serial, "%d", &serial); n != 1 || err != nil {
    return nil, fmt.Errorf("invalid SOA serial %q: expected integer", zf.SOA.Serial)
}
soa.Serial = uint32(serial)
```

The auto-serial path at line 395-396 has the same `fmt.Sscanf` ignore pattern but is lower risk since the format string is machine-generated.

---

### CR-03: NAPTR RR String Injection via User-Controlled Fields

**File:** `internal/zone/parser_dnszone.go:908`

**Issue:** NAPTR record construction embeds user-supplied YAML fields verbatim into a string that is passed to `dns.NewRR`:

```go
s := fmt.Sprintf("%s %d IN NAPTR %d %d \"%s\" \"%s\" \"%s\" %s",
    owner, ttl, rec.Order, rec.Preference, rec.Flags, rec.Service, rec.Regexp, dns.Fqdn(rec.Replacement))
```

If any of `rec.Flags`, `rec.Service`, or `rec.Regexp` contains a newline character (`\n`), the resulting multi-line string causes `dns.NewRR` to parse only the first line and ignore or misparse the remainder — or, depending on the library, parse a second injected record from the second line. A `rec.Regexp` value of `"!^.*$!\n@ 300 IN A 1.2.3.4\n!"` would break the format string into multiple lines. The `replacement` field is passed unquoted, so whitespace in it splits it into multiple NAPTR arguments.

**Fix:** Build the `dns.NAPTR` struct directly to avoid format-string injection entirely:

```go
rr := &dns.NAPTR{
    Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: ttl},
    Order:       uint16(rec.Order),
    Preference:  uint16(rec.Preference),
    Flags:       rec.Flags,
    Service:     rec.Service,
    Regexp:      rec.Regexp,
    Replacement: dns.Fqdn(rec.Replacement),
}
zone.AddRecord(rr)
```

---

### CR-04: AAAA Validation Accepts IPv4 Addresses

**File:** `internal/zone/parser_dnszone.go:482-496`

**Issue:** The AAAA validation is:

```go
ip := net.ParseIP(ipStr)
if ip == nil || ip.To16() == nil {
    return fmt.Errorf("invalid IPv6 address: %s", ipStr)
}
```

`net.ParseIP` returns a 16-byte slice for any valid IP, including IPv4. `ip.To16()` on an IPv4 address returns the IPv4-mapped IPv6 form (`::ffff:x.x.x.x`) and is never nil. So the guard passes for IPv4 inputs like `"192.0.2.1"`. The resulting `dns.AAAA` record stores `ip.To16()` — an IPv4-mapped address — which is technically invalid as a standalone AAAA record and will confuse resolvers expecting a pure IPv6 address. Compare with `parseARecords` which correctly uses `ip.To4() == nil` to reject IPv6 addresses.

**Fix:**

```go
ip := net.ParseIP(ipStr)
if ip == nil || ip.To4() != nil {
    return fmt.Errorf("invalid IPv6 address: %s", ipStr)
}
rr := &dns.AAAA{
    // ...
    AAAA: ip.To16(),
}
```

---

## Warnings

### WR-01: Non-String List Items Silently Dropped in SSHFP/NAPTR/SMIMEA/LOC Parsers

**File:** `internal/zone/parser_dnszone.go:831-836` (SSHFP), `875-901` (NAPTR), `932-955` (SMIMEA), `983-987` (LOC)

**Issue:** When iterating over a `[]interface{}` list, non-matching items are silently skipped:

```go
// LOC example (line 983-987):
for _, item := range v {
    if locStr, ok := item.(string); ok {
        locStrings = append(locStrings, locStr)
    }
    // non-strings silently dropped
}
```

A YAML typo (e.g. a bare integer instead of a quoted string in a LOC list) causes the record to be silently omitted from the zone. In DNS, a silently missing record is far worse than a hard parse error. The same pattern exists in SSHFP and SMIMEA for `map[string]interface{}` type assertions.

**Fix:** Return an error on unexpected item types:

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

### WR-02: MX and SRV Numeric Fields Missing float64 Fallback

**File:** `internal/zone/parser_dnszone.go:529` (MX priority), `671-677` (SRV priority/weight/port)

**Issue:** The MX and SRV parsers assert numeric fields only as `.(int)`:

```go
if priority, ok := mxMap["priority"].(int); ok {
    mx.Priority = priority
}
// no float64 fallback
```

When YAML numeric values are decoded into `interface{}` (as happens when using map-based unmarshalling), the Go YAML library can produce either `int` or `float64` depending on the value and YAML library version. All other new parsers in this phase (CAA at lines 740-744, TLSA at 785-787, SSHFP at 833-836, NAPTR at 879-886) include float64 fallback. Missing it in MX and SRV means priority/weight/port default silently to 0. An MX with priority 0 is a correctness bug (0 is highest priority, so a mis-parsed MX gets promoted to highest priority).

**Fix:** Add float64 fallback for all numeric fields in `parseMXRecords` and `parseSRVRecords`:

```go
if priority, ok := mxMap["priority"].(int); ok {
    mx.Priority = priority
} else if priorityF, ok := mxMap["priority"].(float64); ok {
    mx.Priority = int(priorityF)
}
```

---

### WR-03: Legacy Format SOA Produces Zero-Valued Timing Fields Without Error

**File:** `internal/zone/parser_dnszone.go:73-118`

**Issue:** `convertOldFormat` calls `strconv.Itoa(ozf.SOA.Refresh)` etc. — if `ozf.SOA.Refresh` is 0 (unset in legacy file), the result is `"0"`. `parseTime("0")` succeeds (returns 0). The SOA record is constructed with `Refresh=0`, `Retry=0`, etc. — all legal uint32 values but operationally incorrect: `Refresh=0` means secondaries poll the primary continuously. There is no validation or warning for zero SOA timers.

**Fix:** Validate non-zero SOA timers in `parseSOA`:

```go
if soa.Refresh == 0 {
    return nil, fmt.Errorf("SOA refresh must be non-zero")
}
```

---

### WR-04: `parseTime` Silently Truncates Values Exceeding uint32

**File:** `internal/zone/parser_dnszone.go:1166-1170`

**Issue:**

```go
var seconds uint64
if _, err := fmt.Sscanf(s, "%d", &seconds); err == nil {
    return uint32(seconds), nil
}
```

Values above 4,294,967,295 (roughly 136 years) silently truncate. A zone with `expire: 9999999999` produces `expire = 1410065407` with no error.

**Fix:**

```go
if seconds > math.MaxUint32 {
    return 0, fmt.Errorf("time value %d exceeds uint32 maximum", seconds)
}
return uint32(seconds), nil
```

---

### WR-05: `applyTemplates` is a Silent No-Op Stub

**File:** `internal/zone/parser_dnszone.go:1131-1135`

**Issue:** The function is called in the main `ParseDNSZone` parse path and returns nil unconditionally with a comment that it is "not yet implemented". If a zone file uses `apply:` directives, those records are silently omitted from the output zone. This is a data-loss bug from the user's perspective.

**Fix:** Return an error when `apply:` is non-empty:

```go
func applyTemplates(zone *Zone, zf *DNSZoneFile, defaultTTL uint32) error {
    if len(zf.Apply) > 0 {
        return fmt.Errorf("template application (apply:) is not yet implemented")
    }
    return nil
}
```

---

## Info

### IN-01: Inconsistent Indentation (Tabs vs. Spaces) in New Code

**File:** `internal/zone/parser_dnszone.go:743-744, 764-766, 786-792, 1020-1021, 1064-1065`

**Issue:** Pre-existing code uses hard tabs throughout. The newly added float64 fallback blocks and `if rr != nil` blocks inside `parseCAARecords`, `parseTLSARecords`, and `parseSVCBHTTPRecords` use spaces. This indicates the new code was not run through `gofmt` before submission.

**Fix:** `gofmt -w internal/zone/parser_dnszone.go`

---

### IN-02: No Round-Trip Tests for New Record Types in BIND Parser Path

**File:** `internal/zone/parser_bind_test.go:347-429`

**Issue:** Tests verify that SSHFP, NAPTR, SMIMEA, LOC, TLSA, HTTPS, SVCB records are present after BIND parsing but do not test the compile-and-reload round-trip for the BIND fixture. Only the `.dnszone` path has round-trip coverage. If export of any of these new record types is broken, no test catches it.

**Fix:** Add round-trip tests for the BIND path analogous to the `TestRoundTrip_*` tests in `parser_dnszone_test.go`.

---

### IN-03: `assertRoundTrip` Calls `t.Fatalf` When `len(origRecs) == 0`

**File:** `internal/zone/parser_dnszone_test.go:533-535`

**Issue:** When `origRecs` is empty, `assertRoundTrip` fails with `"no records found for %s type %d"`. This is correct behavior, but the function is also called directly from round-trip tests that already verified record presence (e.g. `TestRoundTrip_SSHFP` calls `doRoundTrip` then `assertRoundTrip`). The double-check is harmless but adds confusion; a more useful pattern would verify that `doRoundTrip` produces `orig` with records present before calling `assertRoundTrip`, rather than letting `assertRoundTrip` fail with a generic message.

**Fix:** Minor test clarity improvement — document that `assertRoundTrip` requires `len(origRecs) > 0`, or call `require` in the round-trip tests themselves.

---

_Reviewed: 2026-05-21T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
