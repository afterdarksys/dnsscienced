---
phase: 10-record-type-expansion
fixed_at: 2026-05-21T00:00:00Z
review_path: .planning/phases/10-record-type-expansion/10-REVIEW.md
iteration: 1
findings_in_scope: 9
fixed: 9
skipped: 0
status: all_fixed
---

# Phase 10: Code Review Fix Report

**Fixed at:** 2026-05-21T00:00:00Z
**Source review:** .planning/phases/10-record-type-expansion/10-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 9 (4 Critical, 5 Warning)
- Fixed: 9
- Skipped: 0

## Fixed Issues

### CR-01: Directory Traversal Guard Has Path-Prefix Spoofing Flaw

**Files modified:** `internal/zone/parser_dnszone.go`, `internal/zone/include_test.go`
**Commit:** f478955, 19f3855
**Applied fix:** Rejected absolute include paths before they enter the join/clean pipeline (`filepath.IsAbs` check added). Also updated the `if !filepath.IsAbs` branch removal — absolute paths now always return an error. The path-prefix guard was also tightened to use `cleanInc != baseDir &&` prefix to handle the edge case where the include resolves to exactly baseDir. The existing `include_test.go` was also updated (commit 19f3855) because it relied on absolute temp paths for includes, which the new guard correctly rejects; the test now creates both files in a shared temp directory and uses a relative include path.

---

### CR-02: SOA Serial Silently Becomes 0 on Malformed Input

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** a15d0e6, 19f3855
**Applied fix:** Added error checking on `fmt.Sscanf` return values in the non-auto serial path. Empty string `""` is now treated the same as `"auto"` (generates a date-based serial) rather than failing, preserving compatibility with zone files that omit the serial field inside `soa:`. Any other non-numeric value now returns an error.

---

### CR-03: NAPTR RR String Injection via User-Controlled Fields

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 707ebb3
**Applied fix:** Replaced the `fmt.Sprintf` + `dns.NewRR` pattern with direct construction of a `*dns.NAPTR` struct. User-controlled fields (flags, service, regexp, replacement) are now assigned as struct fields rather than interpolated into a format string, eliminating the newline injection vector entirely.

---

### CR-04: AAAA Validation Accepts IPv4 Addresses

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 80ad4c6
**Applied fix:** Changed the guard from `ip.To16() == nil` to `ip.To4() != nil`. `ip.To4()` returns non-nil for any IPv4 address (including IPv4-mapped), so this correctly rejects IPv4 inputs. IPv6-only addresses pass the check since `To4()` returns nil for them. This mirrors the A record parser which uses `ip.To4() == nil` to reject IPv6.

---

### WR-01: Non-String List Items Silently Dropped in SSHFP/NAPTR/SMIMEA/LOC Parsers

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 18086f7
**Applied fix:** Updated all four parsers to return an error on unexpected item types rather than silently skipping them. SSHFP, NAPTR, and SMIMEA now use `if !ok { return fmt.Errorf(...) }` after the map type assertion. LOC now uses the same pattern for string type assertion. Error messages include the item index and the actual type received.

---

### WR-02: MX and SRV Numeric Fields Missing float64 Fallback

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 2fcefc9
**Applied fix:** Added `float64` fallback for MX `priority`, and for SRV `priority`, `weight`, and `port` fields, matching the pattern already used in the CAA, TLSA, SSHFP, and NAPTR parsers added in this phase.

---

### WR-03: Legacy Format SOA Produces Zero-Valued Timing Fields Without Error

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 4299858
**Applied fix:** Added zero-value checks for `Refresh`, `Retry`, and `Expire` after `parseTime` returns. A zero value causes an immediate error. `Minttl` (negative TTL) is allowed to be zero as it is valid DNS practice to set the negative cache TTL to 0.

---

### WR-04: `parseTime` Silently Truncates Values Exceeding uint32

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** ea27e1d
**Applied fix:** Added `math.MaxUint32` overflow check in both the duration path and the raw-number path of `parseTime`. Values exceeding 4,294,967,295 now return an error instead of silently truncating. Added `"math"` import.

---

### WR-05: `applyTemplates` is a Silent No-Op Stub

**Files modified:** `internal/zone/parser_dnszone.go`
**Commit:** 0692852
**Applied fix:** `applyTemplates` now returns `fmt.Errorf("template application (apply:) is not yet implemented")` when `len(zf.Apply) > 0`. Zone files that do not use `apply:` are unaffected (the function returns nil as before). This prevents silent data loss when a zone file contains `apply:` directives.

---

_Fixed: 2026-05-21T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
