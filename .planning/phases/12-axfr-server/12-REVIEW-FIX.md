---
phase: 12-axfr-server
fixed_at: 2026-05-23T00:00:00Z
review_path: .planning/phases/12-axfr-server/12-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 12: Code Review Fix Report

**Fixed at:** 2026-05-23
**Source review:** .planning/phases/12-axfr-server/12-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5
- Fixed: 5
- Skipped: 0

## Fixed Issues

### CR-01: SOA duplicated in AXFR middle section for all file-loaded zones

**Files modified:** `internal/server/axfr.go`
**Commit:** 2693a8f
**Applied fix:** Replaced the `rrs := z.GetAllRecords()` direct-use with a filter loop that excludes records with `Rrtype == dns.TypeSOA` before batching middle envelopes. Updated the comment to explain why the filter is required (all three production loaders call `AddRecord` for the SOA, storing it in both `z.SOA` and `z.Records`).

---

### WR-01: Nil SOA dereference panic in transfer path

**Files modified:** `internal/server/axfr.go`
**Commit:** 47ca086
**Applied fix:** Added a nil guard for `z.SOA` before the streaming section (step 7 in the guard chain). Returns `SERVFAIL` if the SOA pointer is nil, preventing a panic inside `dns.Transfer.Out` when a zone loaded via `LoadZone` (which bypasses `Validate()`) has a missing or unparseable SOA.

---

### WR-02: Goroutine leak when Transfer.Out channel is blocked

**Files modified:** `internal/server/axfr.go`
**Commit:** 28ff0b9
**Applied fix:** Introduced a buffered `errCh chan error` (cap 1) so `tr.Out` can exit without blocking. Added a `send()` helper that selects on both `ch <- env` and `<-errCh`, returning false when `tr.Out` exits early. The send loop (opening SOA, middle batches, closing SOA) now calls `close(ch); wg.Wait(); return` immediately on early exit, preventing the goroutine from blocking forever on an unbuffered channel with no reader.

---

### CR-02: IXFR requests bypass TSIG and ACL guards

**Files modified:** `internal/server/server.go`
**Commit:** 40f29c0
**Applied fix:** Extended the AXFR dispatch condition in `handleDNS` to also match `dns.TypeIXFR`, routing both types through `handleAXFR` and its full guard chain (TSIG presence, TSIG validity, zone lookup, ACL). Updated the comment to explain that `handleAXFR` produces a full zone response which satisfies IXFR fallback behaviour (RFC 1995).

---

### WR-03: `NewSourceACL([]string{})` returns allow-all — inconsistent with AXFR empty-list semantics

**Files modified:** `internal/server/server.go`, `internal/dsync/source_acl.go`
**Commit:** 842f220
**Applied fix:** Added explicit documentation at both sites. In `source_acl.go`, the `NewSourceACL` godoc now warns callers that empty input returns `allowAll=true` and that deny-all-on-empty callers must intercept before calling. In `server.go`, the AXFR ACL builder comment now explains the semantic mismatch and why the empty-list interception is intentional. The existing correct workaround (storing `nil` for empty CIDR lists) is unchanged.

---

## Skipped Issues

None — all findings were fixed.

---

_Fixed: 2026-05-23_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
