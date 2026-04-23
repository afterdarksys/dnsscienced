---
status: partial
phase: 04-edns0-customerid
source: [04-VERIFICATION.md]
started: 2026-04-23
updated: 2026-04-23
---

## Current Test

[awaiting human testing]

## Tests

### 1. Starlark Script Branching on `q["customer_id"]` (ROADMAP SC#3)

expected: Load a Starlark script that calls `firewall.nxdomain()` when `q["customer_id"] == "blocked-customer"`. Send one query with EDNS0 option code 65000 carrying "blocked-customer", one without. VerdictNXDomain for the first, VerdictAllow for the second.

result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
