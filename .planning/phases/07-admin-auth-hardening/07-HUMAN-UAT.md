---
status: partial
phase: 07-admin-auth-hardening
source: [07-VERIFICATION.md]
started: 2026-05-16T00:00:00Z
updated: 2026-05-21T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. ListConnections returns real data in production

expected: When a gRPC client connects to the live admin server, ListConnections should return at least 1 connection with real IP, port, and connected_at timestamp.
result: blocked
blocked_by: other
reason: "we have no way to test"

**Context:** In production, `connRegistry` is passed as `nil` to `RegisterAll` (chicken-and-egg constraint documented in 07-05-SUMMARY). The registry returned by `grpcserver.New()` is discarded with `_ = connReg`. `Service.ListConnections` nil-guards and returns an empty slice when `connRegistry` is nil. Tests pass because they wire the registry directly.

**To test:** Start the live daemon with a full TLS config, connect with a valid client cert + Bearer token, call `ListConnections`, and verify at least 1 connection appears with a real IP and `connected_at` timestamp.

**To fix (if needed):** Add a `SetConnRegistry(reg)` setter to the admin service and call it after `grpcserver.New()` returns, or restructure the `RegisterAll` closure to accept a pointer-to-pointer that is populated post-construction. This is also flagged as CR-05 in `07-REVIEW.md`.

## Summary

total: 1
passed: 0
issues: 0
pending: 0
skipped: 0
blocked: 1

## Gaps
