# Phase 4: EDNS0 CustomerID — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 04-edns0-customerid
**Areas discussed:** EDNS0 Option Code, Extraction Location, Payload Format & Validation, Error Handling

---

## EDNS0 Option Code

| Option | Description | Selected |
|--------|-------------|----------|
| 65000 | First private-use code, memorable, clearly internal. RFC 6891 §6.1.3.1 comment. | ✓ |
| Pick a specific number | User has a specific code in mind already in use | |
| Claude's discretion | Any valid private-use code is fine | |

**User's choice:** 65000 (Recommended)
**Notes:** Standard first-pick for private-use range.

---

## Extraction Location

| Option | Description | Selected |
|--------|-------------|----------|
| Inside Check() | No signature change; all firewall extraction in one place | ✓ |
| In server.go before Check() | Explicit separation; server handles protocol | |
| New CheckWithContext() method | Backward-compat API; adds indirection | |

**User's choice:** Inside Check() (Recommended)
**Notes:** Cleaner encapsulation; server.go not modified.

---

## Payload Format & Validation

| Option | Description | Selected |
|--------|-------------|----------|
| Raw bytes as UTF-8 string, 64-byte cap | Simple, no encoding scheme | ✓ |
| Raw bytes, no length cap | Simplest code, unbounded payload | |
| Printable ASCII only, validated | Strict but complex | |

**User's choice:** Raw bytes as UTF-8 string (Recommended), max 64 bytes
**Notes:** 64-byte cap chosen to accommodate UUID-length identifiers.

---

## Error Handling

| Option | Description | Selected |
|--------|-------------|----------|
| Silent empty string | No logging at all | |
| Log + empty string | Debug log for oversized; silent for absent | ✓ |
| Log warn on oversized only | Warn-level for client bugs | |

**User's choice:** Log + empty string
**Notes:** User specifically distinguished use cases — different signal levels for different causes (absent = normal, oversized = likely client misconfiguration).

---

## Claude's Discretion

- Exact constant name and file placement within the firewalld package
- Whether to use a helper function or inline the extraction in Check()

## Deferred Ideas

None.
