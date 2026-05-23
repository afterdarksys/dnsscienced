# Phase 13: Dynamic DNS Updates - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-23
**Phase:** 13-dynamic-dns-updates
**Areas discussed:** Prerequisites (RFC 2136 §2), Delete operation variants, SOA serial management, Zone file persistence

---

## Prerequisites (RFC 2136 §2)

| Option | Description | Selected |
|--------|-------------|----------|
| Skip prerequisites | Return NOTIMP if Prerequisite section is non-empty | |
| Implement full prerequisites | Support all 5 RFC 2136 §2 types | ✓ |

**User's choice:** Implement full prerequisites (all 5 types)
**Notes:** User wants RFC compliance.

---

| Option | Description | Selected |
|--------|-------------|----------|
| NXRRSET (you decide) | Per-spec rcodes per RFC 2136 §3.2 | ✓ |
| REFUSED for all failures | Single rcode regardless of failure type | |

**User's choice:** Per-spec rcodes per RFC 2136 §3.2 — planner follows RFC exactly.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Atomic — evaluate all prereqs first, apply no updates on failure | RFC-conformant | ✓ |
| Sequential apply per RFC §3.4 | Apply one-by-one, return error on mid-failure | |

**User's choice:** Atomic — all prerequisites evaluated before any update is applied.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Enforce illegal update detection | Reject delete-SOA, delete-all-NS, CNAME violations | ✓ |
| Skip integrity checks | Apply update as-is | |

**User's choice:** Enforce illegal update detection → REFUSED.

---

| Option | Description | Selected |
|--------|-------------|----------|
| All-or-nothing atomic apply | Stage on Clone(), validate, swap on success | ✓ |
| Sequential apply per RFC §3.4 | In-place mutation with rollback | |

**User's choice:** Clone-and-swap atomicity model.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Per-zone mutex on Zone struct | Add updateMu sync.Mutex to zone.Zone | ✓ |
| Global mutex | One mutex for all zones | |
| You decide | Planner chooses mechanism | |

**User's choice:** Per-zone mutex added to zone.Zone struct.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Add mutex to Zone struct | updateMu lives with the data it protects | ✓ |
| Mutex map in UPDATE handler | Handler maintains map[string]*sync.Mutex | |

**User's choice:** Add `updateMu sync.Mutex` to zone.Zone.

---

## Delete Operation Variants

| Option | Description | Selected |
|--------|-------------|----------|
| All 3 delete variants | delete-all-rrsets-at-name, delete-rrset, delete-specific-RR | ✓ |
| delete-rrset + delete-specific-RR only | Skip the nuclear delete-all-at-name | |
| delete-specific-RR only | Simplest subset | |

**User's choice:** Implement all 3 RFC 2136 §2.5 delete variants.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Add DeleteRecord/DeleteRRSet/DeleteName to Zone | Zone-level methods, consistent with AddRecord() | ✓ |
| DELETE logic inline in handler | Handler directly mutates clone's Records map | |

**User's choice:** Add zone-level mutation methods for all 3 delete variants.

---

## SOA Serial Management

| Option | Description | Selected |
|--------|-------------|----------|
| Always auto-increment after every successful UPDATE | Uses existing IncrementSerial() | ✓ |
| Skip if client included SOA update | Client's serial takes precedence | |
| Always auto-increment; reject client SOA updates | Server always owns serial | |

**User's choice:** Always auto-increment using IncrementSerial(). SOA records in Update section are ignored.

---

## Zone File Persistence

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory only | No disk writes, matches requirements text | |
| Persist to zone file after each successful update | Updates survive restart | |
| Optional: configurable per-zone | PersistUpdates *bool in ZoneConfig | ✓ |

**User's choice:** Per-zone `PersistUpdates *bool` config field.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Default false — in-memory only unless opted in | Safe default | ✓ |
| Default true — persist unless opted out | Durable by default | |

**User's choice:** Default false (absent = in-memory only).

---

| Option | Description | Selected |
|--------|-------------|----------|
| YAML zone config format | Reuse existing ZoneConfig YAML format | ✓ |
| Standard zone file (RFC 1035 master format) | Separate from YAML config | |
| You decide | Planner chooses serialization | |

**User's choice:** YAML zone config format (matching existing config.go).

---

| Option | Description | Selected |
|--------|-------------|----------|
| Sync write on every successful UPDATE | Simple, immediate | |
| Debounced/async write | Reduces I/O under bursts | |
| You decide | Planner determines write strategy | ✓ |

**User's choice:** You decide — planner determines write strategy.

---

## Claude's Discretion

- Write strategy for `persist_updates: true` (sync vs. debounced async)
- How the handler maps zone name from UPDATE Zone section to server's loaded zone (linear scan vs. startup index map)
- miekg/dns API for TSIG presence detection (`r.IsTsig()` vs. inspecting `r.Extra`)
- Single NOERROR reply message encoding for UPDATE response

## Deferred Ideas

- NOTIFY-on-update to secondaries after dynamic update
- IXFR journal of dynamic changes (RFC 1995)
- DNSSEC re-signing after dynamic updates
- Per-zone TSIG key binding for UPDATE (restricting to a specific named key)
