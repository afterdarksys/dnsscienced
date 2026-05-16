# Phase 7: Admin Auth Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-16
**Phase:** 07-admin-auth-hardening
**Areas discussed:** mTLS vs API keys, Audit log format, Key reload trigger, Connection tracking

---

## mTLS vs API Keys

| Option | Description | Selected |
|--------|-------------|----------|
| Both required | Client must present valid cert AND valid API key | ✓ |
| Either/or | mTLS OR key — whichever the client has | |
| mTLS optional, key required | Key always required; cert adds identity to audit log | |

**User's choice:** Both required
**Notes:** None

---

| Option | Description | Selected |
|--------|-------------|----------|
| Fail closed (Recommended) | Missing TLSClientCAs = server refuses to start | ✓ |
| Warn and allow | Log warning but start without client cert enforcement | |

**User's choice:** Fail closed
**Notes:** None

---

## Audit Log Format

| Option | Description | Selected |
|--------|-------------|----------|
| Structured log via logger | Write to existing logging.Logger as JSON lines | ✓ |
| Dedicated audit file | Separate configurable file path | |
| Both | Logger + dedicated file | |

**User's choice:** Structured log via logger
**Notes:** None

---

| Option | Description | Selected |
|--------|-------------|----------|
| Named keys in config | Config uses {id, secret} structs; audit logs key id | ✓ |
| First 8 chars of key hash | No config change; opaque ID | |
| Key index (key-1, key-2) | Position in list | |

**User's choice:** Named keys in config
**Notes:** Config schema changes from `api_keys: ["secret"]` to `api_keys: [{id: "...", secret: "..."}]`

---

## Key Reload Trigger

| Option | Description | Selected |
|--------|-------------|----------|
| SIGHUP only | OS signal triggers reload; no new RPC | |
| ReloadAPIKeys RPC only | gRPC RPC for programmatic reload | |
| Both SIGHUP and RPC | Maximum flexibility | |

**User's choice:** SIGHUP only
**Notes:** None

---

| Option | Description | Selected |
|--------|-------------|----------|
| API keys only | Simpler; TLS cert rotation needs restart anyway | |
| Full config reload | Reload everything — keys, TLS paths, all config | ✓ |

**User's choice:** Full config reload
**Notes:** Connection draining not in scope — existing connections continue on old TLS session

---

## Connection Tracking

| Option | Description | Selected |
|--------|-------------|----------|
| IP + key ID + cert CN | Full operator identity | ✓ |
| IP + TLS cert CN only | No key info | |
| IP only | Minimal tracking | |

**User's choice:** IP + key ID + cert CN
**Notes:** None

---

| Option | Description | Selected |
|--------|-------------|----------|
| Not retained — live only | Registry holds only active connections | ✓ |
| Retain for 5 minutes | Closed connections kept with timestamp | |
| Configurable retention | Config option for TTL | |

**User's choice:** Live connections only
**Notes:** No memory leak risk

---

## Claude's Discretion

None — all areas had explicit user decisions.

## Deferred Ideas

None — discussion stayed within phase scope.
