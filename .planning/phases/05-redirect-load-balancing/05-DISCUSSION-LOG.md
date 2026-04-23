# Phase 5: Redirect Load Balancing - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 05-redirect-load-balancing
**Areas discussed:** Starlark API

---

## Starlark API

### Q1: Which areas to discuss?

| Option | Description | Selected |
|--------|-------------|----------|
| Starlark API | Does firewall.redirect(server="...") keep per-call server arg or go pool-only? | ✓ |
| Config shape | Global pool vs per-rule pools | |
| Backwards compat | RedirectServer survival/deprecation | |
| Zero/fail behavior | What happens on empty pool or timeout | |

**User's choice:** Starlark API only (other areas resolved through follow-up questions)

---

### Q2: What should the redirect() signature become?

| Option | Description | Selected |
|--------|-------------|----------|
| Pool-only, no server arg | firewall.redirect() — always picks from configured pool | ✓ |
| Keep server arg, pool is fallback | firewall.redirect(server="...") still works; omit for pool | |

**User's choice:** Pool-only — `server=` arg removed entirely.
**Notes:** User confirmed the config.yaml preview showing `firewall.redirect.upstreams: [...]`.

---

### Q3: If someone passes server= anyway (old script)?

| Option | Description | Selected |
|--------|-------------|----------|
| Hard error | Starlark evaluation returns an error | ✓ |
| Silently ignore | Accept kwarg but discard it | |

**User's choice:** Hard error — fail loudly so operators know to update scripts.

---

### Q4: RuleConfig.RedirectServer — what happens to it?

| Option | Description | Selected |
|--------|-------------|----------|
| Remove it, pool-only | Delete field; consistent with Starlark change | |
| Keep as override | redirect_server on a rule overrides global pool for that rule | ✓ |

**User's choice:** Keep as per-rule override. Static rules can redirect to a specific server, bypassing the pool.

---

### Q5: Config shape for global pool

| Option | Description | Selected |
|--------|-------------|----------|
| firewall.redirect.upstreams | New nested RedirectConfig block | ✓ |
| firewall.redirect_upstreams | Flat top-level key | |

**User's choice:** Nested block (`firewall.redirect.upstreams`). Confirmed via config preview.

---

### Q6: Failure behavior

| Option | Description | Selected |
|--------|-------------|----------|
| SERVFAIL | Standard DNS error response | ✓ |
| Try next upstream | Retry on failure (v2 behavior) | |

**User's choice:** SERVFAIL — consistent with existing single-target behavior. Retry-on-failure is REDIR-05/06 (v2).

---

## Claude's Discretion

- Exact struct name for new config type
- Whether UpstreamPool is a struct with method or standalone function
- Internal field name on Firewall
- Test helper naming

## Deferred Ideas

- REDIR-05: Weighted upstream selection (v2)
- REDIR-06: Health-check-based upstream removal (v2)
- Per-call named pool overrides in Starlark (not in v1 scope)
