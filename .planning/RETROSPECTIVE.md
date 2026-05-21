# Retrospective

## Milestone: v1.2 — Fully Operational

**Shipped:** 2026-05-18
**Phases:** 4 (Phases 6–9) | **Plans:** 23

### What Was Built

- All AdminService RPCs registered and fully implemented — zone/record CRUD, metrics, logging, RRL controls
- TSIG (RFC 2845/8945) key management — KeyRing with runtime Add/Remove; secrets never returned or logged
- Admin gRPC hardened — mandatory mTLS + API key AND-auth, structured audit logging, ConnRegistry StatsHandler, atomic SIGHUP reload
- RFC 9859 DSYNC full implementation — record type 66 codec, inbound/outbound NOTIFY, per-source-IP rate limiting, `_dsync` discovery, source ACL, webhook delivery, Prometheus metrics, Admin RPC
- Four v1.2 audit gaps closed — logger/RRL accessors, ConnRegistry wiring, ListZones, stream interceptor key ID propagated

### What Worked

- **Wave-based plan structure** — phases were split into waves (dependencies explicit), no blocking surprises
- **TDD stub-first pattern (Phase 7)** — 12 stub test functions created in Plan 00; concrete assertions in Plan 06; each intermediate plan could run `go test -run TestXxx` with Skip guards
- **Setter pattern for post-construction wiring** (SetWebhook, SetMetrics, SetConnRegistry) — kept constructor signatures stable across plans; no phase-creep
- **Shared-map pattern for TSIG** — assigning KeyRing.secrets to dns.Server.TsigSecret gave live mutation without restart; elegant and zero-overhead

### What Was Inefficient

- **ConnRegistry chicken-and-egg** (Phase 7, Plan 04): registry returned from `grpcserver.New()` but needed to be passed back in for RegisterAll — required Plan 05 to restructure to 5-return signature. A 2-return `(srv, deps)` struct would have avoided this.
- **Phase 9 existence** — four production gaps that should have been caught before v1.2 audit were discovered post-execution. Better gate: run audit mid-milestone, not only at the end.
- **fmt.Sscanf truncation (Plan 02)**: extractBearer() needed to replace Sscanf because it truncates at spaces. A code review before merge would have caught this; it was found during auth testing.

### Patterns Established

- `keyIDStream` wrapper: embed gRPC `ServerStream`, override `Context()` to inject enriched context — reusable pattern for any stream interceptor that needs to add values to stream context
- Unconditional zero-key-ring initialization: `if s.tsigKeyRing == nil { s.tsigKeyRing = tsig.NewKeyRing() }` — a zero-key ring is always safe; nil rings cause panics at auth time
- NOTIFY opcode dispatch before pool/defensive: insert at top of `handleDNS`, before `pool.GetMessage` — any control-plane opcode (NOTIFY, UPDATE) must short-circuit query processing
- Setter injection pattern: `SetWebhook`, `SetMetrics`, `SetConnRegistry` keep constructors stable; post-construction injection makes wiring testable and prevents constructor parameter explosion

### Key Lessons

1. **Audit mid-milestone, not just at the end** — v1.2 gap closure (Phase 9) existed entirely because the audit was run after all phases were "done". A mid-milestone audit at Phase 8 completion would have surfaced the gaps while context was still warm.
2. **Return structs over multi-return tuples for complex constructors** — `grpcserver.New()` grew from 4 to 5 return values over Phases 7–9. A `*ServerResult` struct would have been easier to extend.
3. **Shared-map patterns are elegant but require documentation** — the TSIG shared-map is non-obvious. Document at the assignment site, not just in SUMMARY.md.
4. **fmt.Sscanf is a trap for token parsing** — it stops at whitespace. Use `strings.TrimPrefix` + explicit split instead whenever parsing structured string tokens.

### Cost Observations

- Sessions: ~4 major sessions across 4 phases
- Model: Sonnet 4.x throughout
- Notable: Phase 8 (DSYNC) was the most complex — 7 plans, full RFC implementation — but the wave structure kept each plan focused to ~200 LOC

---

## Cross-Milestone Trends

| Milestone | Phases | Plans | Timeline | Test Count | LOC Added |
|-----------|--------|-------|----------|------------|-----------|
| v1.0 MVP | 1 | 1 | 1 day | 19 | ~5,000 |
| v1.1 Completion | 4 | 10 | 1 day | 44 | ~14,589 |
| v1.2 Fully Operational | 4 | 23 | ~9 days | 80+ | ~25,176 |

**Trend: Plan density increasing** — v1.2 had 23 plans vs v1.1's 10 for the same number of phases. Each plan is doing less but the overall scope is more complex. This is correct — smaller plans = safer execution.

**Trend: Gap-closure phases** — v1.2 needed a Phase 9 to close audit gaps. Consider adding a "gap pass" plan at the end of each milestone rather than a full phase.
