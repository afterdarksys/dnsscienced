# Requirements: dnsscienced — dnsfirewalld Completion

**Defined:** 2026-04-23
**Core Value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.

## v1.1 Requirements

### gRPC Admin

- [ ] **GRPC-01**: Operator can call FirewallStats via gRPC and receive current counters
- [ ] **GRPC-02**: Operator can call LoadScript via gRPC to add or replace a Starlark script
- [ ] **GRPC-03**: Operator can call RemoveScript via gRPC to unload a named script
- [ ] **GRPC-04**: Operator can call InjectScore via gRPC to add a domain or IP threat score
- [ ] **GRPC-05**: gRPC admin RPCs are defined in admin.proto and implemented in internal/admin/

### Threat Feed

- [x] **FEED-01**: Operator can configure a threat feed URL in config.yaml
- [x] **FEED-02**: Server polls configured feed URL at a configurable interval and ingests domain/IP scores
- [x] **FEED-03**: Feed client calls AddDomainScore/AddIPScore on ThreatIntelEngine for each entry
- [x] **FEED-04**: Feed errors are logged and do not crash the server

### Customer Identity

- [ ] **CUST-01**: Server extracts CustomerID from EDNS0 option at query intake
- [ ] **CUST-02**: Extracted CustomerID is stored in QueryContext and visible to firewall policy
- [ ] **CUST-03**: Queries without a CustomerID EDNS0 option are handled gracefully (empty string)

### Redirect Load Balancing

- [x] **REDIR-01**: Operator can configure multiple upstream redirect targets in config.yaml
- [x] **REDIR-02**: Forwarder selects among configured targets using round-robin
- [ ] **REDIR-03**: Starlark redirect() call uses the load-balanced upstream pool
- [ ] **REDIR-04**: Static rule VerdictRedirect uses the same upstream pool

## v2 Requirements

### Future Enhancements

- **FEED-05**: Authenticated feed endpoints (API key / Bearer token)
- **FEED-06**: Multiple concurrent feed sources
- **REDIR-05**: Weighted upstream selection (prefer faster/healthier targets)
- **REDIR-06**: Health-check-based upstream removal
- **CUST-04**: Server-side CustomerID mapping table (IP → CustomerID fallback)

## Out of Scope

| Feature | Reason |
|---------|--------|
| CGO/nftables integration | Go-only enforcement is sufficient; nftables adds build complexity |
| Web UI for firewall management | Operator tool — CLI + gRPC is the right interface |
| ML-based threat scoring | Entropy heuristics cover the use case without the ops burden |
| OAuth/mTLS for feed endpoints | v1 — simple URL + interval is enough to validate the feature |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GRPC-01 | Phase 2 | Pending |
| GRPC-02 | Phase 2 | Pending |
| GRPC-03 | Phase 2 | Pending |
| GRPC-04 | Phase 2 | Pending |
| GRPC-05 | Phase 2 | Pending |
| FEED-01 | Phase 3 | Complete (03-01) |
| FEED-02 | Phase 3 | Complete (03-02) |
| FEED-03 | Phase 3 | Complete (03-02) |
| FEED-04 | Phase 3 | Complete (03-02) |
| CUST-01 | Phase 4 | Pending |
| CUST-02 | Phase 4 | Pending |
| CUST-03 | Phase 4 | Pending |
| REDIR-01 | Phase 5 | Complete (05-01) |
| REDIR-02 | Phase 5 | Complete (05-01) |
| REDIR-03 | Phase 5 | Pending |
| REDIR-04 | Phase 5 | Pending |

**Coverage:**
- v1.1 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-23*
*Last updated: 2026-04-23 — traceability corrected to Phase 2-5 numbering (v1.1 continues from v1.0 Phase 1)*
