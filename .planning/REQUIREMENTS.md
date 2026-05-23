# Requirements: dnsscienced — DNS Protocol Completeness

**Defined:** 2026-05-21
**Core Value:** Operators can express any DNS firewall policy in Starlark and have it enforced at query time with zero restarts.

## v1.3 Requirements

Requirements for the DNS Protocol Completeness milestone. Each maps to roadmap phases.

### Record Type Expansion (RRTYPE)

- [ ] **RRTYPE-01**: Server parses and serves HTTPS/SVCB records (RFC 9460) from BIND and .dnszone zone files
- [ ] **RRTYPE-02**: Server parses and serves TLSA/DANE records (RFC 6698) from BIND and .dnszone zone files
- [ ] **RRTYPE-03**: Server parses and serves SSHFP records (RFC 4255) from BIND and .dnszone zone files
- [ ] **RRTYPE-04**: Server parses and serves NAPTR records (RFC 3403) from BIND and .dnszone zone files
- [ ] **RRTYPE-05**: Server parses and serves SMIMEA records (RFC 8162) from BIND and .dnszone zone files
- [ ] **RRTYPE-06**: Server parses and serves LOC records (RFC 1876) from BIND and .dnszone zone files
- [ ] **RRTYPE-07**: All new record types survive compile/decompile round-trip in .dzc binary format
- [ ] **RRTYPE-08**: Authoritative server returns correct NOERROR + empty answer (not NOTIMP) for in-zone queries of new types with no matching records

### Resolver Behaviors (RESOLVE)

- [x] **RESOLVE-01**: Recursive resolver sends minimized QNAME in outgoing queries (RFC 7816 / RFC 9156) — only the necessary labels sent to each nameserver level
- [ ] **RESOLVE-02**: Resolver synthesizes NXDOMAIN / NOERROR responses from cached NSEC/NSEC3 records without upstream queries (RFC 8198 aggressive caching)
- [x] **RESOLVE-03**: Resolver serves stale cached records with extended TTL (up to configurable stale-max-ttl) when upstream nameservers are unreachable (RFC 8767 proper serve-stale)

### Zone Transfer — AXFR Server (XFER)

- [ ] **XFER-01**: Server responds to AXFR requests with complete zone contents in correct wire format (RFC 5936) — SOA + all RRs + SOA
- [ ] **XFER-02**: AXFR transfers are TSIG-authenticated using the existing KeyRing; unsigned AXFR requests are rejected when the zone requires authentication
- [ ] **XFER-03**: AXFR access is controlled by a per-zone `allow_transfer` ACL (CIDR list); requests from unlisted sources receive REFUSED

### Dynamic DNS Updates (DYNUP)

- [ ] **DYNUP-01**: Server accepts DNS UPDATE opcode (RFC 2136) and applies add/delete operations to the in-memory zone
- [ ] **DYNUP-02**: Dynamic updates are TSIG-authenticated; unauthenticated UPDATE requests are rejected
- [ ] **DYNUP-03**: Update access is controlled by a per-zone `allow_update` ACL (CIDR list); requests from unlisted sources receive REFUSED
- [ ] **DYNUP-04**: Successful updates are immediately visible to subsequent queries without zone reload

## v2 Requirements

Deferred to future milestone. Tracked but not in current roadmap.

### Zone Transfer
- **XFER-04**: IXFR server — serve incremental zone transfers (RFC 1995)
- **XFER-05**: Catalog zones (RFC 9432) — zone provisioning via special catalog zone

### DNSSEC
- **DNSSEC-01**: Online DNSSEC signing — sign zone records on-the-fly at query time
- **DNSSEC-02**: EdDSA (Ed25519/Ed448) algorithm support for DNSSEC (RFC 8080)
- **DNSSEC-03**: Automated key rollover (ZSK/KSK) with RFC 5011 trust anchor management
- **DNSSEC-04**: Quantum-resistant signing (SPHINCS+ hybrid)

### Modern Transports
- **TRANS-01**: DNS over QUIC (DoQ) full server implementation (RFC 9250)
- **TRANS-02**: Oblivious DoH (ODoH) implementation (RFC 9230)
- **TRANS-03**: DNS Stateful Operations (DSO) full implementation (RFC 8490)

## Out of Scope

| Feature | Reason |
|---------|--------|
| DNSSEC signing | Requires HSM/key management infrastructure; separate milestone; validator exists but signing is a distinct subsystem |
| IXFR server | Requires per-zone change journal (complex state); AXFR covers the transfer use case for v1.3 |
| Catalog zones | Zone management paradigm change; separate milestone after AXFR stabilizes |
| DoQ / ODoH / DSO | Config stubs exist; full implementation is transport-layer work scoped separately |
| DNAME records | Complex substitution logic; low operator demand for v1.3 |
| EDNS Client Subnet (RFC 7871) | Privacy-sensitive; requires GeoIP integration not yet planned |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| RRTYPE-01 | Phase 10 | Pending |
| RRTYPE-02 | Phase 10 | Pending |
| RRTYPE-03 | Phase 10 | Pending |
| RRTYPE-04 | Phase 10 | Pending |
| RRTYPE-05 | Phase 10 | Pending |
| RRTYPE-06 | Phase 10 | Pending |
| RRTYPE-07 | Phase 10 | Pending |
| RRTYPE-08 | Phase 10 | Pending |
| RESOLVE-01 | Phase 11 | Complete |
| RESOLVE-02 | Phase 11 | Pending |
| RESOLVE-03 | Phase 11 | Complete |
| XFER-01 | Phase 12 | Pending |
| XFER-02 | Phase 12 | Pending |
| XFER-03 | Phase 12 | Pending |
| DYNUP-01 | Phase 13 | Pending |
| DYNUP-02 | Phase 13 | Pending |
| DYNUP-03 | Phase 13 | Pending |
| DYNUP-04 | Phase 13 | Pending |

**Coverage:**
- v1.3 requirements: 18 total
- Mapped to phases: 18 (roadmap complete)
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-21*
*Last updated: 2026-05-21 — traceability filled after roadmap creation*
