---
phase: 07
slug: admin-auth-hardening
status: draft
nyquist_compliant: true
wave_0_complete: true  # Plan 07-00 creates stubs before Wave 1
created: 2026-05-16
---

# Phase 07 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go testing (stdlib) + testify |
| **Config file** | none — standard `go test ./...` |
| **Quick run command** | `go test ./api/grpc/server/... ./api/grpc/middleware/... -v -run TestAuth` |
| **Full suite command** | `go test ./... -timeout 60s` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./api/grpc/server/... ./api/grpc/middleware/... -timeout 30s`
- **After every plan wave:** Run `go test ./... -timeout 60s`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 07-01-01 | 01 | 1 | ADMIN-AUTH-01 | — | AdminConfig has TLSCertFile, TLSKeyFile, TLSClientCAs fields | unit | `go test ./internal/config/... -run TestAdminConfig` | ❌ W0 | ⬜ pending |
| 07-01-02 | 01 | 1 | ADMIN-AUTH-02 | — | atomicKeySet stores secretToID map; Lookup returns named id | unit | `go test ./api/grpc/server/... -run TestAtomicKeySet` | ❌ W0 | ⬜ pending |
| 07-02-01 | 02 | 2 | ADMIN-AUTH-01 | Spoofing | New() returns error when TLSCertFile empty | unit | `go test ./api/grpc/server/... -run TestNew_NoTLS` | ❌ W0 | ⬜ pending |
| 07-02-02 | 02 | 2 | ADMIN-AUTH-01 | Spoofing | New() returns error when APIKeys empty | unit | `go test ./api/grpc/server/... -run TestNew_NoAuthMechanism` | ❌ W0 | ⬜ pending |
| 07-02-03 | 02 | 2 | ADMIN-AUTH-03 | Spoofing | Valid Bearer token + valid cert → authorized (AND policy) | unit | `go test ./api/grpc/server/... -run TestAPIKey_Valid` | ❌ W0 | ⬜ pending |
| 07-02-04 | 02 | 2 | ADMIN-AUTH-04 | Spoofing | No Bearer token → Unauthenticated even with valid cert | unit | `go test ./api/grpc/server/... -run TestAPIKey_Missing` | ❌ W0 | ⬜ pending |
| 07-02-05 | 02 | 2 | ADMIN-AUTH-02 | Spoofing | No client cert → Unauthenticated even with valid key | unit | `go test ./api/grpc/server/... -run TestMTLS_NoCert` | ❌ W0 | ⬜ pending |
| 07-03-01 | 03 | 2 | ADMIN-AUDIT-01 | Info Disc. | Audit log has caller, method, code, latency_ms, remote_addr, timestamp | unit | `go test ./api/grpc/middleware/... -run TestAuditInterceptor` | ❌ W0 | ⬜ pending |
| 07-03-02 | 03 | 2 | ADMIN-AUDIT-01 | Info Disc. | Raw API key never logged; named id (not sha256) logged | unit | `go test ./api/grpc/middleware/... -run TestAuditInterceptor_NoKeyLeak` | ❌ W0 | ⬜ pending |
| 07-04-01 | 04 | 3 | ADMIN-CONN-01 | DoS | ConnRegistry tracks active connections; ListConnections returns count > 0 | integration | `go test ./internal/admin/... -run TestListConnections` | ❌ W0 | ⬜ pending |
| 07-04-02 | 04 | 3 | ADMIN-CONN-01 | DoS | ConnEnd removes connection from registry | unit | `go test ./api/grpc/server/... -run TestConnRegistry_RemoveOnEnd` | ❌ W0 | ⬜ pending |
| 07-05-01 | 05 | 4 | ADMIN-RELOAD-01 | — | SIGHUP atomically reloads api_keys + TLS config | unit | `go test ./api/grpc/server/... -run TestAtomicKeyReload` | ❌ W0 | ⬜ pending |
| 07-05-02 | 05 | 4 | ADMIN-RELOAD-01 | — | ConfigHolder.Reload fails if new config violates D-01 invariants | unit | `go test ./api/grpc/server/... -run TestConfigHolder_ReloadValidation` | ❌ W0 | ⬜ pending |
| 07-06-01 | 06 | 5 | All | All | Full test suite green: server_auth_test.go, audit_test.go, service_conn_test.go | integration | `go test ./... -timeout 60s` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `api/grpc/server/server_auth_test.go` — covers ADMIN-AUTH-01 through ADMIN-AUTH-04, ADMIN-RELOAD-01
- [ ] `api/grpc/middleware/audit_test.go` — covers ADMIN-AUDIT-01
- [ ] `internal/admin/service_conn_test.go` — covers ADMIN-CONN-01

*Plan 00 (Wave 0) creates stub test files with t.Skip() before Wave 1 runs. Plan 06 (Wave 5) replaces stubs with real assertions.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TLS handshake with real client cert | ADMIN-AUTH-02 | Requires real cert files and live gRPC connection | Run `grpcurl --cert client.crt --key client.key --cacert ca.crt localhost:9090 list` |
| SIGHUP with changed TLS CA path | ADMIN-RELOAD-01 | Requires live process + signal delivery | Start daemon, update config, send `kill -HUP <pid>`, verify new CA accepted |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
