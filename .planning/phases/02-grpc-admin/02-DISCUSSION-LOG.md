# Phase 2: gRPC Admin - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 02-grpc-admin
**Areas discussed:** Proto placement, LoadScript input, Service implementation location, gRPC server wiring

---

## Proto placement

| Option | Description | Selected |
|--------|-------------|----------|
| New FirewallAdminService in admin.proto | Second service block in the same file. Clean separation from DNS/cache RPCs, single codegen run, no new file. | ✓ |
| Extend existing AdminService | Add all 4 RPCs to the existing AdminService. Simpler but AdminService is already 20+ RPCs. | |
| New firewall.proto file | Maximum isolation — dedicated file, separate generated stubs. Adds complexity to codegen/imports. | |

**User's choice:** New FirewallAdminService in admin.proto

---

## LoadScript input

| Option | Description | Selected |
|--------|-------------|----------|
| Script body as string | Request carries the Starlark source directly. Client doesn't need filesystem access to the server. | ✓ |
| File path on server | Matches the HTTP API: request contains a path that the server reads from disk. | |
| Both — body OR path | Most flexible. Adds slightly more handler logic. | |

**User's choice:** Script body as string

| Option | Description | Selected |
|--------|-------------|----------|
| Caller supplies script_id | Request has a required script_id string. Same ID passed to RemoveScript. | ✓ |
| Auto-generate from content hash | Server generates an ID from a hash of the script body. Response returns the assigned ID. | |

**User's choice:** Caller supplies script_id

---

## Service implementation location

| Option | Description | Selected |
|--------|-------------|----------|
| api/grpc/services/firewall.go | Follow the existing codebase pattern — management.go, dns.go, cache.go are all here. | ✓ |
| internal/admin/ (new package) | Create the package the ROADMAP described. More isolated but inconsistent with existing pattern. | |

**User's choice:** api/grpc/services/firewall.go

---

## gRPC server wiring

| Option | Description | Selected |
|--------|-------------|----------|
| Same existing admin gRPC server/port | Register alongside existing services in registry.RegisterAll(). One server, one port. | ✓ |
| Separate gRPC server on a new port | Start a second grpc.Server for firewall-only RPCs. Requires new config key. | |

**User's choice:** Same existing admin gRPC server/port

| Option | Description | Selected |
|--------|-------------|----------|
| Add GetFirewall() to SrvAdapter interface | Extend the SrvAdapter interface. Clean — no new params to RegisterAll. | ✓ |
| Pass *firewalld.Firewall as a new param to RegisterAll | RegisterAll(s, srv, zonesDir, compileBin, fw). Direct but grows the function signature. | |

**User's choice:** Add GetFirewall() to SrvAdapter interface

---

## Claude's Discretion

- InjectScore field structure (combined domain+IP vs separate messages)
- Error response patterns
- How LoadScript writes body to StarlarkEngine internally

## Deferred Ideas

None.
