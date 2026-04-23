---
phase: 02-grpc-admin
reviewed: 2026-04-23T00:00:00Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - api/grpc/proto/admin.proto
  - internal/firewalld/firewalld.go
  - internal/server/server.go
  - api/grpc/services/management.go
  - api/grpc/registry/register.go
  - cmd/dnsscienced/main.go
  - api/grpc/services/firewall.go
  - api/grpc/services/firewall_test.go
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-04-23
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

## Summary

Phase 2 adds `FirewallAdminService` (proto + Go) on top of the existing gRPC admin
infrastructure. The overall structure is sound: the nil-guard in the registry prevents
registration when the firewall is disabled, the `SrvAdapter` interface cleanly avoids
import cycles, and the four RPC handlers are thin and correct. Test coverage for the
new `FirewallService` is good for the happy and validation paths.

Three areas need attention before this ships:

1. **Critical** — `InjectScore` passes an arbitrary string directly into the
   `dynIPs` map without IP parsing. The `Score` lookup later calls
   `qctx.ClientIP.String()`, so an injected key that does not match the canonical
   form produced by `net.IP.String()` (e.g., `"1.2.3.4"` vs a mapped IPv6 form)
   will never match at query time — a silent correctness failure and a potential
   amplification vector if callers keep injecting the "same" IP in different formats.

2. **Warning** — The Starlark goroutine spawned in `runOne` has no hard-kill path:
   `thread.Cancel()` is advisory only, and the goroutine leaks until it finishes
   naturally. Under sustained load or with a hostile script this accumulates goroutines.

3. **Warning** — `compileZone` in `ManagementService` passes user-supplied zone
   content to the filesystem and then executes an external binary (`compileBin`) via
   `exec.CommandContext`. The `compileBin` path is derived from `os.Args[0]`, not
   validated against a whitelist, which widens the attack surface if the daemon is
   ever started from a writable directory.

---

## Critical Issues

### CR-01: `InjectScore` stores raw IP string without canonical parsing

**File:** `api/grpc/services/firewall.go:73-77`

**Issue:** `InjectScore` passes the caller-supplied IP string directly to
`ti.AddIPScore(t.Ip, ...)` which stores it verbatim in `dynIPs` (threat_intel.go:158).
At query time, `Score()` looks up `qctx.ClientIP.String()` (threat_intel.go:83), which
always returns the canonical form produced by `net.IP.String()` (e.g. IPv4-mapped IPv6
addresses are normalised to `"::ffff:1.2.3.4"` for IPv6-facing paths). If the injected
key does not match that canonical form the score is silently never applied. Additionally,
no IP format validation is performed, so any arbitrary string (including `:invalid`) is
accepted and stored.

**Fix:**
```go
// In firewall.go InjectScore, before calling AddIPScore:
case *pb.FirewallInjectScoreRequest_Ip:
    if t.Ip == "" {
        return nil, status.Error(codes.InvalidArgument, "ip is required")
    }
    parsed := net.ParseIP(t.Ip)
    if parsed == nil {
        return nil, status.Errorf(codes.InvalidArgument, "invalid IP address: %q", t.Ip)
    }
    ti.AddIPScore(parsed.String(), int(req.Score)) // canonical form
```

The same canonical-form guarantee should be enforced in `AddIPScore` itself so other
callers are also protected:
```go
// In threat_intel.go AddIPScore:
func (ti *ThreatIntel) AddIPScore(ip string, score int) {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return // or return error if signature is changed
    }
    canonical := parsed.String()
    ti.dynMu.Lock()
    ti.dynIPs[canonical] = score
    ti.dynMu.Unlock()
}
```

---

## Warnings

### WR-01: Goroutine leak in Starlark `runOne` — `thread.Cancel` is advisory

**File:** `internal/firewalld/starlark.go:152-170`

**Issue:** `runOne` spawns a goroutine to call `starlark.Call`. On timeout it calls
`thread.Cancel("timeout")` and returns, but the goroutine continues executing until the
Starlark thread checks for cancellation. A pure-Go tight loop in a Starlark script
(unlikely but possible via recursion depth or long string ops) will never yield and the
goroutine will run indefinitely. Under sustained gRPC load targeting `LoadScript` +
adversarial bodies this can accumulate goroutines without bound.

**Fix:** Add a hard-stop mechanism. The simplest approach is to set a `MaxSteps` limit
on the thread before calling `Init`/`Call`, which Starlark will honour unconditionally:
```go
thread := &starlark.Thread{Name: s.id}
thread.SetMaxExecutionSteps(1_000_000) // reject scripts that loop too long
```
This provides a deterministic bound independent of `context.WithTimeout`.

### WR-02: `LoadScript` compile error mapped to `InvalidArgument` for all failures

**File:** `api/grpc/services/firewall.go:47-49`

**Issue:** Any error from `fw.LoadSource` is returned as `codes.InvalidArgument`. Some
failures (e.g. an internal engine state corruption, or a Starlark VM init error) are
server-side, not caller-side. Callers that auto-retry on `InvalidArgument` will loop
forever on a persistent server fault. The distinction matters for client retry logic.

**Fix:**
```go
if err := s.fw.LoadSource(req.ScriptId, req.Body); err != nil {
    // Starlark parse/compile errors are caller errors; runtime/engine errors
    // (e.g. starlark.EvalError from Init) are server errors.
    // Use a type assertion or string prefix check to distinguish:
    code := codes.InvalidArgument
    var evalErr *starlark.EvalError
    if errors.As(err, &evalErr) {
        code = codes.Internal // init-time EvalError is a server/script state issue
    }
    return nil, status.Errorf(code, "compile script: %v", err)
}
```
At minimum, document the current behaviour in the RPC comment so clients know not to
retry on `InvalidArgument` from this endpoint.

### WR-03: `compileBin` path derived from `os.Args[0]` — no validation

**File:** `cmd/dnsscienced/main.go:206`

**Issue:**
```go
compileBin := filepath.Join(filepath.Dir(os.Args[0]), "dnsscienced-compile")
```
`os.Args[0]` can be any string on some platforms (symlinks, proc remounting). If the
daemon is started from a world-writable directory (e.g. `/tmp`), an attacker who can
write a binary named `dnsscienced-compile` there can get it executed with daemon
privileges whenever `CreateZone`/`UpdateRecord` is called via gRPC.

**Fix:** Accept the compiler path from the config file rather than deriving it from
`os.Args[0]`, and validate it is an absolute path that exists before starting the gRPC
server:
```go
// In config.yaml admin section, add:
//   compile_bin: /usr/local/bin/dnsscienced-compile
compileBin := loadedCfg.Admin.CompileBin
if compileBin == "" {
    compileBin = filepath.Join(filepath.Dir(os.Args[0]), "dnsscienced-compile")
}
if !filepath.IsAbs(compileBin) {
    fmt.Fprintf(os.Stderr, "compile_bin must be an absolute path: %s\n", compileBin)
    os.Exit(1)
}
if _, err := os.Stat(compileBin); err != nil {
    fmt.Fprintf(os.Stderr, "compile_bin not found: %v\n", err)
    os.Exit(1)
}
```

### WR-04: `removeRecord` silently succeeds on non-existent record; `DeleteRecord` returns success

**File:** `api/grpc/services/management.go:450`

**Issue:** `removeRecord` is a no-op when the record does not exist in the zone. Both
`DeleteRecord` and `UpdateRecord` (old-record removal step) call it without checking the
return. A client that sends a `DeleteRecord` for a record that was already deleted (or
never existed) gets back `success: true` and a full `serializeCompileReload` cycle, and
the zone is re-serialised and recompiled for no reason. More importantly, the client
receives a false confirmation of deletion.

**Fix:** Return a boolean from `removeRecord` and surface a `NotFound` error for
`DeleteRecord`:
```go
// removeRecord returns true if a record was actually removed.
func removeRecord(z *zone.Zone, owner string, rrtype uint16, content string) bool {
    // ... existing logic ...
    // return true only when len(before) != len(filtered)
}

// In DeleteRecord:
if removed := removeRecord(z, owner, rrtype, content); !removed {
    return nil, status.Errorf(codes.NotFound, "record %s not found in zone %s", req.RecordId, req.ZoneId)
}
```

---

## Info

### IN-01: `FirewallStatsRequest` is an empty message — should be `google.protobuf.Empty`

**File:** `api/grpc/proto/admin.proto:358`

**Issue:** `FirewallStatsRequest` is declared as an empty message. The existing proto
already imports `google/protobuf/empty.proto` and uses `google.protobuf.Empty` for
equivalent parameterless RPCs (`GetCacheStats`, `GetServerStatus`, etc.). Using a
custom empty message breaks API consistency and wastes a message number.

**Fix:** Change the RPC signature to use `google.protobuf.Empty`:
```protobuf
rpc FirewallStats(google.protobuf.Empty) returns (FirewallStatsResponse);
```
This is a breaking change to the generated Go API; do it before the first external
release.

### IN-02: Test `TestFirewallService_Stats` assertion adds no real coverage

**File:** `api/grpc/services/firewall_test.go:31-35`

**Issue:** Asserting `GreaterOrEqual(counter, uint64(0))` on a freshly created firewall
is trivially true (unsigned integers cannot be negative). The test does not exercise
counter increment paths (no queries are fed through the firewall). It verifies the
method is callable but not that it returns correct values.

**Fix:** Feed at least one query through the firewall before calling `FirewallStats` and
assert the counters are the expected non-zero values:
```go
fw.Check(&dns.Msg{Question: []dns.Question{{Name: "evil.example.", Qtype: dns.TypeA}}}, net.ParseIP("1.2.3.4"))
resp, err := svc.FirewallStats(...)
assert.Equal(t, uint64(1), resp.TotalQueries)
```

### IN-03: `management.go` imports `os/exec` — unused in test builds; `compileBin` missing from `NoopSrvAdapter` test coverage

**File:** `api/grpc/registry/register.go:28`

**Issue:** `NoopSrvAdapter.GetFirewall()` returns `nil`, so `FirewallAdminService` is
never registered when `NoopSrvAdapter` is used. There is no test that exercises the
conditional registration path with a real `*firewalld.Firewall`. If `GetFirewall()`
were accidentally changed to return a non-nil value from `NoopSrvAdapter`, the service
would be registered but backed by a nil firewall, panicking on the first RPC call.

**Fix:** Add a registry-level test that creates a `*firewalld.Firewall`, wraps it in
a minimal `SrvIface`, calls `RegisterAll`, and asserts `FirewallAdminService` is
reachable in the service info map. This is also the natural place to add an integration
smoke test for the `FirewallStats` RPC.

---

_Reviewed: 2026-04-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
