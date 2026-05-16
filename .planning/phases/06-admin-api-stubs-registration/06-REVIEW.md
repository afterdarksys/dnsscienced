---
phase: 06-admin-api-stubs-registration
reviewed: 2026-05-16T00:00:00Z
depth: standard
files_reviewed: 17
files_reviewed_list:
  - api/grpc/proto/admin.proto
  - api/grpc/proto/pb/admin_grpc.pb.go
  - api/grpc/proto/pb/admin.pb.go
  - api/grpc/registry/register.go
  - api/grpc/services/management.go
  - cmd/dnsscienced/main.go
  - internal/admin/service.go
  - internal/config/config.go
  - internal/logging/logger_test.go
  - internal/logging/logger.go
  - internal/resolver/recursive.go
  - internal/rrl/limiter_admin_test.go
  - internal/rrl/limiter.go
  - internal/server/server_transport_test.go
  - internal/server/server.go
  - internal/tsig/tsig_test.go
  - internal/tsig/tsig.go
findings:
  critical: 7
  warning: 8
  info: 4
  total: 19
status: issues_found
---

# Phase 06: Code Review Report

**Reviewed:** 2026-05-16T00:00:00Z
**Depth:** standard
**Files Reviewed:** 17
**Status:** issues_found

## Summary

This phase introduces the AdminService gRPC stubs and registration, the TSIG key ring (`internal/tsig`), RRL admin methods, logger admin methods, and transport-level UDP/TCP counters on the DNS server. The implementation is broadly functional but contains several significant defects: two separate path traversal vulnerabilities in zone file operations, a nil-pointer panic path in cache operations, a race condition in the token-bucket refill logic, a TSIG secret exposure vector via the shared map reference, and multiple places where mutations to zone data are not persisted back to disk (leaving in-memory state diverging from disk). Additionally, the TSIG key ring API surface exposes the live mutable `secrets` map directly to callers, which is a data-safety and concurrency hazard.

---

## Critical Issues

### CR-01: Path traversal in `AdminService.CreateZone` via `zone_content` field

**File:** `internal/admin/service.go:147`
**Issue:** `CreateZone` writes arbitrary caller-supplied `req.ZoneContent` bytes directly to disk at a path derived from `req.ZoneName`. While `validateZoneName` rejects names containing `/` or `..`, a crafted `zone_content` payload could contain symlink content or other file data, but more importantly the `ZoneContent` field is never validated to be well-formed YAML or bounded in size. An authenticated caller can write an arbitrarily large file to `<zonesDir>/<zoneName>.dnszone`, which could exhaust disk space and cause a Denial of Service.

The more concrete vulnerability: `validateZoneName` only blocks `/` and `..` in the name itself, but the `zone_content` field is written verbatim. If the compiler binary (`compileBin`) interprets the content in a way that allows injection (e.g., embedded shell metacharacters processed by a shell-invoked compiler), this becomes a command injection surface. The `compileZone` call at line 152 passes `inputPath` (controlled only by `domain` which is validated) to an external binary, but the binary reads the file content which is fully attacker-controlled.
**Fix:** Validate and size-cap `ZoneContent` before writing. At minimum: reject if `len(req.ZoneContent) > MaxZoneSize` (suggest 10 MB). Pre-parse the YAML to verify it is syntactically valid zone data before writing to disk. Do not shell-invoke the compiler — pass it via `exec.Command` (already done), but be aware the compiler processes attacker data.

```go
const maxZoneContentBytes = 10 * 1024 * 1024 // 10 MB

if len(req.ZoneContent) == 0 {
    return nil, status.Error(codes.InvalidArgument, "zone_content is required")
}
if len(req.ZoneContent) > maxZoneContentBytes {
    return nil, status.Error(codes.InvalidArgument, "zone_content exceeds maximum size")
}
// Pre-parse to validate YAML structure before writing to disk:
if _, err := zone.ParseYAMLContent([]byte(req.ZoneContent)); err != nil {
    return nil, status.Errorf(codes.InvalidArgument, "invalid zone content: %v", err)
}
```

---

### CR-02: Path traversal in `ManagementService.compileZone` via `zonesDir` — `compileBin` arg injection

**File:** `api/grpc/services/management.go:748`
**Issue:** `compileZone` builds an `exec.CommandContext` with `-input inputPath -output outputPath`. Both `inputPath` and `outputPath` are constructed via `filepath.Join(s.zonesDir, domain+".dnszone")`. However `domain` is derived from `req.Domain` after `strings.TrimSuffix(req.Domain, ".")` — there is no path traversal check in `ManagementService.CreateZone` for the domain field (unlike `AdminService` which calls `validateZoneName`). A domain string like `"../../etc/cron.d/evil"` would pass `TrimSuffix` and then be written to `../../etc/cron.d/evil.dnszone` when `zonesDir` is an absolute path only if `filepath.Join` collapses it — but `filepath.Join` **does** collapse `..` components, making this a real path traversal.

For example: `domain = "../../etc/passwd-backup"` → `filepath.Join("/var/zones", "../../etc/passwd-backup.dnszone")` = `/etc/passwd-backup.dnszone`. An attacker can overwrite or create files outside `zonesDir`.
**Fix:** Add an explicit validation step in `ManagementService.CreateZone` (and `DeleteZone`, `ReloadZones`) equivalent to `AdminService.validateZoneName`:

```go
func validateMgmtDomain(domain string) error {
    if domain == "" {
        return status.Error(codes.InvalidArgument, "domain is required")
    }
    if strings.Contains(domain, "/") || strings.Contains(domain, "..") ||
        strings.ContainsAny(domain, "\x00\r\n") {
        return status.Error(codes.InvalidArgument, "domain contains illegal characters")
    }
    return nil
}
```

Apply this before `strings.TrimSuffix` in `CreateZone`, `DeleteZone`, `ReloadZones` (for zone IDs), and `serializeCompileReload`.

---

### CR-03: Nil pointer panic in `AdminService.FlushCache` when `s.cache` is nil

**File:** `internal/admin/service.go:291`
**Issue:** `FlushCache` calls `s.cache.Flush()` at line 291 without a nil guard on `s.cache`. `NewService` accepts `cache *cache.ShardedCache` as a parameter that is allowed to be nil (the `GetServerStatus` and `GetMetrics` methods correctly nil-guard `s.cache`). If the admin service is registered when `GetShardedCache()` returns nil (e.g., recursive resolver disabled), any call to `FlushCache`, `GetCacheStats`, `PurgeCache`, `flushByPattern`, `flushNegativeEntries`, or `flushExpiredEntries` will panic.

Similarly, `GetCacheStats` at line 358 calls `s.cache.GetStats()` without nil check, while `GetMetrics` at line 913 correctly nil-guards it. This inconsistency is a bug.
**Fix:** Add nil guard at the top of `FlushCache`, `GetCacheStats`, and `PurgeCache`:

```go
func (s *Service) FlushCache(ctx context.Context, req *pb.AdminFlushCacheRequest) (*pb.AdminFlushCacheResponse, error) {
    if s.cache == nil {
        return nil, status.Error(codes.FailedPrecondition, "cache not configured")
    }
    // ...
}
```

---

### CR-04: Race condition in RRL token bucket refill — non-atomic read-modify-write

**File:** `internal/rrl/limiter.go:187-204`
**Issue:** The token refill sequence reads `lastCheck`, computes `elapsed`, reads `currentTokens`, computes `newTokens`, then stores both atomically one at a time. However, between `atomic.LoadInt32(&b.tokens)` (line 196) and `atomic.StoreInt32(&b.tokens, newTokens)` (line 200), another goroutine can also read the same `currentTokens` value, compute its own `newTokens`, and both store — resulting in double-refill (tokens granted above the maximum) or other corruption. The goroutines also race on `lastCheck`: both can read `elapsed > 0`, both refill, and both update `lastCheck` to `now`. This means in a high-concurrency scenario tokens are over-credited, making rate limiting ineffective.
**Fix:** Use `atomic.CompareAndSwap` for both `tokens` and `lastCheck`, or hold a per-bucket mutex for the refill step. Alternatively restructure so refill is done inside a single CAS loop:

```go
for {
    cur := atomic.LoadInt32(&b.tokens)
    last := atomic.LoadInt64(&b.lastCheck)
    elapsed := now - last
    newVal := cur
    if elapsed > 0 {
        newVal = cur + int32(elapsed*int64(limit))
        if newVal > maxTokens { newVal = maxTokens }
    }
    if atomic.CompareAndSwapInt32(&b.tokens, cur, newVal-1) {
        atomic.CompareAndSwapInt64(&b.lastCheck, last, now)
        // token consumed or at boundary
        break
    }
}
```

---

### CR-05: `TsigSecretMap()` returns a mutable shared reference — concurrent map write/read race

**File:** `internal/tsig/tsig.go:98-103`
**Issue:** `TsigSecretMap()` returns the internal `kr.secrets` map directly by reference (not a copy). The `dns.Server` from `miekg/dns` reads this map without locking for every TSIG verification. Meanwhile, `KeyRing.Add()` and `KeyRing.Remove()` write to `kr.secrets` under `kr.mu.Lock()`. But the `dns.Server` reads from the same map concurrently without any lock. This is an unsynchronized concurrent map access — a Go data race that can cause a runtime panic.

The comment in the code says "mutations via Add/Remove are visible to the dns.Server on the next request" — but this design is only safe if `miekg/dns` also locks the map when reading it, which it does not.
**Fix:** Rather than sharing the map directly, implement a thread-safe map type (e.g., `sync.Map`) or copy-on-write semantics. If `miekg/dns` requires a plain `map[string]string`, then a `sync.RWMutex`-protected copy-on-write approach is needed: every `Add`/`Remove` replaces the entire map atomically using a pointer swap, and `TsigSecretMap` returns the current snapshot pointer.

```go
type KeyRing struct {
    mu      sync.RWMutex
    keys    map[string]keyEntry
    secrets atomic.Pointer[map[string]string] // swapped atomically on Add/Remove
}
```

---

### CR-06: `UpdateRecord` in `AdminService` does not persist changes to disk

**File:** `internal/admin/service.go:657-700`
**Issue:** `AdminService.UpdateRecord` calls `adminRemoveRecord` and `z.AddRecord(rr)` on the in-memory zone, but then returns without persisting the change to disk or reloading the compiled zone. The persistence block (lines 635-645) exists only in `CreateRecord`, not in `UpdateRecord` or `DeleteRecord` (lines 704-724). After a server restart, all in-memory-only mutations made via `UpdateRecord` or `DeleteRecord` will be lost, and the server will revert to the stale zone on disk. This is a data-integrity defect that could also cause correctness problems if the disk and in-memory states diverge.
**Fix:** Apply the same serialize-compile-reload block that `CreateRecord` uses to both `UpdateRecord` and `DeleteRecord`:

```go
// After adminRemoveRecord + z.AddRecord in UpdateRecord:
if s.zonesDir != "" && s.compileBin != "" {
    dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
    dzcPath    := filepath.Join(s.zonesDir, domain+".dzc")
    if data, serErr := zone.SerializeDNSZone(z); serErr == nil {
        _ = os.WriteFile(dnszonePath, data, 0644)
        if compErr := s.compileZone(ctx, dnszonePath, dzcPath); compErr == nil {
            if updated, loadErr := zone.LoadCompiledZone(dzcPath); loadErr == nil {
                _ = s.srv.AddZone(updated)
            }
        }
    }
}
```

The same fix applies to `DeleteRecord`.

---

### CR-07: `ShutdownServer` ignores `shutdownFn` error return in goroutine

**File:** `internal/admin/service.go:932-934`
**Issue:** `ShutdownServer` spawns a goroutine that sleeps and then calls `s.shutdownFn()`. The error return value of `s.shutdownFn()` is silently discarded. If shutdown fails (e.g., a component fails to stop cleanly), the caller receives a success response but the server may not actually stop. This misreports success to the caller.

Additionally, `time.Sleep(time.Duration(req.GracePeriodSeconds) * time.Second)` with `GracePeriodSeconds = 0` means the goroutine fires immediately — but the RPC has already returned `Success: true`. There is no mechanism to report failure back to the caller, which is somewhat inherent to the async design, but the total silence on error is still a defect.
**Fix:** Log the error from `shutdownFn`:

```go
go func() {
    time.Sleep(time.Duration(req.GracePeriodSeconds) * time.Second)
    if err := s.shutdownFn(); err != nil {
        // Use structured logging or fmt.Fprintf(os.Stderr, ...)
        fmt.Fprintf(os.Stderr, "shutdown error: %v\n", err)
    }
}()
```

---

## Warnings

### WR-01: `AdminService.BY_NAME` flush only removes one type/class combination, not all cache entries for the name

**File:** `internal/admin/service.go:305-310`
**Issue:** The `BY_NAME` flush case uses `cache.HashKey(req.Name, 1, 1)` (hardcoded type A, class IN) and deletes exactly one hash. DNS names have entries for multiple types (AAAA, MX, TXT, NS, etc.) and the flush will silently leave all non-A entries in the cache. The response message claims "Flushed cache for %s" but the semantics are broken.
**Fix:** Iterate over all known DNS types and classes to compute and delete all hashes, or add a `FlushByName(name string)` method to `ShardedCache` that does a pattern match on the name field.

---

### WR-02: `adminRemoveRecord` content comparison uses `rr.String()` prefix stripping — fragile and inconsistent

**File:** `internal/admin/service.go:593-594`
**Issue:** `adminRemoveRecord` identifies the record to delete by extracting content as `strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr.String()))`. This differs from how `management.go`'s `rrContent` helper extracts content (type-switch with explicit field access). For TXT records, `rr.String()` produces quoted strings with backslash escapes (e.g., `"hello world"`), while `rrToPBRecord` in `management.go` joins `v.Txt` without quotes. If the content stored in the record ID was created by `adminMakeRecordID` using `req.Content` directly (the raw string "hello world"), the comparison in `adminRemoveRecord` will never match a TXT record (which would have content `"hello world"` with quotes from `.String()`). This means `UpdateRecord` and `DeleteRecord` on TXT records will silently fail to remove the old record.
**Fix:** Use a type-switch like `management.go`'s `rrContent` function for content extraction, and ensure `adminMakeRecordID` uses the same extraction method. Centralise the content-to-string logic into a shared helper.

---

### WR-03: `AdminService.ListRecords` owner filter uses `HasPrefix` — returns unintended matches

**File:** `internal/admin/service.go:757`
**Issue:** The owner filter `strings.HasPrefix(strings.ToLower(owner), filterOwner)` matches any owner whose FQDN starts with the filter string. Filtering for owner `"mail"` would also match `"mailer"`, `"mailbox"`, etc. In a DNS context, owner filtering should be exact (or wildcard), not prefix-based.
**Fix:** Use exact equality after normalizing both sides to FQDN:

```go
if filterOwner != "" {
    ownerFQDN := dns.Fqdn(filterOwner + "." + domain)
    if strings.ToLower(owner) != ownerFQDN && strings.ToLower(owner) != filterOwner {
        continue
    }
}
```

---

### WR-04: `ManagementService.CreateZone` assigns initial records only as A type — ignores actual record type

**File:** `api/grpc/services/management.go:160-170`
**Issue:** When processing `req.InitialRecords`, the code unconditionally assigns values to `sec.A` regardless of what record type the caller intended. If the caller passes MX or CNAME records in `InitialRecords`, they will be silently stored as A records in the zone file structure, producing an incorrect zone.

```go
sec := zone.RecordSection{}
if len(rs.Values) == 1 {
    sec.A = rs.Values[0]   // always A, ignoring rs.Type
} else if len(rs.Values) > 1 {
    // ...
    sec.A = iface           // always A
}
```
**Fix:** Use the `rs.Type` (or equivalent field from the proto) to assign to the correct field in `RecordSection` (e.g., `sec.CNAME`, `sec.MX`, `sec.TXT`).

---

### WR-05: `ManagementService.BatchDeleteRecords` increments `deleted` even when `removeRecord` silently no-ops

**File:** `api/grpc/services/management.go:629-637`
**Issue:** `removeRecord` is a best-effort helper that returns no error and silently does nothing if the record does not match. `BatchDeleteRecords` always increments `deleted++` after calling `removeRecord`, even when no record was actually found or removed. The response therefore over-reports `DeletedCount`, and `Success: true` is returned even when some records were not found.
**Fix:** `removeRecord` (and `adminRemoveRecord`) should return a boolean indicating whether a record was actually removed:

```go
func removeRecord(z *zone.Zone, owner string, rrtype uint16, content string) bool {
    // ... existing logic ...
    // return true if len(before) != len(filtered)
}
```

Then only increment `deleted` if the return is true; append to `errs` otherwise.

---

### WR-06: `AddTsigKey` in `AdminService` blocks when `tsigKeyRing` is nil but config could be wired later

**File:** `internal/admin/service.go:957-959`
**Issue:** `AddTsigKey` returns `codes.FailedPrecondition` with message "TSIG key ring not configured (no keys in config)" when `s.tsigKeyRing == nil`. However in `registry/register.go` line 78, `srv.GetTsigKeyRing()` is passed and may be nil if no TSIG keys are in the config. This makes `AddTsigKey` permanently unavailable unless the admin was started with at least one TSIG key pre-configured. This is a bootstrapping problem: an operator cannot add the first TSIG key via the admin API if the server started with no keys.
**Fix:** Initialise a non-nil `KeyRing` by default (using `tsig.NewKeyRing(nil)` which creates an empty ring) in `server.New()` rather than leaving `tsigKeyRing` nil when no keys are configured. The empty ring is safe and allows runtime addition of keys.

---

### WR-07: `SetQueryLogEnabled` reopens a new file descriptor each time it is called with `enabled=true`, leaking the previous one

**File:** `internal/logging/logger.go:267-269`
**Issue:** `SetQueryLogEnabled(true)` when `!l.config.EnableQueryLog` sets the flag and calls `l.setupQueryLog()`. `setupQueryLog` opens a new `os.File` and assigns it to `l.queryFile`. But if `l.queryFile` was previously non-nil (e.g., from an earlier enable-disable-enable cycle), the old file descriptor is overwritten without being closed first. This leaks a file descriptor.
**Fix:** Close the existing `queryFile` before reopening:

```go
func (l *Logger) SetQueryLogEnabled(enabled bool) error {
    l.mu.Lock()
    defer l.mu.Unlock()
    if enabled && !l.config.EnableQueryLog {
        if l.queryFile != nil {
            _ = l.queryFile.Close()
            l.queryFile = nil
        }
        l.config.EnableQueryLog = true
        return l.setupQueryLog()
    }
    // ...
}
```

---

### WR-08: `main.go` does not wire TSIG keys from `loadedCfg.TsigKeys` into `cfg.TsigKeys` before creating the server

**File:** `cmd/dnsscienced/main.go:121`
**Issue:** `cfg = loadedCfg.Server` replaces the entire server config with the loaded one, but `config.Config.TsigKeys` is at the top level (`loadedCfg.TsigKeys`), not inside `loadedCfg.Server`. After line 121, `cfg.TsigKeys` will be the zero value (nil/empty) because `server.Config.TsigKeys` has `yaml:"-"` and is never populated from the file. TSIG keys configured in `tsig_keys:` in `config.yaml` are silently ignored — the key ring will always be nil, disabling TSIG for zone transfers and making the TSIG admin RPCs return `FailedPrecondition`.
**Fix:** After loading the config, copy TSIG key configs into the server config:

```go
cfg = loadedCfg.Server
// Wire TSIG keys from top-level config into server config
for _, k := range loadedCfg.TsigKeys {
    cfg.TsigKeys = append(cfg.TsigKeys, tsig.KeyConfig{
        Name:      k.Name,
        Algorithm: k.Algorithm,
        Secret:    k.Secret,
    })
}
```

---

## Info

### IN-01: Duplicate `compileZone` implementations in `AdminService` and `ManagementService`

**File:** `internal/admin/service.go:111-121`, `api/grpc/services/management.go:744-758`
**Issue:** Both `admin.Service` and `services.ManagementService` have their own identical `compileZone` method. Any future bug fix or enhancement to one will need to be replicated to the other, and will likely be missed.
**Fix:** Extract `compileZone` to a shared package (e.g., `internal/zoneutil`) and import it from both services.

---

### IN-02: TODO comments in `GetMetrics` for latency tracking

**File:** `internal/admin/service.go:899-900`
**Issue:** `AvgLatencyMs` and `P99LatencyMs` are always 0.0 with TODO comments. These fields are part of the public gRPC API and returning zero without a documented reason may confuse callers.
**Fix:** Until implemented, either omit the fields from the response or document in the proto/response that these are not yet populated.

---

### IN-03: `HealthCheck` in `ManagementService` hardcodes version as `"1.0"`

**File:** `api/grpc/services/management.go:663`
**Issue:** `HealthCheck` and `GetServerStatus` both return hardcoded `Version: "1.0"`. The registry package has a `version` variable injected at build time via `-ldflags`, but that value is not accessible to `ManagementService`. `GetServerStatus` in `admin/service.go` also hardcodes `"1.0.0"` (note different format from `management.go`'s `"1.0"`).
**Fix:** Pass the build-time version string into `ManagementService` at construction time (e.g., as a `version string` parameter to `NewManagementService`) and use it in responses.

---

### IN-04: `PurgeCache` glob path does not collect samples for non-regex patterns

**File:** `internal/admin/service.go:400-404`
**Issue:** When `req.Regex = false`, `PurgeCache` calls `flushByPattern` which does not collect samples, so the response always has `Samples: nil`. The regex path collects samples. This inconsistency will confuse callers who use glob patterns and expect sample output.
**Fix:** Refactor `flushByPattern` to optionally collect and return samples, or inline the glob logic in `PurgeCache` so both paths populate `Samples`.

---

_Reviewed: 2026-05-16T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
