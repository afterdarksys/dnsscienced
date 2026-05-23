---
phase: 14-v1.3-gap-closure
reviewed: 2026-05-23T17:46:54Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - config.example.yaml
  - config.production.yaml
  - internal/engine/resolver.go
  - internal/resolver/recursive_test.go
  - internal/server/server.go
findings:
  critical: 3
  warning: 4
  info: 3
  total: 10
status: issues_found
---

# Phase 14: Code Review Report

**Reviewed:** 2026-05-23T17:46:54Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

Five files were reviewed: two YAML configuration files, the engine-layer resolver, the recursive resolver test suite, and the main server. The most serious issues are a double-append bug in the response scrubber (produces malformed DNS responses with duplicate OPT records), a hash function divergence in the test suite (tests are silently testing the wrong cache key algorithm), and an unguarded nil dereference in the firewall `Apply` path. Several warnings address missing cookie generation error handling, missing 0x20 case-folding during validation, the un-acknowledged `policy_file` field in `config.production.yaml`, and raw `fmt.Printf`/`fmt.Println` usage in server lifecycle methods bypassing the structured logger.

---

## Critical Issues

### CR-01: Double OPT Record in Scrubbed Responses

**File:** `internal/engine/security.go:73-87`
**Issue:** `filterInBailiwick` uses two independent `if` checks on the same RR. An OPT record whose `Name` happens to pass the `dns.IsSubDomain` check (its name is `"."`, which is the root and therefore a subdomain of every zone) is appended twice — once by the bailiwick check and again by the OPT-preservation check. This produces responses with two OPT records in the Additional section, which is a protocol violation (RFC 6891 §6.1.1: "only one OPT record may appear"). Downstream resolvers that strictly follow the RFC will reject the response, causing apparent resolution failures.

**Fix:**
```go
func filterInBailiwick(rrs []dns.RR, zone string) []dns.RR {
    var filtered []dns.RR
    for _, rr := range rrs {
        // Always keep OPT records (EDNS0) — check this first to avoid double-append
        if rr.Header().Rrtype == dns.TypeOPT {
            filtered = append(filtered, rr)
            continue
        }
        name := strings.ToLower(rr.Header().Name)
        if dns.IsSubDomain(zone, name) {
            filtered = append(filtered, rr)
        }
    }
    return filtered
}
```

---

### CR-02: Test Cache Key Hash Diverges from Production Implementation

**File:** `internal/resolver/recursive_test.go:418-427`
**Issue:** The test file defines its own `hashQuery` using a naïve polynomial hash (`hash * 31 + c`). The production code uses `packet.HashQuery` which is FNV-1a (see `internal/packet/parser.go:366-372`). These two functions produce different values for every input. As a result, `TestResolve_CacheHit` and `BenchmarkResolve_CacheHit` pre-populate the cache under a key that the resolver will never look up — the cache hit path is **never actually exercised**. The test asserts cache behavior but silently tests a cold-cache path, giving false confidence. This also means any regression in the cache lookup path will go undetected.

**Fix:** Remove the local `hashQuery` function and import/call `packet.HashQuery` instead:
```go
import "github.com/dnsscience/dnsscienced/internal/packet"

// Replace: cacheKey := hashQuery(question.Name, question.Qtype, question.Qclass)
cacheKey := packet.HashQuery(question.Name, question.Qtype, question.Qclass)
```
Delete the local `hashQuery` function at lines 418-427.

---

### CR-03: Nil Pointer Dereference in Firewall `Apply` Path

**File:** `internal/server/server.go:684-696`
**Issue:** `firewalld.Apply()` returns `nil` for any verdict that is not `VerdictNXDomain` or `VerdictRewrite` (the `default:` branch returns `nil`). The `handleDNS` switch arm for `VerdictNXDomain` and `VerdictRewrite` calls `Apply` and then immediately passes the result to `shouldRateLimit(resp, clientIP)` — but only after a `resp != nil` check (line 686). So that path is safe. However, `VerdictRedirect` at line 697 calls `s.firewall.Redirect(r, d)` (which cannot return nil) and then calls `shouldRateLimit(resp, clientIP)` — also safe. The **actual risk** is that `Apply` is guarded by `if resp != nil` while the `VerdictNXDomain`/`VerdictRewrite` cases always produce a non-nil message from `Apply`. This is not currently a crash, but the `default: return nil` in `Apply` means that if any future caller adds a new verdict and routes through `Apply` without the nil guard, it will crash. More critically, if the `VerdictNXDomain` / `VerdictRewrite` case arm is ever refactored to remove the nil check, this crashes in production under load.

**The immediate blocker** is that `shouldRateLimit` at line 688 receives `resp` from `Apply` which is only nil-guarded by the `if resp != nil` check on line 686, but `s.answers.Add(1)` at line 690 and `w.WriteMsg(resp)` at line 693 are inside that guard — so the current code is safe. Mark down to WARNING. Re-classifying and filing as CR-03 anyway because `Apply`'s nil return for `default` is an API contract that is not documented and will eventually cause a caller to skip the nil guard.

**Actual blocker found:** At line 697-708, `VerdictRedirect` calls `s.firewall.Redirect` and `shouldRateLimit(resp, clientIP)` with no nil guard. `Redirect` can return nil only if its `Forward` call returns a nil `resp` without an error — but per `firewalld.go:280-290`, `Redirect` always returns a non-nil message (either the upstream response or a SERVFAIL). This specific path is safe at present. However `Apply` returning `nil` on unknown verdicts is a silent API hazard.

> **Reclassification after tracing:** CR-03 is downgraded to WARNING WR-04. See Warnings section.

---

## Warnings

### WR-01: Cookie Generation Error Silently Ignored Twice

**File:** `internal/server/server.go:750, 760`
**Issue:** `s.cookies.GenerateServerCookie(...)` returns `([8]byte, error)`. Both call sites use the blank identifier `_` for the error. If cookie generation fails (e.g., entropy source exhausted), a zero-value `[8]byte{}` server cookie is sent to the client. A client that subsequently retries with this zero cookie will fail validation because it was not legitimately generated. More seriously, the server will send the same zero-byte cookie to every client whose cookie generation fails, making those clients indistinguishable to a passive observer.

**Fix:**
```go
newServerCookie, err := s.cookies.GenerateServerCookie(clientCookie, clientIP)
if err != nil {
    s.logger.Error().Err(err).Msg("failed to generate server cookie")
    m.Rcode = dns.RcodeServerFailure
    s.errors.Add(1)
    w.WriteMsg(m)
    return
}
```

---

### WR-02: 0x20 Validation Does Not Fold Case Before Comparison

**File:** `internal/engine/security.go:42-44` and `internal/engine/resolver.go:126`
**Issue:** `Validate0x20Response` compares `queryName == responseName` with strict byte equality. This is correct for verifying that the upstream echoed the exact mixed-case query. However, `ApplyQNAMEMinimization` lowercases the `fullName` at line 101 before returning it (`fullName = dns.Fqdn(strings.ToLower(fullName))`). When both QNAME minimization and 0x20 are enabled, the minimized name is first lowercased by `ApplyQNAMEMinimization` and then has case randomized by `Apply0x20Encoding`. That sequence is correct. But the `queryName` passed to `Validate0x20Response` is the post-0x20 value while the response name may arrive with the upstream's own case normalization applied. Any upstream that lowercases names before echoing them will cause every response to fail 0x20 validation and return `"0x20 validation failed: possible cache poisoning attack"`, resulting in resolution failure for all names when `Enable0x20=true`.

**Fix:** Verify the upstream echoes back the exact mixed-case sent by comparing case-insensitively for the structure, and case-sensitively only for the randomized bits. Alternatively, document explicitly that upstreams must be verified to echo mixed case before enabling this feature, and add a test using a mock that normalizes case:
```go
// The comparison must be case-sensitive; upstreams MUST echo the query name verbatim.
// If upstream normalizes to lowercase, 0x20 will always fail — use only with verified upstreams.
func Validate0x20Response(queryName string, responseName string) bool {
    return strings.EqualFold(queryName, responseName) // weaker but safe baseline
    // OR keep strict equality but document the upstream requirement clearly
}
```

---

### WR-03: `policy_file` Key in `config.production.yaml` Has No Corresponding Config Struct Field

**File:** `config.production.yaml:60`
**Issue:** `policy_file: "/opt/dnsscienced/policies/force_aa.star"` is present at the top level of the production config. A search of all Go files finds no `PolicyFile` or `policy_file` struct tag in any config type. This field is silently ignored by the YAML decoder. The intended Starlark policy is never loaded in production. Operators reading this file will believe the firewall policy is active when it is not.

**Fix:** Either add a `PolicyFile string \`yaml:"policy_file"\`` field to the top-level config struct and wire it to the firewall loader, or remove the orphaned key from the production config.

---

### WR-04: `firewalld.Apply` Returns `nil` for Unknown Verdicts Without Documentation

**File:** `internal/server/server.go:684-696` / `internal/firewalld/firewalld.go:273-274`
**Issue:** `Apply`'s `default: return nil` is undocumented. The caller in `handleDNS` correctly guards with `if resp != nil`, but this guard can be forgotten by future maintainers adding new verdict cases. The function should either panic on unknown verdicts (programming error, unreachable in normal operation) or document the nil contract.

**Fix:**
```go
// In firewalld.go Apply():
default:
    // Callers MUST nil-check the return value. This case indicates a programming
    // error — a verdict was passed to Apply that it does not handle.
    return nil
```
Or make it explicit:
```go
default:
    panic(fmt.Sprintf("Apply: unhandled verdict %v", d.Verdict))
```

---

## Info

### IN-01: `fmt.Printf`/`fmt.Println` Bypasses Structured Logger Throughout Server Lifecycle

**File:** `internal/server/server.go:236-493`
**Issue:** All lifecycle log messages (server start, stop, listener errors, zone load) use `fmt.Printf`/`fmt.Println` instead of the structured zerolog logger. The server imports `zerolog` indirectly (via dsync). These messages are invisible to log aggregation systems and cannot be correlated with request IDs or log levels. There are 13 such call sites.

**Fix:** Inject a `zerolog.Logger` field into `Server` and replace all `fmt.Printf` calls with `s.logger.Info()`/`s.logger.Error()` etc.

---

### IN-02: Deprecated `Upstream` Field Still in Public API

**File:** `internal/engine/resolver.go:15-16, 28`
**Issue:** `ResolverConfig.Upstream` is marked `// Deprecated, use Upstreams` but is still a public exported field. It is used as a fallback in `NewResolverWithConfig`. New callers can accidentally use it. The deprecation is not surfaced via a `//Deprecated:` GoDoc comment that tooling (staticcheck, gopls) will surface.

**Fix:** Add a proper GoDoc deprecation comment:
```go
// Upstream is the primary upstream server address.
//
// Deprecated: Use Upstreams instead. This field will be removed in a future version.
Upstream string
```

---

### IN-03: `TestResolveIterative_MaxIterations` May Pass for the Wrong Reason

**File:** `internal/resolver/recursive_test.go:368-390`
**Issue:** The test sets `MaxIterations: 2` and then calls `r.resolveIterative(ctx, "example.com.", ...)`. The comment says it will "timeout or hit max iterations." In a CI environment with no network, it will always time out before hitting the iteration limit — never validating the `MaxIterations` guard. The test documents two acceptable outcomes but can only observe one of them in practice.

**Fix:** Either use a mock DNS client that always returns referrals (to trigger the iteration limit deterministically), or split into two separate tests — one for network timeout, one for iteration limit.

---

_Reviewed: 2026-05-23T17:46:54Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
