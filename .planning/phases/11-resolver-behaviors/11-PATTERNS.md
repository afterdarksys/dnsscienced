# Phase 11: Resolver Behaviors - Pattern Map

**Mapped:** 2026-05-22
**Files analyzed:** 5 files (3 modified, 2 new test files)
**Analogs found:** 5 / 5

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/resolver/recursive.go` | service | request-response | self (existing file, bug-fix + extension) | exact |
| `internal/cache/nsec.go` | service | CRUD | self (existing file, NSEC3 extension) | exact |
| `internal/config/config.go` | config | — | self (existing file, struct extension) | exact |
| `internal/resolver/resolver_behaviors_test.go` | test | request-response | `internal/resolver/recursive_test.go` | exact |
| `internal/cache/nsec_test.go` | test | CRUD | `internal/resolver/recursive_test.go` (same test conventions) | role-match |

---

## Pattern Assignments

### `internal/resolver/recursive.go` (service, request-response — 3 changes)

**Analog:** self — `internal/resolver/recursive.go`

---

#### Change A: Config struct extension (lines 44–71)

Add three feature-flag fields and `StaleTTL` to `resolver.Config`. Follow the existing field layout: bool flag + sub-struct config for each feature.

**Existing struct pattern** (`recursive.go` lines 44–71):
```go
type Config struct {
    CacheConfig cache.Config `yaml:"cache"`
    Workers     int          `yaml:"workers"`
    // ... timeout, MaxIterations ...
    EnableCookies bool          `yaml:"enable_cookies"`
    CookieConfig  cookie.Config `yaml:"cookies"`
    EnableRRL     bool          `yaml:"enable_rrl"`
    RRLConfig     rrl.Config    `yaml:"rrl"`
    EnableDNSSEC  bool          `yaml:"enable_dnssec"`
    DNSSECConfig  dnssec.ValidatorConfig `yaml:"dnssec"`
}
```

**New fields to add** (after `EnableDNSSEC`/`DNSSECConfig`):
```go
// QNAMEMinimization enables RFC 7816 + RFC 9156 per-delegation query name rewriting.
// Reveals only one additional label beyond the current zone at each iterative hop.
QNAMEMinimization bool `yaml:"qname_minimization"`

// AggressiveNSEC enables RFC 8198 synthesis from cached NSEC/NSEC3 records.
// Requires EnableDNSSEC: true. Wired into CacheConfig.AggressiveNSEC in NewRecursive().
AggressiveNSEC bool `yaml:"aggressive_nsec"`

// ServeStale enables RFC 8767 behavior: serve expired cache entries with TTL=0
// when all upstream nameservers are unreachable.
ServeStale bool `yaml:"serve_stale"`

// StaleTTL is the maximum age past expiry that a stale record may be served.
// Defaults to 24h. Wired into CacheConfig.MaxStaleTTL to avoid duplication (D-11).
StaleTTL time.Duration `yaml:"stale_max_ttl"`
```

---

#### Change B: NewRecursive() — wire feature flags into cache config (after line 96, before `cache.NewShardedCache`)

**Existing pattern for conditional init** (`recursive.go` lines 112–138):
```go
// Initialize cookies if enabled
if cfg.EnableCookies {
    var err error
    r.cookies, err = cookie.NewManager(cfg.CookieConfig)
    if err != nil {
        return nil, fmt.Errorf("init cookies: %w", err)
    }
}
// Initialize RRL if enabled
if cfg.EnableRRL {
    r.rrl = rrl.NewLimiter(cfg.RRLConfig)
}
```

**New wiring block** (insert before `r := &Recursive{...}` at line 99, after default-setting):
```go
// Wire resolver feature flags into cache config (D-11: avoid duplication).
if cfg.ServeStale {
    cfg.CacheConfig.ServeStale = true
    if cfg.StaleTTL > 0 {
        cfg.CacheConfig.MaxStaleTTL = cfg.StaleTTL
    } else {
        cfg.CacheConfig.MaxStaleTTL = 24 * time.Hour
    }
}
if cfg.AggressiveNSEC {
    cfg.CacheConfig.AggressiveNSEC = true
}
// Default feature flags ON (D-10)
// QNAMEMinimization, AggressiveNSEC, ServeStale default to false in Go zero-value;
// defaults must be set here if D-10 requires them ON for new deployments.
```

---

#### Change C: Resolve() — fix stale guard + add upstream-failure fallback (lines 171 and 198–201)

**Bug 1 — line 171. Current (buggy):**
```go
if entry, ok := r.cache.Get(cacheKey); ok && !entry.IsExpired() {
```
**Fixed:**
```go
if entry, ok := r.cache.Get(cacheKey); ok {
```

**Bug 2 — line 198–201. Current (no stale fallback):**
```go
resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
if err != nil {
    return nil, err
}
```

**Fixed (insert stale-fallback block):**
```go
resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
if err != nil {
    // Upstream failure: attempt stale cache lookup before returning SERVFAIL (RFC 8767).
    if r.cfg.ServeStale {
        if staleEntry, ok := r.cache.Get(cacheKey); ok {
            staleResp := pool.GetMessage()
            defer pool.PutMessage(staleResp)
            if unpackErr := staleResp.Unpack(staleEntry.Data); unpackErr == nil {
                staleResp.Id = q.Id
                staleResp.RecursionAvailable = true
                // RFC 8767 §5: rewrite TTL=0 on all RRs in stale response.
                for _, rr := range staleResp.Answer {
                    rr.Header().Ttl = 0
                }
                for _, rr := range staleResp.Ns {
                    rr.Header().Ttl = 0
                }
                for _, rr := range staleResp.Extra {
                    if rr.Header().Rrtype != dns.TypeOPT {
                        rr.Header().Ttl = 0
                    }
                }
                return staleResp.Copy(), nil
            }
        }
    }
    return nil, err
}
```

**Reference patterns from existing file:**
- `pool.GetMessage()` / `pool.PutMessage()` — already used at lines 180–183
- `resp.Unpack(entry.Data)` — already used at line 182
- `resp.Id = q.Id` — already used at line 203
- `resp.Copy()` — already used at line 187

---

#### Change D: resolveIterative() — add QNAME minimization state (lines 262–318)

**Import to add** (top of file, imports block):
```go
"strings"

"github.com/dnsscience/dnsscienced/internal/engine"
```
Note: `"strings"` may already be present; `engine` import is new but cycle-free (verified: engine does not import resolver).

**Existing iteration pattern** (`recursive.go` lines 262–318):
```go
func (r *Recursive) resolveIterative(ctx context.Context, qname string, qtype, qclass uint16) (*dns.Msg, error) {
    nameservers := rootServers
    iterations := 0

    for iterations < r.cfg.MaxIterations {
        iterations++

        resp, err := r.queryNameserver(ctx, nameservers[0], qname, qtype, qclass)
        if err != nil {
            if len(nameservers) > 1 {
                nameservers = nameservers[1:]
                continue
            }
            return nil, fmt.Errorf("all nameservers failed: %w", err)
        }

        if len(resp.Answer) > 0 {
            return resp, nil
        }
        if resp.Rcode == dns.RcodeNameError {
            return resp, nil
        }

        // Follow referral
        if len(resp.Ns) > 0 {
            var newNameservers []string
            for _, rr := range resp.Ns {
                if ns, ok := rr.(*dns.NS); ok {
                    nsIP := r.findGlue(resp, ns.Ns)
                    if nsIP != "" {
                        newNameservers = append(newNameservers, nsIP+":53")
                    }
                }
            }
            if len(newNameservers) == 0 {
                return nil, ErrNoNameservers
            }
            nameservers = newNameservers
            continue
        }
        return resp, nil
    }
    return nil, ErrMaxIterations
}
```

**Modified version with QNAME minimization:**
```go
func (r *Recursive) resolveIterative(ctx context.Context, qname string, qtype, qclass uint16) (*dns.Msg, error) {
    nameservers := rootServers
    iterations := 0
    currentZone := "."   // RFC 7816/9156: track delegation zone across hops

    for iterations < r.cfg.MaxIterations {
        iterations++

        // Compute minimized send name and type for this hop (D-02, D-03).
        sendName := qname
        sendType := qtype
        if r.cfg.QNAMEMinimization {
            sendName = engine.ApplyQNAMEMinimization(qname, currentZone)
            // RFC 9156: intermediate hops use qtype=A; final hop uses original qtype.
            if sendName != qname {
                sendType = dns.TypeA
            }
        }

        resp, err := r.queryNameserver(ctx, nameservers[0], sendName, sendType, qclass)
        if err != nil {
            if len(nameservers) > 1 {
                nameservers = nameservers[1:]
                continue
            }
            return nil, fmt.Errorf("all nameservers failed: %w", err)
        }

        // QNAME minimization NODATA at intermediate hop (RFC 9156 §4):
        // if minimized and answer is empty + NOERROR, disable minimization for
        // remainder (fall through to full qname query next iteration).
        if r.cfg.QNAMEMinimization && sendName != qname &&
            len(resp.Answer) == 0 && resp.Rcode == dns.RcodeSuccess && len(resp.Ns) == 0 {
            // Intermediate NODATA: re-issue full qname to this same nameserver set.
            sendName = qname
            sendType = qtype
            resp, err = r.queryNameserver(ctx, nameservers[0], sendName, sendType, qclass)
            if err != nil {
                if len(nameservers) > 1 {
                    nameservers = nameservers[1:]
                    continue
                }
                return nil, fmt.Errorf("all nameservers failed: %w", err)
            }
        }

        if len(resp.Answer) > 0 {
            return resp, nil
        }
        if resp.Rcode == dns.RcodeNameError {
            return resp, nil
        }

        // Follow referral; update currentZone from NS authority owner name (NOT ns.Ns).
        if len(resp.Ns) > 0 {
            var newNameservers []string
            for _, rr := range resp.Ns {
                if ns, ok := rr.(*dns.NS); ok {
                    nsIP := r.findGlue(resp, ns.Ns)
                    if nsIP != "" {
                        newNameservers = append(newNameservers, nsIP+":53")
                    }
                }
            }
            if len(newNameservers) == 0 {
                return nil, ErrNoNameservers
            }
            // Update zone to delegation zone: use NS RR owner name (the zone), not ns.Ns (the nameserver).
            currentZone = dns.Fqdn(strings.ToLower(resp.Ns[0].Header().Name))
            nameservers = newNameservers
            continue
        }
        return resp, nil
    }
    return nil, ErrMaxIterations
}
```

---

### `internal/cache/nsec.go` (service, CRUD — NSEC3 extension)

**Analog:** self — `internal/cache/nsec.go`

---

#### Change A: Add nsec3Record struct (after existing nsecRecord, line 28–34)

**Existing nsecRecord struct** (`nsec.go` lines 28–34):
```go
type nsecRecord struct {
    Owner     string
    Next      string
    TypeMap   []uint16
    ExpiresAt time.Time
    Zone      string
}
```

**New nsec3Record struct** (add immediately after nsecRecord):
```go
// nsec3Record is one validated NSEC3 record stored for RFC 8198 aggressive synthesis.
type nsec3Record struct {
    OwnerHash  string    // base32-encoded hashed owner name (uppercase, no zone suffix)
    NextHash   string    // base32-encoded hashed next owner name (uppercase)
    Zone       string    // lowercase FQDN of the zone this NSEC3 covers
    Hash       uint8     // hash algorithm; only dns.SHA1 (1) is stored (D-06, Pitfall 4)
    Iterations uint16
    Salt       string    // hex-encoded as stored in *dns.NSEC3.Salt
    Flags      uint8
    TypeMap    []uint16
    ExpiresAt  time.Time
}
```

---

#### Change B: Add nsec3records field to NSECCache struct (line 22–25)

**Existing struct** (`nsec.go` lines 22–25):
```go
type NSECCache struct {
    mu      sync.RWMutex
    records []*nsecRecord
}
```

**Modified:**
```go
type NSECCache struct {
    mu           sync.RWMutex
    records      []*nsecRecord  // NSEC records (canonical ordering)
    nsec3records []*nsec3Record // NSEC3 records (hashed, RFC 5155)
}
```

---

#### Change C: Extend Store() to also store NSEC3 records (after existing NSEC loop, line 79)

**Existing Store() NSEC loop pattern** (`nsec.go` lines 49–78):
```go
func (c *NSECCache) Store(msg *dns.Msg, zone string) {
    now := time.Now()
    c.mu.Lock()
    defer c.mu.Unlock()

    for _, rr := range msg.Ns {
        nsec, ok := rr.(*dns.NSEC)
        if !ok {
            continue
        }
        owner := strings.ToLower(dns.Fqdn(nsec.Hdr.Name))
        next  := strings.ToLower(dns.Fqdn(nsec.NextDomain))
        rec := &nsecRecord{
            Owner:     owner,
            Next:      next,
            TypeMap:   nsec.TypeBitMap,
            ExpiresAt: now.Add(time.Duration(nsec.Hdr.Ttl) * time.Second),
            Zone:      strings.ToLower(dns.Fqdn(zone)),
        }
        replaced := false
        for i, existing := range c.records {
            if existing.Owner == owner {
                c.records[i] = rec
                replaced = true
                break
            }
        }
        if !replaced {
            c.records = append(c.records, rec)
        }
    }
}
```

**NSEC3 loop to append after the NSEC loop (same lock, same now):**
```go
    // Also store NSEC3 records (RFC 5155) for NSEC3-signed zones.
    for _, rr := range msg.Ns {
        nsec3, ok := rr.(*dns.NSEC3)
        if !ok {
            continue
        }
        // Skip non-SHA1 algorithms — miekg/dns only implements SHA-1 (Pitfall 4).
        if nsec3.Hash != dns.SHA1 {
            continue
        }
        // NSEC3 owner format: "<hash>.<zone>" — split at second label boundary.
        owner := strings.ToUpper(nsec3.Hdr.Name)
        labelIdx := dns.Split(owner)
        if len(labelIdx) < 2 {
            continue
        }
        ownerHash := owner[:labelIdx[1]-1]
        ownerZone := strings.ToLower(dns.Fqdn(owner[labelIdx[1]:]))

        rec := &nsec3Record{
            OwnerHash:  ownerHash,
            NextHash:   strings.ToUpper(nsec3.NextDomain),
            Zone:       ownerZone,
            Hash:       nsec3.Hash,
            Iterations: nsec3.Iterations,
            Salt:       nsec3.Salt,
            Flags:      nsec3.Flags,
            TypeMap:    nsec3.TypeBitMap,
            ExpiresAt:  now.Add(time.Duration(nsec3.Hdr.Ttl) * time.Second),
        }
        // Replace existing record for same ownerHash+zone (mirrors NSEC replace pattern).
        replaced := false
        for i, existing := range c.nsec3records {
            if existing.OwnerHash == ownerHash && existing.Zone == ownerZone {
                c.nsec3records[i] = rec
                replaced = true
                break
            }
        }
        if !replaced {
            c.nsec3records = append(c.nsec3records, rec)
        }
    }
```

---

#### Change D: Add synthesizeFromNSEC3() method and extend SynthesizeNXDOMAIN()

**Existing SynthesizeNXDOMAIN() — add NSEC3 fallback after existing NSEC check** (`nsec.go` lines 85–113):
```go
func (c *NSECCache) SynthesizeNXDOMAIN(qname string, qtype uint16, qclass uint16, queryID uint16) *dns.Msg {
    // ... existing NSEC synthesis ...
    return nil
}
```

**Modified tail (replace final `return nil`):**
```go
    // Fall through: try NSEC3 synthesis (RFC 5155 + RFC 8198).
    return c.synthesizeFromNSEC3(qname, qtype, qclass, queryID)
}

// synthesizeFromNSEC3 attempts NSEC3-based NXDOMAIN synthesis (RFC 8198 + RFC 5155).
// Uses dns.NSEC3.Cover() which calls dns.HashName() internally and handles zone-end
// wrap-around in the circular hashed namespace. Returns nil if no synthesis is possible.
func (c *NSECCache) synthesizeFromNSEC3(qname string, qtype, qclass, queryID uint16) *dns.Msg {
    qname = strings.ToLower(dns.Fqdn(qname))
    now := time.Now()

    // mu.RLock is already held by the caller (SynthesizeNXDOMAIN).
    for _, rec := range c.nsec3records {
        if rec.ExpiresAt.Before(now) {
            continue
        }
        // Pre-filter by zone to prevent false Cover() results (Pitfall 3).
        if !dns.IsSubDomain(rec.Zone, qname) {
            continue
        }
        // Opt-out flag (bit 0): signed delegations only; do not synthesize for opt-out zones.
        if rec.Flags&0x01 != 0 {
            continue
        }
        // Reconstruct minimal *dns.NSEC3 for the Cover() method.
        n3 := &dns.NSEC3{
            Hdr:        dns.RR_Header{Name: rec.OwnerHash + "." + rec.Zone},
            Hash:       rec.Hash,
            Flags:      rec.Flags,
            Iterations: rec.Iterations,
            Salt:       rec.Salt,
            NextDomain: rec.NextHash,
            TypeBitMap: rec.TypeMap,
        }
        if n3.Cover(qname) {
            return buildSyntheticNXDOMAIN_NSEC3(qname, qtype, qclass, queryID, rec, n3)
        }
    }
    return nil
}

// buildSyntheticNXDOMAIN_NSEC3 constructs an NXDOMAIN response from a cached NSEC3 record.
// Mirrors buildSyntheticNXDOMAIN() for NSEC.
func buildSyntheticNXDOMAIN_NSEC3(qname string, qtype, qclass, queryID uint16, rec *nsec3Record, n3 *dns.NSEC3) *dns.Msg {
    m := new(dns.Msg)
    m.Id = queryID
    m.Response = true
    m.Opcode = dns.OpcodeQuery
    m.Authoritative = false
    m.RecursionAvailable = true
    m.Rcode = dns.RcodeNameError

    m.Question = []dns.Question{{
        Name:   qname,
        Qtype:  qtype,
        Qclass: qclass,
    }}

    // Include NSEC3 in authority section so clients can validate the synthetic denial.
    nsec3RR := &dns.NSEC3{
        Hdr: dns.RR_Header{
            Name:   n3.Hdr.Name,
            Rrtype: dns.TypeNSEC3,
            Class:  dns.ClassINET,
            Ttl:    uint32(time.Until(rec.ExpiresAt).Seconds()),
        },
        Hash:       rec.Hash,
        Flags:      rec.Flags,
        Iterations: rec.Iterations,
        Salt:       rec.Salt,
        NextDomain: rec.NextHash,
        TypeBitMap: rec.TypeMap,
    }
    m.Ns = []dns.RR{nsec3RR}
    return m
}
```

---

#### Change E: Extend Flush() to also flush nsec3records (lines 117–129)

**Existing Flush()** (`nsec.go` lines 117–129):
```go
func (c *NSECCache) Flush() {
    c.mu.Lock()
    defer c.mu.Unlock()

    now := time.Now()
    valid := c.records[:0]
    for _, rec := range c.records {
        if rec.ExpiresAt.After(now) {
            valid = append(valid, rec)
        }
    }
    c.records = valid
}
```

**Add NSEC3 flush after NSEC flush (same pattern):**
```go
    valid3 := c.nsec3records[:0]
    for _, rec := range c.nsec3records {
        if rec.ExpiresAt.After(now) {
            valid3 = append(valid3, rec)
        }
    }
    c.nsec3records = valid3
```

---

### `internal/config/config.go` (config — struct extension only)

**Analog:** self — `internal/config/config.go`

**Existing pattern for Resolver field** (lines 16–19):
```go
type Config struct {
    Server   server.Config   `yaml:"server"`
    Resolver resolver.Config `yaml:"resolver"`
    // ...
}
```

No change to `config.go` is needed — `Config.Resolver` already maps `yaml:"resolver"` to `resolver.Config`. The new fields in `resolver.Config` are picked up automatically by the YAML decoder. The planner should verify the YAML example in CONTEXT.md D-09 is consistent with the field names added to `resolver.Config`.

---

### `internal/resolver/resolver_behaviors_test.go` (test, request-response — new file)

**Analog:** `internal/resolver/recursive_test.go`

**Imports pattern** (`recursive_test.go` lines 1–13):
```go
package resolver

import (
    "context"
    "net"
    "testing"
    "time"

    "github.com/dnsscience/dnsscienced/internal/cache"
    "github.com/dnsscience/dnsscienced/internal/cookie"
    "github.com/dnsscience/dnsscienced/internal/rrl"
    "github.com/miekg/dns"
)
```

New test file adds: `"github.com/dnsscience/dnsscienced/internal/pool"` for stale-fallback tests that call `pool.GetMessage`.

**Config construction pattern** (`recursive_test.go` lines 16–26):
```go
cfg := Config{
    CacheConfig: cache.Config{
        ShardCount: 256,
        MaxEntries: 10000,
    },
    Workers:       100,
    QueryTimeout:  5 * time.Second,
    MaxIterations: 20,
    EnableCookies: false,
    EnableRRL:     false,
}
r, err := NewRecursive(cfg)
if err != nil {
    t.Fatalf("NewRecursive() error = %v", err)
}
defer r.Close()
```

**Cache pre-population pattern** (`recursive_test.go` lines 134–168):
```go
// Pack a response and insert into cache directly
packed, err := cachedResp.Pack()
if err != nil {
    t.Fatalf("Pack() error = %v", err)
}
question := cachedResp.Question[0]
cacheKey := hashQuery(question.Name, question.Qtype, question.Qclass)

r.cache.Set(cacheKey, &cache.Entry{
    Data:      packed,
    ExpiresAt: time.Now().Add(1 * time.Hour),  // <-- for stale: use time.Now().Add(-1*time.Hour)
    OrigTTL:   3600,
    QName:     question.Name,
    QType:     question.Qtype,
    QClass:    question.Qclass,
})
```

**For serve-stale tests**, set `ExpiresAt` in the past and configure `CacheConfig.ServeStale=true` + `MaxStaleTTL`:
```go
cfg := Config{
    ServeStale: true,
    StaleTTL:   24 * time.Hour,
    CacheConfig: cache.Config{
        ShardCount:  256,
        MaxEntries:  10000,
        ServeStale:  true,
        MaxStaleTTL: 24 * time.Hour,
    },
}
// ...
r.cache.Set(cacheKey, &cache.Entry{
    Data:      packed,
    ExpiresAt: time.Now().Add(-1 * time.Hour), // expired but within 24h stale window
    OrigTTL:   3600,
    QName:     question.Name,
    QType:     question.Qtype,
    QClass:    question.Qclass,
})
```

**Assertion pattern** (`recursive_test.go` line 183):
```go
if resp.Id != 0x1234 {
    t.Errorf("Response ID = 0x%x, want 0x1234", resp.Id)
}
```

**Table-driven test pattern** (`recursive_test.go` lines 250–300):
```go
tests := []struct {
    name     string
    msg      *dns.Msg
    expected uint32
}{
    { name: "...", msg: ..., expected: ... },
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        got := getTTL(tt.msg)
        if got != tt.expected {
            t.Errorf("getTTL() = %d, want %d", got, tt.expected)
        }
    })
}
```

---

### `internal/cache/nsec_test.go` (test, CRUD — new file)

**Analog:** `internal/resolver/recursive_test.go` (same test conventions; no existing nsec_test.go)

**Package and imports pattern:**
```go
package cache

import (
    "testing"
    "time"

    "github.com/miekg/dns"
)
```

**NSECCache construction pattern** (modeled on `NewNSECCache()` in `nsec.go` line 37):
```go
c := NewNSECCache()
```

**NSEC store + synthesize test structure** (model from `recursive_test.go` table-driven pattern):
```go
func TestNSECCache_SynthesizeNXDOMAIN(t *testing.T) {
    c := NewNSECCache()

    // Build a synthetic validated NXDOMAIN response carrying an NSEC record
    msg := new(dns.Msg)
    msg.Ns = []dns.RR{
        &dns.NSEC{
            Hdr: dns.RR_Header{
                Name:   "aaa.example.com.",
                Rrtype: dns.TypeNSEC,
                Class:  dns.ClassINET,
                Ttl:    300,
            },
            NextDomain: "zzz.example.com.",
            TypeBitMap: []uint16{dns.TypeA},
        },
    }
    c.Store(msg, "example.com.")

    synth := c.SynthesizeNXDOMAIN("bbb.example.com.", dns.TypeA, dns.ClassINET, 0x1234)
    if synth == nil {
        t.Fatal("expected synthetic NXDOMAIN, got nil")
    }
    if synth.Rcode != dns.RcodeNameError {
        t.Errorf("Rcode = %d, want NXDOMAIN", synth.Rcode)
    }
}
```

**NSEC3 store + synthesize test structure:**
```go
func TestNSEC3Cache_SynthesizeNXDOMAIN(t *testing.T) {
    c := NewNSECCache()

    // Build an NSEC3 record that covers a hashed range
    // Use a real NSEC3 owner/next that dns.NSEC3.Cover() will match.
    // Simplest approach: use pre-computed hashes or build a msg that
    // the existing dns.NSEC3.Cover() will return true for.
    msg := new(dns.Msg)
    msg.Ns = []dns.RR{
        &dns.NSEC3{
            Hdr: dns.RR_Header{
                Name:   "<ownerHash>.example.com.",
                Rrtype: dns.TypeNSEC3,
                Class:  dns.ClassINET,
                Ttl:    300,
            },
            Hash:       dns.SHA1,
            Flags:      0,
            Iterations: 1,
            Salt:       "",
            NextDomain: "<nextHash>",
            TypeBitMap: []uint16{dns.TypeA},
        },
    }
    c.Store(msg, "example.com.")

    // Query for a name that hashes into the owner..next range
    synth := c.SynthesizeNXDOMAIN("nonexistent.example.com.", dns.TypeA, dns.ClassINET, 0x5678)
    // Result depends on hash values; use dns.HashName() to compute expected coverage.
    _ = synth // verify Cover() result matches
}
```

---

## Shared Patterns

### Feature Flag Guard (nil-guard / bool-flag pattern)

**Source:** `internal/resolver/recursive.go` lines 112–138 (EnableCookies, EnableRRL, EnableDNSSEC blocks)
**Apply to:** All three new feature paths in `recursive.go`

```go
// Pattern: check cfg bool flag before using the feature
if r.cfg.ServeStale {
    // ... stale fallback logic ...
}
if r.cfg.QNAMEMinimization {
    // ... minimization logic ...
}
```

### pool.GetMessage / pool.PutMessage

**Source:** `internal/resolver/recursive.go` lines 180–183
**Apply to:** Serve-stale upstream-failure fallback block

```go
staleResp := pool.GetMessage()
defer pool.PutMessage(staleResp)
if err := staleResp.Unpack(staleEntry.Data); err == nil {
    // use staleResp
}
```

### sync.RWMutex + slice pattern for cache data

**Source:** `internal/cache/nsec.go` lines 22–25, 43–78
**Apply to:** NSEC3 storage in NSECCache (same mu covers both slices)

```go
c.mu.Lock()
defer c.mu.Unlock()
// Operate on c.records and c.nsec3records under same lock
```

### DNS name normalization

**Source:** `internal/cache/nsec.go` lines 55–56 and `internal/engine/security.go` lines 101–102
**Apply to:** All new code that handles DNS names

```go
name = strings.ToLower(dns.Fqdn(name))       // for NSEC canonical ordering
name = dns.Fqdn(strings.ToLower(name))        // for QNAME minimization (engine style)
currentZone = dns.Fqdn(strings.ToLower(...))  // for iterative zone tracking (Pitfall 5)
```

### buildSynthetic* response constructor

**Source:** `internal/cache/nsec.go` lines 132–162 (`buildSyntheticNXDOMAIN`)
**Apply to:** `buildSyntheticNXDOMAIN_NSEC3` — copy this exact structure, substituting NSEC3 RR

```go
m := new(dns.Msg)
m.Id = queryID
m.Response = true
m.Opcode = dns.OpcodeQuery
m.Authoritative = false
m.RecursionAvailable = true
m.Rcode = dns.RcodeNameError
m.Question = []dns.Question{{Name: qname, Qtype: qtype, Qclass: qclass}}
m.Ns = []dns.RR{ /* NSEC or NSEC3 RR */ }
return m
```

---

## No Analog Found

None — all files have strong existing analogs (self or same-package test files).

---

## Anti-Patterns (from RESEARCH.md — avoid these)

| Anti-Pattern | Correct Pattern |
|--------------|-----------------|
| `if entry, ok := r.cache.Get(key); ok && !entry.IsExpired()` | Remove `&& !entry.IsExpired()` — trust cache's own stale logic |
| Hand-rolling NSEC3 hash range comparison with base32 strings | Use `(*dns.NSEC3).Cover(qname)` — handles zone-end wrap-around |
| Using `resp.Ns[0].(*dns.NS).Ns` for `currentZone` | Use `resp.Ns[0].Header().Name` — that's the zone, not the nameserver hostname |
| Sending original `qtype` at intermediate minimized hops | Send `dns.TypeA` when `sendName != qname` (RFC 9156) |
| Storing NSEC3 records with `Hash != dns.SHA1` | Skip non-SHA1 records at Store() time; `dns.HashName()` returns `""` for unknown algorithms |
| Synthesizing from unvalidated NSEC/NSEC3 | Gate `StoreNSEC()` call on `dnssecValidated=true` (already enforced at recursive.go line 253) |

---

## Metadata

**Analog search scope:** `internal/resolver/`, `internal/cache/`, `internal/engine/`, `internal/config/`
**Files read:** 6 source files, 1 test file
**Pattern extraction date:** 2026-05-22
