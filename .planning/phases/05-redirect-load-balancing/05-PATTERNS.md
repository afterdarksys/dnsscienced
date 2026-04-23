# Phase 5: Redirect Load Balancing - Pattern Map

**Mapped:** 2026-04-23
**Files analyzed:** 6 (5 modified, 1 with additions)
**Analogs found:** 6 / 6

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/firewalld/forwarder.go` (ADD: UpstreamPool) | service | request-response | `internal/firewalld/firewalld.go` (atomic.Uint64 counters) | role-match |
| `internal/firewalld/config.go` (ADD: RedirectConfig) | config | — | `internal/firewalld/config.go` ThreatIntelConfig / JunkConfig | exact |
| `internal/firewalld/firewalld.go` (ADD: pool field + wire in New()) | service | request-response | `internal/firewalld/firewalld.go` existing New() + field pattern | exact |
| `internal/firewalld/policy.go` (EDIT: Evaluate() pool fallback + compileRule relaxation) | service | request-response | `internal/firewalld/policy.go` compileRule + Evaluate() | exact |
| `internal/firewalld/starlark.go` (EDIT: redirect builtin) | service | event-driven | `internal/firewalld/starlark.go` existing redirect/rewrite builtins | exact |
| `internal/firewalld/firewalld_test.go` (ADD: UpstreamPool + integration tests) | test | — | `internal/firewalld/firewalld_test.go` existing test patterns | exact |

---

## Pattern Assignments

### `internal/firewalld/forwarder.go` — ADD: UpstreamPool struct + Next() method

**Analog:** `internal/firewalld/firewalld.go` — atomic.Uint64 counter pattern

**Imports pattern** (`forwarder.go` lines 1-9 — already present; add `sync/atomic` and `fmt`):
```go
package firewalld

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)
```

**Atomic counter pattern to copy** (`firewalld.go` lines 98-103):
```go
// counters
totalQueries   atomic.Uint64
totalBlocked   atomic.Uint64
totalNXDomain  atomic.Uint64
totalDropped   atomic.Uint64
totalRedirected atomic.Uint64
```

**Core UpstreamPool pattern** (new code modeled on codebase atomic usage):
```go
// UpstreamPool selects among configured upstream DNS addresses using
// atomic round-robin. Safe for concurrent use without locks.
type UpstreamPool struct {
	upstreams []string
	counter   atomic.Uint64
}

func newUpstreamPool(upstreams []string) *UpstreamPool {
	return &UpstreamPool{upstreams: upstreams}
}

// Next returns the next upstream address via round-robin.
// Returns ("", error) when the pool is empty (D-13: caller returns SERVFAIL).
func (p *UpstreamPool) Next() (string, error) {
	if len(p.upstreams) == 0 {
		return "", fmt.Errorf("upstream pool is empty — configure firewall.redirect.upstreams")
	}
	idx := (p.counter.Add(1) - 1) % uint64(len(p.upstreams))
	return p.upstreams[idx], nil
}
```

**Error return pattern to copy** (`forwarder.go` lines 44-46):
```go
if err != nil {
    return nil, fmt.Errorf("forward to %s: %w", server, err)
}
```

---

### `internal/firewalld/config.go` — ADD: RedirectConfig struct + Redirect field on Config

**Analog:** `internal/firewalld/config.go` — ThreatIntelConfig / JunkConfig pattern

**Nested config struct pattern** (`config.go` lines 72-107 and 117-129):
```go
// ThreatIntelConfig controls threat scoring behaviour.
type ThreatIntelConfig struct {
	BlockThreshold int    `yaml:"block_threshold"`
	// ... fields with yaml tags ...
	FeedURL      string        `yaml:"feed_url"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// JunkConfig controls junk/bogus query detection.
type JunkConfig struct {
	BlockDGA            bool    `yaml:"block_dga"`
	BlockDataExfil      bool    `yaml:"block_data_exfil"`
	BlockRandomSubdomain bool   `yaml:"block_random_subdomain"`
	RandomSubdomainThreshold float64 `yaml:"random_subdomain_threshold"`
}
```

**Config struct field pattern** (`config.go` lines 6-27 — how nested structs are declared on Config):
```go
type Config struct {
	Enabled bool `yaml:"enabled"`
	Rules   []RuleConfig          `yaml:"rules"`
	// ...
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`
	Junk        JunkConfig        `yaml:"junk"`
	DefaultAction string          `yaml:"default_action"`
	ScriptTimeout time.Duration   `yaml:"script_timeout"`
}
```

**New RedirectConfig to add** (follows the JunkConfig pattern exactly):
```go
// RedirectConfig holds upstream pool configuration for VerdictRedirect.
type RedirectConfig struct {
	// Upstreams is the list of upstream DNS targets for redirect load balancing.
	// Each entry is "ip:port". At least one entry is required for redirect verdicts
	// that do not have a per-rule redirect_server override.
	Upstreams []string `yaml:"upstreams"`
}
```

Add to `Config` struct:
```go
// Redirect holds upstream pool configuration for VerdictRedirect.
Redirect RedirectConfig `yaml:"redirect"`
```

**DefaultConfig pattern** (`config.go` lines 132-152 — no non-zero default needed for Redirect):
```go
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 80,
			StaticIPScores: make(map[string]int),
			// ...
		},
		Junk: JunkConfig{
			BlockDGA:                 true,
			BlockDataExfil:           true,
			BlockRandomSubdomain:     false,
			RandomSubdomainThreshold: 4.0,
		},
		// Redirect: RedirectConfig{} — zero value is valid; empty pool → SERVFAIL (D-13)
	}
}
```

---

### `internal/firewalld/firewalld.go` — ADD: pool field on Firewall, initialize in New()

**Analog:** `internal/firewalld/firewalld.go` — existing Firewall struct + New() + Redirect()

**Struct field pattern** (`firewalld.go` lines 85-104 — add pool alongside existing fields):
```go
type Firewall struct {
	cfg      Config
	policy   *PolicyEngine
	junk     *JunkDetector
	intel    *ThreatIntel
	starlark *StarlarkEngine
	forwarder *Forwarder
	metrics  *Metrics
	logger   zerolog.Logger
	// ADD:
	pool     *UpstreamPool

	mu      sync.RWMutex
	enabled atomic.Bool

	// counters
	totalQueries    atomic.Uint64
	totalRedirected atomic.Uint64
	// ...
}
```

**New() initialization pattern** (`firewalld.go` lines 108-161 — insert pool init after existing engine construction):
```go
func New(cfg Config) (*Firewall, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	// ... existing engine construction ...

	// Initialize upstream pool (D-10).
	pool := newUpstreamPool(cfg.Redirect.Upstreams)

	fw := &Firewall{
		cfg:       cfg,
		policy:    policy,
		junk:      junk,
		intel:     intel,
		starlark:  starlark,
		forwarder: NewForwarder(cfg.ScriptTimeout * 1500),
		metrics:   metrics,
		logger:    log.With().Str("component", "firewalld").Logger(),
		pool:      pool,  // ADD
	}
	// Wire pool into starlark engine (A1: post-construction setter).
	se.pool = pool   // ADD — after fw struct literal

	fw.enabled.Store(true)
	// ...
}
```

**Error handling in New() pattern** (`firewalld.go` lines 122-125):
```go
policy, err := newPolicyEngine(cfg.Rules)
if err != nil {
    return nil, fmt.Errorf("firewalld: build policy engine: %w", err)
}
```

**Redirect + SERVFAIL pattern** (`firewalld.go` lines 257-268 — Redirect() unchanged; pool-empty SERVFAIL follows same response shape):
```go
func (fw *Firewall) Redirect(r *dns.Msg, d *Decision) *dns.Msg {
	resp, err := fw.forwarder.Forward(r, d.Server)
	if err != nil {
		fw.logger.Warn().Str("server", d.Server).Err(err).Msg("redirect forward failed")
		fail := new(dns.Msg)
		fail.SetReply(r)
		fail.Rcode = dns.RcodeServerFailure
		return fail
	}
	fw.totalRedirected.Add(1)
	return resp
}
```

**Pool-empty SERVFAIL in Check() pattern** (new code modeled on Redirect() SERVFAIL shape + D-13):
```go
// In Check(), after fw.policy.Evaluate(qctx) returns VerdictRedirect:
if d.Verdict == VerdictRedirect && d.Server == "" {
    server, err := fw.pool.Next()
    if err != nil {
        fw.logger.Error().Err(err).Msg("redirect pool empty — returning SERVFAIL")
        fail := new(dns.Msg)
        fail.SetReply(r)
        fail.Rcode = dns.RcodeServerFailure
        // return inline SERVFAIL; caller sees non-nil response
        return &Decision{Verdict: VerdictDrop, Reason: "pool empty"}
    }
    d.Server = server
}
```

**zerolog structured log pattern** (`firewalld.go` lines 329-336):
```go
fw.logger.Debug().
    Str("name", qctx.Name).
    Str("client", qctx.ClientIP.String()).
    Str("verdict", d.Verdict.String()).
    Str("rule", d.RuleName).
    Str("reason", d.Reason).
    Msg("firewall decision")
```

---

### `internal/firewalld/policy.go` — EDIT: compileRule + Evaluate()

**Analog:** `internal/firewalld/policy.go` — existing compileRule redirect case + Evaluate()

**compileRule redirect case to relax** (`policy.go` lines 70-74 — remove hard error for empty RedirectServer):
```go
// CURRENT (remove this guard):
case "redirect":
    if r.RedirectServer == "" {
        return cr, fmt.Errorf("redirect action requires redirect_server")
    }
    cr.verdict = VerdictRedirect

// NEW (allow empty RedirectServer; pool is the fallback):
case "redirect":
    cr.verdict = VerdictRedirect
    // redirect_server may be empty; pool.Next() provides the target at runtime (D-07)
```

**Evaluate() Decision return pattern** (`policy.go` lines 84-98 — Server field already set from RedirectServer; pool fallback happens in Check()):
```go
func (pe *PolicyEngine) Evaluate(qctx *QueryContext) *Decision {
	for i := range pe.rules {
		cr := &pe.rules[i]
		if cr.matches(qctx) {
			return &Decision{
				Verdict:  cr.verdict,
				Target:   cr.cfg.RewriteTarget,
				Server:   cr.cfg.RedirectServer, // "" when no per-rule override; pool fills it in Check()
				Reason:   fmt.Sprintf("static rule %q matched", cr.cfg.Name),
				RuleName: cr.cfg.Name,
			}
		}
	}
	return allow()
}
```

**PolicyEngine struct pattern** (`policy.go` lines 12-15 — no pool field added here; pool call moves to Check()):
```go
type PolicyEngine struct {
	rules []compiledRule
}
```

**newPolicyEngine validation pattern** (`policy.go` lines 24-34 — model New()-level validation for redirect+empty pool on same pattern):
```go
func newPolicyEngine(rules []RuleConfig) (*PolicyEngine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		compiled = append(compiled, cr)
	}
	return &PolicyEngine{rules: compiled}, nil
}
```

---

### `internal/firewalld/starlark.go` — EDIT: redirect builtin (remove server=, add hard error, call pool.Next())

**Analog:** `internal/firewalld/starlark.go` — existing redirect + rewrite builtins

**StarlarkEngine struct pattern** (`starlark.go` lines 33-37 — add pool field alongside timeout):
```go
type StarlarkEngine struct {
	mu      sync.RWMutex
	scripts map[string]*compiledScript
	timeout time.Duration
	// ADD:
	pool    *UpstreamPool
}
```

**Builtin with reason= kwarg pattern** (`starlark.go` lines 219-230 — nxdomain/drop as template for the new redirect):
```go
"nxdomain": starlark.NewBuiltin("firewall.nxdomain", func(
    _ *starlark.Thread, _ *starlark.Builtin,
    args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
    reason := "starlark policy"
    var reasonStr starlark.String
    if err := starlark.UnpackArgs("firewall.nxdomain", args, kwargs,
        "reason?", &reasonStr); err == nil && reasonStr != "" {
        reason = string(reasonStr)
    }
    sink.set(&Decision{Verdict: VerdictNXDomain, Reason: reason})
    return starlark.None, nil
}),
```

**Builtin with required kwarg pattern** (`starlark.go` lines 233-251 — rewrite builtin as template for kwarg detection loop):
```go
"rewrite": starlark.NewBuiltin("firewall.rewrite", func(
    _ *starlark.Thread, _ *starlark.Builtin,
    args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
    var target, reason starlark.String
    if err := starlark.UnpackArgs("firewall.rewrite", args, kwargs,
        "target", &target, "reason?", &reason); err != nil {
        return nil, err
    }
    if string(target) == "" {
        return nil, fmt.Errorf("firewall.rewrite: target must not be empty")
    }
    r := "starlark policy"
    if string(reason) != "" {
        r = string(reason)
    }
    sink.set(&Decision{Verdict: VerdictRewrite, Target: string(target), Reason: r})
    return starlark.None, nil
}),
```

**Current redirect builtin to replace** (`starlark.go` lines 253-271):
```go
// CURRENT — replace entirely:
"redirect": starlark.NewBuiltin("firewall.redirect", func(
    _ *starlark.Thread, _ *starlark.Builtin,
    args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
    var server, reason starlark.String
    if err := starlark.UnpackArgs("firewall.redirect", args, kwargs,
        "server", &server, "reason?", &reason); err != nil {
        return nil, err
    }
    if string(server) == "" {
        return nil, fmt.Errorf("firewall.redirect: server must not be empty")
    }
    r := "starlark policy"
    if string(reason) != "" {
        r = string(reason)
    }
    sink.set(&Decision{Verdict: VerdictRedirect, Server: string(server), Reason: r})
    return starlark.None, nil
}),
```

**New redirect builtin** (D-01/D-02/D-03/D-04 — modeled on nxdomain pattern + kwarg detection from rewrite):
```go
// NEW:
"redirect": starlark.NewBuiltin("firewall.redirect", func(
    _ *starlark.Thread, _ *starlark.Builtin,
    args starlark.Tuple, kwargs []starlark.Tuple,
) (starlark.Value, error) {
    // D-02: hard error if caller passes server=
    for _, kv := range kwargs {
        if string(kv[0].(starlark.String)) == "server" {
            return nil, fmt.Errorf("firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams")
        }
    }
    var reason starlark.String
    if err := starlark.UnpackArgs("firewall.redirect", args, kwargs,
        "reason?", &reason); err != nil {
        return nil, err
    }
    // D-04: pool.Next() populates Server on Decision
    server, err := se.pool.Next()
    if err != nil {
        return nil, fmt.Errorf("firewall.redirect: %w", err)
    }
    r := "starlark policy"
    if string(reason) != "" {
        r = string(reason)
    }
    sink.set(&Decision{Verdict: VerdictRedirect, Server: server, Reason: r})
    return starlark.None, nil
}),
```

**decisionSink pattern** (`starlark.go` lines 174-184 — unchanged, shown for reference):
```go
type decisionSink struct {
	mu sync.Mutex
	d  *Decision
}

func (ds *decisionSink) set(d *Decision) {
	ds.mu.Lock()
	ds.d = d
	ds.mu.Unlock()
}
```

---

### `internal/firewalld/firewalld_test.go` — ADD: UpstreamPool unit tests + REDIR integration tests

**Analog:** `internal/firewalld/firewalld_test.go` — existing test patterns

**Test file header pattern** (`firewalld_test.go` lines 1-11):
```go
package firewalld

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

**makeQuery helper pattern** (`firewalld_test.go` lines 14-18 — use existing helper, do not add a new one):
```go
func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}
```

**Table-driven unit test pattern** (`firewalld_test.go` lines 39-74):
```go
func TestJunkDetector_DGA(t *testing.T) {
	jd := newJunkDetector(JunkConfig{BlockDGA: true, RandomSubdomainThreshold: 4.0})
	tests := []struct {
		name    string
		domain  string
		wantDGA bool
	}{
		{"legit short", "google.com", false},
		{"dga-like", "qzxmvpkblrtnfjsghdye.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ...
			assert.Equal(t, VerdictNXDomain, d.Verdict, ...)
		})
	}
}
```

**Config struct literal test pattern** (`firewalld_test.go` lines 175-213 — inline Config{}, no helper function):
```go
func TestPolicyEngine_StaticRules(t *testing.T) {
	rules := []RuleConfig{
		{
			Name:   "block-bad-tld",
			Match:  MatchConfig{DomainSuffix: ".bad."},
			Action: "nxdomain",
		},
		{
			Name:          "rewrite-test",
			Match:         MatchConfig{DomainSuffix: ".rewrite."},
			Action:        "rewrite",
			RewriteTarget: "sink.example.com.",
		},
	}
	pe, err := newPolicyEngine(rules)
	require.NoError(t, err)
	// ...
	qctx := &QueryContext{Name: "anything.bad.", ClientIP: localhost}
	d := pe.Evaluate(qctx)
	assert.Equal(t, VerdictNXDomain, d.Verdict)
}
```

**Error assertion pattern** (`firewalld_test.go` lines 216-219):
```go
func TestPolicyEngine_InvalidRule(t *testing.T) {
	_, err := newPolicyEngine([]RuleConfig{
		{Name: "bad", Match: MatchConfig{}, Action: "rewrite"},
	})
	// assert.Error(t, err)
```

**New UpstreamPool tests to add** (modeled on existing single-component test style):
```go
func TestUpstreamPool_RoundRobin(t *testing.T) {
	p := newUpstreamPool([]string{"1.1.1.1:53", "2.2.2.2:53"})
	got0, err := p.Next()
	require.NoError(t, err)
	got1, err := p.Next()
	require.NoError(t, err)
	assert.NotEqual(t, got0, got1, "round-robin should alternate")
	got2, err := p.Next()
	require.NoError(t, err)
	assert.Equal(t, got0, got2, "should wrap around to first upstream")
}

func TestUpstreamPool_Empty(t *testing.T) {
	p := newUpstreamPool(nil)
	_, err := p.Next()
	assert.Error(t, err)
}

func TestUpstreamPool_SingleUpstream(t *testing.T) {
	p := newUpstreamPool([]string{"9.9.9.9:53"})
	for i := 0; i < 5; i++ {
		got, err := p.Next()
		require.NoError(t, err)
		assert.Equal(t, "9.9.9.9:53", got)
	}
}
```

---

## Shared Patterns

### Atomic counter pattern
**Source:** `internal/firewalld/firewalld.go` lines 98-103
**Apply to:** `UpstreamPool` struct in `forwarder.go`
```go
totalQueries   atomic.Uint64
// Pattern: field of type atomic.Uint64, incremented with .Add(1), read with .Load()
// For UpstreamPool: counter atomic.Uint64 — use .Add(1) in Next(), no mutex needed
```

### Error wrapping pattern
**Source:** `internal/firewalld/forwarder.go` lines 44-46; `firewalld.go` lines 122-125
**Apply to:** `UpstreamPool.Next()`, pool-empty SERVFAIL in `Check()`
```go
return nil, fmt.Errorf("forward to %s: %w", server, err)
return nil, fmt.Errorf("firewalld: build policy engine: %w", err)
```

### zerolog structured error log pattern
**Source:** `internal/firewalld/firewalld.go` lines 260-261
**Apply to:** Pool-empty error log in `Check()` (D-13: log at error level)
```go
fw.logger.Warn().Str("server", d.Server).Err(err).Msg("redirect forward failed")
// For pool-empty: fw.logger.Error().Err(err).Msg("redirect pool empty — returning SERVFAIL")
```

### SERVFAIL response construction
**Source:** `internal/firewalld/firewalld.go` lines 261-264
**Apply to:** Pool-empty SERVFAIL path in `Check()`
```go
fail := new(dns.Msg)
fail.SetReply(r)
fail.Rcode = dns.RcodeServerFailure
return fail
```

### Starlark kwarg detection pattern
**Source:** `internal/firewalld/starlark.go` lines 233-251 (rewrite builtin — UnpackArgs with required kwarg)
**Apply to:** New `redirect` builtin kwarg detection loop (iterate kwargs, check key name)

### Config yaml tag pattern
**Source:** `internal/firewalld/config.go` lines 29-46
**Apply to:** `RedirectConfig` struct fields
```go
RedirectServer string `yaml:"redirect_server"`
Upstreams      []string `yaml:"upstreams"`
```

---

## No Analog Found

All files in scope have close analogs in the codebase. No entries in this section.

---

## Key Design Decisions Captured

### D-02 hard error approach
The kwargs loop must run before `starlark.UnpackArgs` — if `UnpackArgs` runs first with only `reason?`, it will silently ignore `server=` rather than erroring. The kwarg scan must be the first thing in the builtin body.

### D-07 per-rule override bypass
`policy.Evaluate()` already returns `Server: cr.cfg.RedirectServer` — when that is non-empty it bypasses the pool. The pool path in `Check()` is guarded by `d.Server == ""`. No change needed to `Evaluate()` logic beyond relaxing `compileRule`.

### Pool threading approach (A1 / A2)
Pool reference to `StarlarkEngine` via post-construction setter (`se.pool = pool`) in `New()` — keeps `newStarlarkEngine` signature stable. Pool call for static rule path moves to `Check()` (not threaded into `PolicyEngine`) — centralizes "ensure Decision.Server is populated" in one place.

### compileRule validation relaxation (Pitfall 1)
Remove the `redirect_server != ""` guard from `compileRule`. Add validation in `New()` (after building the pool) to catch the misconfiguration: if any rule has `action: redirect` and `redirect_server == ""` and `cfg.Redirect.Upstreams` is empty, return an error from `New()`.

---

## Metadata

**Analog search scope:** `internal/firewalld/` (all 9 files read)
**Files scanned:** `forwarder.go`, `firewalld.go`, `config.go`, `policy.go`, `starlark.go`, `edns0.go`, `firewalld_test.go`
**Pattern extraction date:** 2026-04-23
