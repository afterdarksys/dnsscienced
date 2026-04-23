# Phase 4: EDNS0 CustomerID — Pattern Map

**Mapped:** 2026-04-23
**Files analyzed:** 3 (1 new, 2 modified)
**Analogs found:** 3 / 3

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/firewalld/edns0.go` | utility | transform | `internal/server/server.go` lines 448–460 | role-match (same EDNS0 iteration idiom, different type assertion) |
| `internal/firewalld/firewalld.go` | service | request-response | self (existing `Check()` at lines 164–194) | self-modification — insertion point is line 181 |
| `internal/firewalld/firewalld_test.go` | test | — | self (existing `makeQuery` helper at lines 12–17) | self-modification — extend with new helper + test cases |

---

## Pattern Assignments

### `internal/firewalld/edns0.go` (utility, transform)

**Analog:** `internal/server/server.go` lines 448–460

**Imports pattern** — copy from `internal/firewalld/firewalld.go` lines 17–27:

```go
import (
    "github.com/miekg/dns"
    "github.com/rs/zerolog"
)
```

No additional imports needed — both packages are already in the module and imported by the rest of the `firewalld` package.

**Core EDNS0 iteration pattern** (`internal/server/server.go` lines 448–460):

```go
opt := r.IsEdns0()
if opt != nil {
    for _, option := range opt.Option {
        if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
            copy(clientCookie[:], cookie.Cookie[:8])
            if len(cookie.Cookie) >= 16 {
                copy(serverCookie[:], cookie.Cookie[8:16])
            }
            break
        }
    }
}
```

**Adaptation for `extractCustomerID`:** Replace `*dns.EDNS0_COOKIE` with `*dns.EDNS0_LOCAL`, add `.Code` check, add 64-byte length guard, and remove `break` (use `continue` to guard against early exit on wrong code). Full form:

```go
// edns0CustomerIDCode is the private-use EDNS0 option code carrying the
// customer identifier. RFC 6891 §6.1.3.1 reserves codes 65000–65534 for
// private use / local experimentation.
// Note: dns.EDNS0LOCALSTART = 0xFDE9 (65001); this code is 0xFDE8 (65000).
const edns0CustomerIDCode uint16 = 65000

// edns0MaxCustomerIDLen is the maximum accepted payload size in bytes.
const edns0MaxCustomerIDLen = 64

func extractCustomerID(r *dns.Msg, logger zerolog.Logger) string {
    opt := r.IsEdns0()
    if opt == nil {
        return ""
    }
    for _, option := range opt.Option {
        local, ok := option.(*dns.EDNS0_LOCAL)
        if !ok || local.Code != edns0CustomerIDCode {
            continue
        }
        if len(local.Data) > edns0MaxCustomerIDLen {
            logger.Debug().
                Int("len", len(local.Data)).
                Msg("edns0 customer_id payload too large, ignoring")
            return ""
        }
        return string(local.Data)
    }
    return ""
}
```

**Key differences from the server.go cookie pattern:**
- Type assertion: `*dns.EDNS0_LOCAL` (not `*dns.EDNS0_COOKIE`) — all unregistered codes arrive as `EDNS0_LOCAL` via the miekg/dns factory's `default` branch
- Must check `.Code == edns0CustomerIDCode` after the type assertion — unlike cookies, multiple `EDNS0_LOCAL` options with different codes may coexist
- No `break` on non-matching type assertions; use `continue` to skip wrong codes
- Add 64-byte length guard before converting to string

**Logging pattern** — copy from `internal/firewalld/firewalld.go` zerolog usage (line 154–158):

```go
fw.logger.Info().
    Int("static_rules", len(cfg.Rules)).
    Msg("DNS firewall started")

// Debug variant for oversized payload:
logger.Debug().
    Int("len", len(local.Data)).
    Msg("edns0 customer_id payload too large, ignoring")
```

---

### `internal/firewalld/firewalld.go` (service, request-response — MODIFY)

**Insertion point:** line 181 — immediately after the `qctx` struct literal, before the `// 1. Static policy rules.` comment.

**Existing `qctx` construction** (`internal/firewalld/firewalld.go` lines 174–180):

```go
q := r.Question[0]
qctx := &QueryContext{
    Msg:      r,
    ClientIP: clientIP,
    Name:     strings.ToLower(q.Name),
    Qtype:    q.Qtype,
}
```

**Single line to insert at line 181** (between the struct literal closing brace and `// 1. Static policy rules.`):

```go
qctx.CustomerID = extractCustomerID(r, fw.logger)
```

**`QueryContext.CustomerID` field** (firewalld.go lines 80–81) — already exists, no change:

```go
// CustomerID is populated from EDNS0 or server-side mapping.
CustomerID string
```

**`Firewall` struct logger field** (firewalld.go line 93) — `fw.logger` is a `zerolog.Logger` value, pass by value to `extractCustomerID`:

```go
logger   zerolog.Logger
```

No import additions needed — `github.com/miekg/dns` and `github.com/rs/zerolog` are already in the import block (firewalld.go lines 17–27).

---

### `internal/firewalld/firewalld_test.go` (test — MODIFY)

**Existing test package declaration and imports** (firewalld_test.go lines 1–10):

```go
package firewalld

import (
    "net"
    "testing"

    "github.com/miekg/dns"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)
```

**Existing `makeQuery` helper to extend** (firewalld_test.go lines 12–17):

```go
func makeQuery(name string, qtype uint16) *dns.Msg {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), qtype)
    return m
}
```

**New `makeQueryWithCustomerID` helper — append after `makeQuery`:**

```go
func makeQueryWithCustomerID(name string, qtype uint16, customerID string) *dns.Msg {
    m := makeQuery(name, qtype)
    opt := new(dns.OPT)
    opt.Hdr.Name = "."
    opt.Hdr.Rrtype = dns.TypeOPT
    opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
        Code: edns0CustomerIDCode,
        Data: []byte(customerID),
    })
    m.Extra = append(m.Extra, opt)
    return m
}
```

**Existing test table pattern** (firewalld_test.go lines 23–57) — use this structure for `TestExtractCustomerID`:

```go
tests := []struct {
    name       string
    // ...fields...
    wantResult string
}{
    {"present", ...},
    {"no opt record", ...},
    {"wrong code", ...},
    {"oversized payload", ...},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // ...
        assert.Equal(t, tt.wantResult, got)
    })
}
```

**Test cases required** (from RESEARCH.md validation map):

| Test Name | Scenario | Expected |
|-----------|----------|----------|
| `TestExtractCustomerID_Present` | OPT with code 65000, payload "cust-abc" | `"cust-abc"` |
| `TestExtractCustomerID_NoOPT` | No OPT record in message | `""` |
| `TestExtractCustomerID_WrongCode` | OPT with code 65001 only | `""` |
| `TestExtractCustomerID_Oversized` | OPT with code 65000, payload 65 bytes | `""` |
| `TestFirewall_CustomerIDExtracted` | `Firewall.Check()` with EDNS0 option — verify `qctx.CustomerID` visible to Starlark or ThreatIntel | populated before evaluation |
| `TestFirewall_NoCustomerID_Allowed` | `Firewall.Check()` with no EDNS0 — normal query proceeds | `VerdictAllow` |

---

## Shared Patterns

### Zerolog Debug Logging
**Source:** `internal/firewalld/firewalld.go` lines 154–158 (Info example); same style for Debug
**Apply to:** `extractCustomerID` in `edns0.go` for oversized-payload path

```go
logger.Debug().
    Int("len", len(local.Data)).
    Msg("edns0 customer_id payload too large, ignoring")
```

### EDNS0 Nil Guard
**Source:** `internal/server/server.go` lines 448–449
**Apply to:** `extractCustomerID` — first statement after call to `r.IsEdns0()`

```go
opt := r.IsEdns0()
if opt == nil {
    return ""
}
```

### Package-Internal Test Style
**Source:** `internal/firewalld/firewalld_test.go` lines 1–10
**Apply to:** All new tests — same `package firewalld` declaration (not `firewalld_test`), same imports (`testing`, `github.com/miekg/dns`, `testify/assert`, `testify/require`)

---

## No Analog Found

None — all three files have direct codebase analogs or are self-modifications.

---

## Metadata

**Analog search scope:** `internal/firewalld/`, `internal/server/`
**Files read:** `internal/server/server.go` (lines 440–470), `internal/firewalld/firewalld.go` (lines 1–194), `internal/firewalld/firewalld_test.go` (lines 1–60)
**Pattern extraction date:** 2026-04-23
