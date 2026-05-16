# Phase 8: RFC 9859 — Generalized DNS Notifications (DSYNC) - Research

**Researched:** 2026-05-16
**Domain:** DNS protocol extension — RFC 9859 DSYNC record type, NOTIFY opcode handling, delegation maintenance
**Confidence:** HIGH (RFC verified, miekg/dns source verified, codebase read)

---

## Summary

RFC 9859 defines "Generalized DNS Notifications" — a mechanism by which child zones signal
their parent zones when CDS/CDNSKEY/CSYNC records change, enabling faster delegation
maintenance (DS record updates, NS changes). The protocol introduces DSYNC, a new RR type
(number 66), and extends the existing DNS NOTIFY opcode (RFC 1996) to carry qtypes other
than SOA.

**miekg/dns v1.1.72 does not include `TypeDSYNC` or a native `DSYNC` struct.** This is
confirmed by direct inspection of the installed module. Type 66 must be implemented as a
custom type using `dns.RFC3597` for wire encoding and a hand-written struct that satisfies
`dns.RR` for structured use within the daemon. The existing `parseGenericTypes` facility in
`internal/zone/parser_dnszone.go` already handles `TYPE66` in `.dnszone` YAML files via the
`Generic map[string]interface{}` inline field. The BIND zone parser inherits RFC 3597
fallback automatically via `dns.NewZoneParser`.

The NOTIFY opcode (value 4) is already accepted by miekg/dns's `DefaultMsgAcceptFunc` —
no changes to the miekg server setup are needed for the server to receive NOTIFY packets.
What is missing is a branch in `handleDNS` that detects `r.Opcode == dns.OpcodeNotify` and
dispatches to a new DSYNC inbound handler instead of treating the message as a query.

**Primary recommendation:** Implement in a new `internal/dsync/` package: (1) a `DSYNC` RR
type backed by `dns.RFC3597` wire format, (2) an inbound NOTIFY handler that branches off
`handleDNS`, (3) a per-source-IP token-bucket rate limiter using the already-imported
`golang.org/x/time/rate`, and (4) an outbound sender that discovers `_dsync.<parent>`
and fires a NOTIFY with the appropriate qtype.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| DSYNC record type (parse/serialize) | DNS Protocol Layer (`internal/dsync`) | Zone loader (`internal/zone`) | Record type is protocol-level; zone loader calls into it |
| Zone file support (BIND + dnszone) | Zone loader (`internal/zone`) | `internal/dsync` | Zone parsers need to know type 66 to serve it correctly |
| Inbound NOTIFY handler | DNS Server (`internal/server`) | `internal/dsync` | `handleDNS` dispatches; dsync package implements logic |
| Rate limiting (NOTIFY) | `internal/dsync` (new per-source limiter) | — | Separate concern from RRL (which limits response volume) |
| Outbound NOTIFY sender | `internal/dsync` | DNS client (miekg `dns.Client`) | Discovery + send encapsulated in dsync package |
| _dsync lookup (discovery) | `internal/dsync` | Recursive resolver | Standard DNS query over loopback or resolver |
| DNSSEC signing of zones | `internal/zone` / DNSSEC subsystem | — | Already wired in `ZoneDNSSECConfig`; no new infra needed |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| github.com/miekg/dns | v1.1.72 (already in go.mod) | Wire encode/decode, OpcodeNotify, dns.Client for sending NOTIFY, RFC3597 fallback | Project's DNS library — all DNS protocol work goes here |
| golang.org/x/time/rate | v0.14.0 (already in go.mod) | Token-bucket rate limiter for per-source-IP NOTIFY limiting | Already imported; RFC 9859 §5 MUST rate limit |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| sync.Map / sync.RWMutex | stdlib | Concurrency-safe state for rate limiter visitor map and pending NOTIFY dedup | Any shared state in dsync handler |
| context + time | stdlib | Timeouts on outbound NOTIFY exchanges | Outbound sender goroutines |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Custom dns.RR DSYNC struct | Pure dns.RFC3597 at all layers | RFC3597 is correct for on-wire; a typed struct improves handler ergonomics; use typed internally, RFC3597 for wire |
| golang.org/x/time/rate per-source | Custom sliding window | x/time/rate is already a dependency and thread-safe; no reason to hand-roll |

**Installation:** No new dependencies required. Both `github.com/miekg/dns` and `golang.org/x/time` are already in `go.mod`.

---

## RFC 9859 Wire Format (VERIFIED)

[VERIFIED: rfc-editor.org/rfc/rfc9859]

### DSYNC RDATA Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            RRtype             |    Scheme     |      Port (hi)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Port (lo)    |            Target (domain name, variable)...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields in order:
- **RRtype** (uint16, 2 bytes): Which delegation record type triggers this endpoint. Currently `CDS` (59) or `CSYNC` (62). Note: CDS type code is 59, NOT 60. CDNSKEY is 60.
- **Scheme** (uint8, 1 byte): Contact method. Value `1` = NOTIFY (RFC 1996). Value `0` = null (ignore). Values 128-255 = private use.
- **Port** (uint16, 2 bytes): Destination port for the NOTIFY message. Standard 53.
- **Target** (variable): Fully-qualified domain name of the notification endpoint. Wire-encoded as compressed or uncompressed domain name per RFC 1035.

**Presentation format example:**
```
_dsync.example.com. 3600 IN DSYNC CDS NOTIFY 5359 cds-scanner.example.net.
_dsync.example.com. 3600 IN DSYNC CSYNC NOTIFY 53 csync-scanner.example.net.
```

**Total minimum RDATA length:** 5 bytes (2+1+2) + root label (1 byte) = 6 bytes minimum.

**Important:** Receivers MUST ignore DSYNC records with Scheme=0 or Port=0.

### Type Number Confirmed

DSYNC = **type 66** [VERIFIED: rfc-editor.org/rfc/rfc9859, IANA DNS parameters registry]

**miekg/dns v1.1.72 does NOT define `TypeDSYNC` or a `DSYNC` struct.** The value 66 is
unregistered in the library. Type 65 is `TypeHTTPS`, type 63 is `TypeZONEMD`. The slot at
66 is vacant. [VERIFIED: direct grep of installed module source]

---

## miekg/dns Integration Details (VERIFIED)

[VERIFIED: direct grep of /Users/ryan/go/pkg/mod/github.com/miekg/dns@v1.1.72/]

### Key Constants

```go
dns.OpcodeNotify   = 4       // NOTIFY opcode
dns.TypeCDS        = 59      // CDS record type (NOTE: phase description says 60, that is wrong; 60 = TypeCDNSKEY)
dns.TypeCDNSKEY    = 60      // CDNSKEY record type
dns.TypeCSYNC      = 62      // CSYNC record type
// TypeDSYNC does NOT exist — define it:
const TypeDSYNC uint16 = 66
```

### NOTIFY Message Acceptance

`dns.DefaultMsgAcceptFunc` already accepts `OpcodeNotify` packets. The server handler
`handleDNS` currently does NOT branch on opcode — it falls through to `handleAuthoritative`
and `s.recursive.Resolve` which are both wrong for NOTIFY messages. A branch MUST be added
at the top of `handleDNS`:

```go
// Source: verified from server.go handleDNS structure
if r.Opcode == dns.OpcodeNotify {
    s.handleInboundNotify(w, r, clientIP)
    return
}
```

### Sending a NOTIFY Message (outbound)

```go
// Source: miekg/dns defaults.go SetNotify + types.go
m := new(dns.Msg)
// SetNotify sets Opcode=OpcodeNotify, AA=true, Question[0]={zone, TypeSOA, ClassINET}
// For DSYNC we override the Qtype after calling SetNotify:
m.SetNotify(zoneName)
m.Question[0].Qtype = dns.TypeCDS  // or dns.TypeCSYNC

c := new(dns.Client)
c.Net = "udp"
resp, _, err := c.Exchange(m, net.JoinHostPort(targetIP, port))
```

### RFC3597 for DSYNC Wire Encoding

For inbound DSYNC records received over the wire (in answer sections of _dsync lookups),
miekg/dns will decode them as `*dns.RFC3597` since type 66 is unknown. The handler must
cast and decode manually:

```go
// Decode RFC3597 Rdata (hex string) into DSYNC fields
rr, ok := answer.(*dns.RFC3597)
if !ok || rr.Hdr.Rrtype != TypeDSYNC { continue }
rdata, _ := hex.DecodeString(rr.Rdata)
// rdata[0:2] = RRtype (big-endian uint16)
// rdata[2]   = Scheme (uint8)
// rdata[3:5] = Port (big-endian uint16)
// rdata[5:]  = Target (wire-format domain name)
```

### Zone File Serving (DSYNC records in zone files)

The BIND zone parser (`dns.NewZoneParser`) already handles `TYPE66` via RFC 3597 fallback
(`scan.go:654 rr = &RFC3597{Hdr: *h}`). Zone files can contain:
```
_dsync.example.com. 3600 IN TYPE66 \# 10 003B 01 0035 076578616D706C6503636F6D00
```
The dnszone YAML parser also handles it via the `Generic map[string]interface{}` inline
field (already in `RecordSection`):
```yaml
_dsync:
  TYPE66: "\\# 10 003B 01 0035 076578616D706C6503636F6D00"
```

For the dnszone format, it would be much more ergonomic to add a `DSYNC` field to
`RecordSection` with a custom parse function, following the pattern of other typed records
in `parser_dnszone.go`.

---

## Architecture Patterns

### System Architecture Diagram

```
Child zone CDS/CSYNC change
          |
          v
   ZoneManager.UpdateRecords()
          |
          v
   [Zone serial incremented]
          |
          v
   DSYNCNotifier.OnZoneUpdate(zone)
          |
          v
   _dsync.<parent> DNS lookup (via dns.Client to resolver)
          |
         / \
        /   \
   DSYNC    No record
   found    found → skip
        \
         v
   For each DSYNC RR:
     Scheme=1 (NOTIFY), Port, Target
          |
          v
   Delay until propagation (configurable, default 60s)
          |
          v
   dns.Client.Exchange(NOTIFY(CDS/CSYNC), target:port)
          |
         / \
    NOERROR  Error
      ACK    → log, retry up to N times

────────────────────────────────────────────────

Inbound path (port 53):

Client NOTIFY(CDS) or NOTIFY(CSYNC)
          |
          v
   handleDNS() — opcode check
          |
     r.Opcode == OpcodeNotify?
          |
          v
   handleInboundNotify(w, r, clientIP)
          |
          v
   Rate limit check (per-source-IP token bucket)
          |
         / \
    allowed  exceeded → respond NOERROR + EDE 15 (Blocked), return
        |
        v
   Send NOTIFY acknowledgement (NOERROR, QR=1)
        |
        v
   Schedule delegation check:
     lookup CDS/CDNSKEY/CSYNC for zone in r.Question[0].Name
     (same checks as timer-triggered maintenance)
```

### Recommended Project Structure

```
internal/dsync/
├── dsync.go          # DSYNC RR type definition, encode/decode
├── handler.go        # Inbound NOTIFY handler (handleInboundNotify)
├── ratelimit.go      # Per-source-IP token bucket using x/time/rate
├── sender.go         # Outbound NOTIFY sender + _dsync discovery
├── discovery.go      # _dsync.<parent> lookup algorithm
└── dsync_test.go     # Unit tests for all components
```

### Pattern 1: Custom RR Type via Interface

miekg/dns does not provide DSYNC natively. The correct approach is a typed struct that
implements `dns.RR` by embedding an RFC3597 for wire operations and providing typed field
access:

```go
// Source: miekg/dns types.go pattern (e.g., type CDS struct{ DS })
// internal/dsync/dsync.go

const TypeDSYNC uint16 = 66

// DSYNC implements dns.RR for RFC 9859 DSYNC records.
// Wire encoding uses dns.RFC3597 (hex rdata) because miekg/dns v1.1.72
// has no native DSYNC support.
type DSYNCRecord struct {
    RRtype uint16 // CDS(59) or CSYNC(62)
    Scheme uint8  // 1 = NOTIFY
    Port   uint16
    Target string // FQDN
}

// EncodeDSYNC encodes a DSYNCRecord to wire format for use in dns.RFC3597.Rdata.
func EncodeDSYNC(rec DSYNCRecord) (string, error) {
    buf := make([]byte, 5)
    binary.BigEndian.PutUint16(buf[0:2], rec.RRtype)
    buf[2] = rec.Scheme
    binary.BigEndian.PutUint16(buf[3:5], rec.Port)
    // Encode Target as wire-format domain name
    nameBuf := make([]byte, 255)
    n, err := dns.PackDomainName(rec.Target, nameBuf, 0, nil, false)
    if err != nil {
        return "", err
    }
    buf = append(buf, nameBuf[:n]...)
    return hex.EncodeToString(buf), nil
}

// DecodeDSYNC parses a dns.RFC3597 Rdata hex string into a DSYNCRecord.
func DecodeDSYNC(rdata string) (DSYNCRecord, error) {
    raw, err := hex.DecodeString(rdata)
    if err != nil || len(raw) < 6 {
        return DSYNCRecord{}, fmt.Errorf("invalid DSYNC rdata")
    }
    rec := DSYNCRecord{
        RRtype: binary.BigEndian.Uint16(raw[0:2]),
        Scheme: raw[2],
        Port:   binary.BigEndian.Uint16(raw[3:5]),
    }
    name, _, err := dns.UnpackDomainName(raw, 5)
    if err != nil {
        return DSYNCRecord{}, fmt.Errorf("unpack DSYNC target: %w", err)
    }
    rec.Target = name
    return rec, nil
}
```

### Pattern 2: Inbound NOTIFY Handler

```go
// internal/dsync/handler.go
// Called from server.handleDNS when r.Opcode == dns.OpcodeNotify

func (h *Handler) HandleInbound(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
    if len(r.Question) == 0 {
        replyError(w, r, dns.RcodeFormatError)
        return
    }

    qtype := r.Question[0].Qtype  // CDS(59) or CSYNC(62)
    zone  := r.Question[0].Name

    // Rate limit per source IP (RFC 9859 §5 MUST)
    if !h.limiter.Allow(clientIP) {
        // RFC 9859 §4.3: MAY use EDE code 15 (Blocked)
        reply := new(dns.Msg)
        reply.SetReply(r)
        reply.Rcode = dns.RcodeSuccess  // Acknowledge but don't process
        // Optionally add EDE EDNS option code 15
        w.WriteMsg(reply)
        return
    }

    // Acknowledge immediately (RFC 1996 §3.10)
    reply := new(dns.Msg)
    reply.SetReply(r)
    reply.Rcode = dns.RcodeSuccess
    w.WriteMsg(reply)

    // Schedule delegation check asynchronously
    go h.scheduleDelegationCheck(zone, qtype)
}
```

### Pattern 3: Per-Source Rate Limiter

```go
// internal/dsync/ratelimit.go
// Uses golang.org/x/time/rate (already in go.mod)

type NotifyLimiter struct {
    mu       sync.Mutex
    visitors map[string]*rate.Limiter
    r        rate.Limit
    b        int
}

func NewNotifyLimiter(rps float64, burst int) *NotifyLimiter {
    return &NotifyLimiter{
        visitors: make(map[string]*rate.Limiter),
        r:        rate.Limit(rps),
        b:        burst,
    }
}

func (nl *NotifyLimiter) Allow(ip net.IP) bool {
    key := ip.String()
    nl.mu.Lock()
    lim, ok := nl.visitors[key]
    if !ok {
        lim = rate.NewLimiter(nl.r, nl.b)
        nl.visitors[key] = lim
    }
    nl.mu.Unlock()
    return lim.Allow()
}
```

**Memory management:** Add a background goroutine that sweeps stale entries (last-seen >
10 minutes) using an augmented struct. This is the standard pattern for per-IP limiters.

### Pattern 4: _dsync Discovery Algorithm

[VERIFIED: rfc-editor.org/rfc/rfc9859 §3]

Given a delegation `child.example.com.`, the lookup sequence is:

1. Query `_dsync.child.example.com.` for DSYNC (TYPE66)
2. If NXDOMAIN or NOERROR with no answers: check if there are additional labels to remove.
3. Remove leftmost label(s) to find zone boundary: try `_dsync.example.com.`
4. If still no record: return nil (no endpoint found).
5. Optionally try wildcard `_dsync.example.com.` (parent's catch-all).

```go
// internal/dsync/discovery.go
func DiscoverDSYNC(ctx context.Context, delegation string, client *dns.Client, resolver string) ([]DSYNCRecord, error) {
    // Step 1: try _dsync.<first-label-of-delegation>.<rest>
    labels := dns.SplitDomainName(delegation)
    for i := 0; i < len(labels)-1; i++ {
        candidate := "_dsync." + strings.Join(labels[i:], ".") + "."
        records, err := queryDSYNC(ctx, candidate, client, resolver)
        if err == nil && len(records) > 0 {
            return records, nil
        }
    }
    return nil, nil
}
```

### Anti-Patterns to Avoid

- **Treating NOTIFY like a query:** `handleDNS` currently always tries authoritative then
  recursive resolution. NOTIFY must short-circuit before that path.
- **Blocking the DNS goroutine during delegation check:** The check involves additional DNS
  lookups; always run it in a goroutine. Acknowledge NOTIFY synchronously.
- **Using the existing RRL limiter for NOTIFY rate limiting:** RRL (`internal/rrl`) limits
  response rates (amplification protection). NOTIFY rate limiting is a separate concern:
  it limits *processing* of inbound control plane messages. Use a separate limiter.
- **Sending outbound NOTIFY before zone propagation:** RFC 9859 recommends a propagation
  delay (configurable). The parent would look up CDS/CSYNC and see old data if the child
  sends immediately after serial increment.
- **Using SetNotify() directly for CDS/CSYNC NOTIFY:** `dns.SetNotify()` hardcodes
  `Question[0].Qtype = TypeSOA`. Override `Qtype` after calling `SetNotify`:
  `m.Question[0].Qtype = dns.TypeCDS`

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token bucket rate limiting | Custom sliding window or leaky bucket | `golang.org/x/time/rate.Limiter` | Thread-safe, already imported, standard Go pattern |
| DNS wire encoding for DSYNC target field | Custom domain name encoder | `dns.PackDomainName` / `dns.UnpackDomainName` | Handles compression, length validation |
| Sending DNS queries for _dsync discovery | Raw UDP socket | `dns.Client.Exchange` | Retries, timeout, TCP fallback |
| NOTIFY message construction | Manual bit manipulation | `dns.Msg.SetNotify()` + Qtype override | Handles ID, AA bit, opcode correctly |

**Key insight:** The tricky domain is the RDATA codec. `dns.PackDomainName`/`dns.UnpackDomainName`
handle the variable-length domain name field correctly. Everything else is fixed-width and
straightforward with `encoding/binary`.

---

## Common Pitfalls

### Pitfall 1: TypeCDS Value Error in Phase Description
**What goes wrong:** Phase description says "qtype=CDS (type 60)" — this is wrong. CDS is
type **59**. Type 60 is CDNSKEY.
**Why it happens:** Off-by-one confusion; CDS and CDNSKEY were allocated together (RFC 7344).
**How to avoid:** Use `dns.TypeCDS` (59) and `dns.TypeCSYNC` (62) constants from miekg/dns.
Check: `grep "TypeCDS\|TypeCDNSKEY" $(go env GOPATH)/pkg/mod/github.com/miekg/dns@v1.1.72/types.go`
**Warning signs:** NOTIFY handler not triggering for inbound CDS notifications; wrong qtype in outbound NOTIFYs.

### Pitfall 2: NOTIFY Not Branching Before Authoritative Lookup
**What goes wrong:** `handleDNS` currently has no `r.Opcode` check. A NOTIFY message would
fall through to `handleAuthoritative` which would treat `r.Question[0]` as a query. The
server might return the zone's SOA record (since NOTIFY carries the zone name as the
question) and not process the NOTIFY semantics.
**Why it happens:** `handleDNS` only handles queries today.
**How to avoid:** Insert `if r.Opcode == dns.OpcodeNotify { ... return }` as the FIRST
opcode dispatch in `handleDNS`, before the authoritative and recursive paths.
**Warning signs:** NOTIFY acknowledged with a real DNS answer instead of an empty NOERROR.

### Pitfall 3: Memory Leak in Per-IP Rate Limiter Map
**What goes wrong:** `visitors map[string]*rate.Limiter` grows indefinitely as new source
IPs appear. In a busy environment with many unique IPs (spoofed or real), this becomes a
memory issue.
**Why it happens:** No eviction policy.
**How to avoid:** Store `lastSeen time.Time` alongside each limiter; sweep in a background
goroutine every 5 minutes, evicting entries older than 10 minutes.
**Warning signs:** Memory growth proportional to unique source IPs over time.

### Pitfall 4: Blocking on Outbound NOTIFY in the Zone Update Path
**What goes wrong:** If `ZoneManager.UpdateRecords` or serial increment calls the outbound
NOTIFY sender synchronously, any network timeout (default 5s in miekg client) blocks the
zone update goroutine.
**Why it happens:** Convenience of calling inline.
**How to avoid:** Enqueue zone-changed events onto a channel; a dedicated sender goroutine
drains the channel, applies propagation delay, then sends NOTIFYs.
**Warning signs:** Zone update calls blocking for several seconds under network issues.

### Pitfall 5: RFC3597 Rdata Is Hex-Encoded (Not Raw Bytes)
**What goes wrong:** `dns.RFC3597.Rdata` is a hex-encoded string, not a `[]byte`.
Attempting to access `rr.Rdata[0]` gives the first hex nibble, not the first byte.
**Why it happens:** The miekg/dns tag `dns:"hex"` signals that the field is encoded as hex.
**How to avoid:** Always use `hex.DecodeString(rr.Rdata)` before parsing field values.
**Warning signs:** Wrong RRtype values parsed from DSYNC records; bit-shifting errors.

### Pitfall 6: _dsync Discovery Returns Multiple Records
**What goes wrong:** A parent zone may publish multiple DSYNC records at `_dsync.<zone>` —
one for CDS, one for CSYNC. If the outbound sender only reads the first record, it misses
the second endpoint.
**Why it happens:** Assuming single-record response.
**How to avoid:** Iterate over all DSYNC records in the answer section; filter by
`DSYNCRecord.RRtype` to match the notification type (CDS vs CSYNC) being sent.

---

## Code Examples

### DSYNC Constants and Type Definition
```go
// internal/dsync/dsync.go
// Source: RFC 9859 §2, verified against miekg/dns types.go

const TypeDSYNC uint16 = 66  // Not in miekg/dns v1.1.72; defined here

// Scheme values
const (
    DSYNCSchemeNull   uint8 = 0 // No-op
    DSYNCSchemeNOTIFY uint8 = 1 // RFC 1996 NOTIFY
)
```

### Detect NOTIFY Opcode in handleDNS
```go
// internal/server/server.go — add near top of handleDNS, before authoritative check
// Source: verified from miekg/dns types.go (OpcodeNotify = 4)

if r.Opcode == dns.OpcodeNotify {
    if s.dsyncHandler != nil {
        s.dsyncHandler.HandleInbound(w, r, clientIP)
    } else {
        // NOTIFY not configured — send NOTIMPL
        m.Rcode = dns.RcodeNotImplemented
        w.WriteMsg(m)
    }
    return
}
```

### Outbound NOTIFY with Custom Qtype
```go
// internal/dsync/sender.go
// Source: miekg/dns defaults.go SetNotify pattern

func sendNotify(ctx context.Context, zoneName string, qtype uint16, target string, port uint16) error {
    m := new(dns.Msg)
    m.SetNotify(zoneName)
    m.Question[0].Qtype = qtype  // Override TypeSOA → TypeCDS or TypeCSYNC

    c := &dns.Client{
        Net:     "udp",
        Timeout: 5 * time.Second,
    }
    addr := net.JoinHostPort(target, strconv.Itoa(int(port)))
    resp, _, err := c.ExchangeContext(ctx, m, addr)
    if err != nil {
        return fmt.Errorf("notify %s: %w", addr, err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return fmt.Errorf("notify %s: rcode %s", addr, dns.RcodeToString[resp.Rcode])
    }
    return nil
}
```

### DSYNC Decode from RFC3597 Wire
```go
// internal/dsync/dsync.go
// Source: miekg/dns RFC3597 struct + dns.UnpackDomainName

func ParseRFC3597(rr *dns.RFC3597) (DSYNCRecord, error) {
    raw, err := hex.DecodeString(rr.Rdata)
    if err != nil {
        return DSYNCRecord{}, fmt.Errorf("dsync hex decode: %w", err)
    }
    if len(raw) < 6 {
        return DSYNCRecord{}, fmt.Errorf("dsync rdata too short: %d bytes", len(raw))
    }
    rec := DSYNCRecord{
        RRtype: binary.BigEndian.Uint16(raw[0:2]),
        Scheme: raw[2],
        Port:   binary.BigEndian.Uint16(raw[3:5]),
    }
    name, _, err := dns.UnpackDomainName(raw, 5)
    if err != nil {
        return DSYNCRecord{}, fmt.Errorf("dsync target unpack: %w", err)
    }
    rec.Target = name
    return rec, nil
}
```

### Zone File DSYNC Record (BIND format)
```
; _dsync zone entries for example.com. parent serving DSYNC
; TYPE66 = DSYNC, \# length hex-rdata (RFC 3597 unknown-type presentation)
;   003B = CDS(59), 01 = NOTIFY, 0035 = port 53, rest = target FQDN wire format
_dsync.example.com. 3600 IN TYPE66 \# 14 003B010035 076578616D706C6503636F6D00
_dsync.example.com. 3600 IN TYPE66 \# 14 003E010035 076578616D706C6503636F6D00
```

---

## Existing Infrastructure Reuse

### NotifySecondaries (zones.proto / ZoneManager.Notify)

The existing `ZoneManager.Notify()` in `internal/engine/zonemanager.go` is a stub that
returns immediately. The `NotifyRequest`/`NotifyResponse` in `zones.proto` are designed for
notifying secondary servers (zone transfer NOTIFY), not for DSYNC parent notifications. The
two concerns are **separate**:

- **Existing Notify**: zone transfer, SOA qtype, targets = secondary nameservers
- **DSYNC Notify**: delegation maintenance, CDS/CSYNC qtype, targets = discovered via _dsync

**Recommendation:** Do not extend `ZoneManager.Notify` for DSYNC. Implement DSYNC outbound
notification as a separate `DSYNCNotifier` component in `internal/dsync/sender.go`. Wire it
into zone update events (e.g., from `ZoneManager.UpdateRecords` or `ZoneManager.ReloadZone`
callbacks) rather than the existing Notify RPC path.

### AlsoNotify (config.go)

`ZoneConfig.AlsoNotify []string` is for additional NOTIFY targets for zone transfer
purposes. DSYNC targets are discovered dynamically via DNS (_dsync lookup), not configured
statically. A new optional config field `DSYNCNotify bool` (enable/disable per zone) is
sufficient.

### Rate Limiting vs. RRL

The existing `internal/rrl` package limits **response rates** (amplification defense). DSYNC
needs a **request processing rate limit** on inbound NOTIFY. These are architecturally
separate. The new `internal/dsync/ratelimit.go` does not replace or extend RRL.

---

## Configuration Changes Required

Add to `ZoneConfig` in `internal/config/config.go`:

```go
// DSYNCConfig controls RFC 9859 generalized notifications
DSYNC *ZoneDSYNCConfig `yaml:"dsync,omitempty"`
```

```go
type ZoneDSYNCConfig struct {
    // Enable outbound NOTIFY to discovered _dsync parent endpoints
    // when this zone's CDS/CSYNC records change
    NotifyParent bool `yaml:"notify_parent"`

    // PropagationDelay: wait this long after serial increment before
    // sending outbound NOTIFY (RFC 9859 recommendation)
    // Default: 60s
    PropagationDelay time.Duration `yaml:"propagation_delay"`
}
```

Add to `server.Config` (for inbound handling):

```go
// DSYNC inbound NOTIFY handler configuration
DSYNC DSYNCConfig `yaml:"dsync"`
```

```go
type DSYNCConfig struct {
    // Enable inbound NOTIFY(CDS/CSYNC) handling
    Enabled bool `yaml:"enabled"`

    // Rate limit: max NOTIFY messages processed per source IP per second
    // Default: 5
    RatePerSecond float64 `yaml:"rate_per_second"`

    // Burst: token bucket burst size
    // Default: 10
    Burst int `yaml:"burst"`
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual DS updates (operator polls for CDS) | RFC 9859 DSYNC automated notification | RFC 9859 published 2025 | Parent zones can update DS records within minutes of child CDS publication |
| NOTIFY only for zone transfer (SOA qtype) | NOTIFY with CDS/CSYNC qtype for delegation maintenance | RFC 9859 | Same NOTIFY opcode, different qtype |
| _dsync discovery by hardcoded config | Dynamic `_dsync.<parent>` DNS lookup | RFC 9859 §3 | No static config of parent scanner endpoints needed |

**Deprecated/outdated:**
- Using NOTIFY opcode exclusively for zone transfer: RFC 9859 generalizes it; the opcode is now overloaded for delegation maintenance as well.

---

## Environment Availability

Step 2.6: SKIPPED (no external dependencies beyond already-present Go toolchain and miekg/dns).

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go testing (stdlib) + testify v1.11.1 |
| Config file | none (go test ./...) |
| Quick run command | `go test ./internal/dsync/... -v -run TestUnit` |
| Full suite command | `go test ./... -timeout 30s` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DSYNC-01 | DSYNC type 66: encode → decode roundtrip | unit | `go test ./internal/dsync/... -run TestDSYNCCodec` | ❌ Wave 0 |
| DSYNC-02 | DecodeDSYNC rejects rdata < 6 bytes | unit | `go test ./internal/dsync/... -run TestDSYNCDecodeTooShort` | ❌ Wave 0 |
| DSYNC-03 | Inbound NOTIFY(CDS) dispatches to handler | unit | `go test ./internal/dsync/... -run TestHandleInboundNotifyCDS` | ❌ Wave 0 |
| DSYNC-04 | Inbound NOTIFY rate limiter blocks excess | unit | `go test ./internal/dsync/... -run TestNotifyRateLimiter` | ❌ Wave 0 |
| DSYNC-05 | Rate limiter visitor map evicts stale entries | unit | `go test ./internal/dsync/... -run TestRateLimiterEviction` | ❌ Wave 0 |
| DSYNC-06 | _dsync discovery returns DSYNC records | unit | `go test ./internal/dsync/... -run TestDiscoverDSYNC` | ❌ Wave 0 |
| DSYNC-07 | Outbound NOTIFY(CDS) carries correct qtype | unit | `go test ./internal/dsync/... -run TestSendNotifyQtype` | ❌ Wave 0 |
| DSYNC-08 | handleDNS dispatches NOTIFY to dsync handler | integration | `go test ./internal/server/... -run TestHandleDNSNotifyOpcode` | ❌ Wave 0 |
| DSYNC-09 | Zone file with TYPE66 loads and serves correctly | unit | `go test ./internal/zone/... -run TestDSYNCZoneFile` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/dsync/... -v`
- **Per wave merge:** `go test ./... -timeout 30s`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/dsync/dsync_test.go` — covers DSYNC-01, DSYNC-02
- [ ] `internal/dsync/handler_test.go` — covers DSYNC-03, DSYNC-04, DSYNC-05
- [ ] `internal/dsync/discovery_test.go` — covers DSYNC-06
- [ ] `internal/dsync/sender_test.go` — covers DSYNC-07
- [ ] `internal/server/notify_test.go` — covers DSYNC-08
- [ ] `internal/zone/parser_dsync_test.go` — covers DSYNC-09

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | NOTIFY is unauthenticated in base RFC 1996; DNSSEC on response is recommended mitigation |
| V3 Session Management | no | Stateless protocol |
| V4 Access Control | yes | Rate limit inbound NOTIFY per source IP; optionally restrict source IPs via ACL |
| V5 Input Validation | yes | Validate DSYNC rdata length before parsing; validate Target is valid FQDN |
| V6 Cryptography | no | No crypto in DSYNC record itself; DNSSEC on zones is separate |

### Known Threat Patterns for DSYNC/NOTIFY Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| NOTIFY flood from spoofed IPs (amplification of delegation checks) | DoS | Per-source-IP rate limiting (RFC 9859 §5 MUST); token bucket |
| Malicious DSYNC record with crafted Target pointing to attacker server | Spoofing | DNSSEC validation of `_dsync` zone responses (RFC 9859 RECOMMENDED) |
| Slow-path delegation check triggered for every NOTIFY → resource exhaustion | DoS | Async delegation check with bounded goroutine pool or channel-based queue |
| Forged DSYNC Rdata with malformed domain name causing decoder panic | Tampering | Length check before UnpackDomainName; recover in handler; fuzzing test |
| Discovery loop via malicious `_dsync` chain referrals | DoS | Max hop count in discovery loop; timeout via context |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Outbound NOTIFY should fire from ZoneManager.UpdateRecords callback | Architecture | Could be better triggered from zone file reload event; discuss with owner |
| A2 | PropagationDelay default of 60s is appropriate | Config changes | RFC 9859 does not specify a value; operator may need to tune |
| A3 | A separate `internal/dsync/` package is the right home for all DSYNC logic | Project structure | Could go in `internal/server/` or `internal/zone/` if team prefers co-location |

---

## Open Questions

1. **Should inbound NOTIFY(CDS/CSYNC) trigger actual DS record updates?**
   - What we know: RFC 9859 says "schedule an immediate check"; the check validates CDS records.
   - What's unclear: Does dnsscienced act as a parent-side registry (that would update DS records in its zones), or only as a child (that publishes CDS records)?
   - Recommendation: For this phase, implement the inbound handler as "acknowledge + log + schedule check"; full delegation maintenance engine can be a later phase.

2. **Where does the delegation check implementation live?**
   - What we know: RFC 9859 §4.3 says to run "the same DNS lookups and verifications that would otherwise be triggered based on a timer."
   - What's unclear: No such timer or delegation maintenance engine exists in dnsscienced today.
   - Recommendation: The `scheduleDelegationCheck` goroutine in this phase logs and records the NOTIFY; full verification is deferred.

3. **Does the BIND zone parser parse `TYPE66` in presentation format correctly?**
   - What we know: miekg/dns scanner falls back to RFC3597 for unknown types; the `\# length hex` format is supported.
   - What's unclear: Whether the ZoneParser will parse `DSYNC CDS NOTIFY 53 target.` mnemonic form (it will not — mnemonics are only known for registered types).
   - Recommendation: Zone files must use `TYPE66 \# length hexdata` format unless we register a custom parse hook in miekg/dns (not worth it given library version).

---

## Sources

### Primary (HIGH confidence)
- [RFC 9859 full text](https://www.rfc-editor.org/rfc/rfc9859) — DSYNC wire format, type number, NOTIFY requirements, discovery algorithm, rate limiting MUST
- miekg/dns v1.1.72 source at `/Users/ryan/go/pkg/mod/github.com/miekg/dns@v1.1.72/` — verified TypeCDS=59, TypeCDNSKEY=60, TypeCSYNC=62, OpcodeNotify=4, TypeHTTPS=65 (type 66 absent), RFC3597 fallback path in scan.go and msg.go
- Project codebase — server.go handleDNS structure, zone/parser_dnszone.go Generic inline field, internal/rrl design, go.mod confirming golang.org/x/time v0.14.0 already present

### Secondary (MEDIUM confidence)
- [pkg.go.dev miekg/dns](https://pkg.go.dev/github.com/miekg/dns) — confirmed no DSYNC listing in package index
- [pkg.go.dev golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) — per-IP token bucket pattern

### Tertiary (LOW confidence)
- WebSearch results suggesting miekg/dns includes TypeDSYNC — **CONTRADICTED** by direct source inspection; miekg/dns v1.1.72 does NOT have it. Do not rely on the web search assertion.

---

## Metadata

**Confidence breakdown:**
- RFC 9859 wire format: HIGH — fetched from rfc-editor.org
- miekg/dns type availability: HIGH — verified by direct grep of installed module source
- Type code for CDS: HIGH — verified (it is 59, not 60 as phase description states)
- Architecture patterns: HIGH — derived from reading actual codebase structure
- Rate limiting pattern: HIGH — golang.org/x/time/rate is already a go.mod dependency

**Research date:** 2026-05-16
**Valid until:** 2026-08-16 (stable RFC + stable library)
