# DNS Wire Protocol Implementation Guide

## Overview

This document details the DNS wire protocol handling for DNSScienced, covering message parsing, serialization, transport layers, and edge cases.

---

## 1. DNS Message Format (RFC 1035)

### Message Structure

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                   QUESTION                    /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    ANSWER                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                   AUTHORITY                   /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                   ADDITIONAL                  /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Header Flags Detail

```
Bit  Field   Description
───────────────────────────────────────────────────────────────
0    QR      Query (0) or Response (1)
1-4  OPCODE  0=QUERY, 1=IQUERY(obsolete), 2=STATUS, 4=NOTIFY, 5=UPDATE
5    AA      Authoritative Answer
6    TC      Truncation - message was truncated
7    RD      Recursion Desired
8    RA      Recursion Available
9    Z       Reserved (must be 0)
10   AD      Authentic Data (DNSSEC)
11   CD      Checking Disabled (DNSSEC)
12-15 RCODE  Response code (extended via EDNS)
```

### Response Codes

| RCODE | Name | Description |
|-------|------|-------------|
| 0 | NOERROR | No error |
| 1 | FORMERR | Format error in query |
| 2 | SERVFAIL | Server failure |
| 3 | NXDOMAIN | Name does not exist |
| 4 | NOTIMP | Not implemented |
| 5 | REFUSED | Query refused |
| 6 | YXDOMAIN | Name exists when it should not |
| 7 | YXRRSET | RR set exists when it should not |
| 8 | NXRRSET | RR set does not exist |
| 9 | NOTAUTH | Server not authoritative / Not authorized |
| 10 | NOTZONE | Name not contained in zone |
| 16 | BADVERS | Bad OPT version (EDNS) |
| 16 | BADSIG | TSIG signature failure |
| 17 | BADKEY | Key not recognized |
| 18 | BADTIME | Signature out of time window |
| 19 | BADMODE | Bad TKEY mode |
| 20 | BADNAME | Duplicate key name |
| 21 | BADALG | Algorithm not supported |
| 22 | BADTRUNC | Bad truncation |
| 23 | BADCOOKIE | Bad/missing server cookie |

---

## 2. Name Compression

### Compression Pointer Format

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1  1|                OFFSET                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- First two bits = 11 indicates compression pointer
- Remaining 14 bits = offset from start of message
- Maximum offset: 16383 (0x3FFF)
```

### Compression Rules

1. **Pointers can only point backwards** - never forward in the message
2. **Maximum compression depth**: Prevent loops by tracking visited offsets
3. **Compression is optional for queries** - but MUST be handled in responses
4. **Preserve original case** for 0x20 encoding compatibility

### Decompression Algorithm

```
function decompress_name(buffer, offset):
    name = ""
    visited = set()
    max_jumps = 128  // Prevent infinite loops
    jumps = 0

    while true:
        if offset in visited:
            return ERROR("compression loop detected")
        visited.add(offset)

        length = buffer[offset]

        if length == 0:
            // End of name
            break

        if (length & 0xC0) == 0xC0:
            // Compression pointer
            if jumps++ > max_jumps:
                return ERROR("too many compression jumps")
            pointer = ((length & 0x3F) << 8) | buffer[offset + 1]
            if pointer >= offset:
                return ERROR("forward pointer not allowed")
            offset = pointer
            continue

        if (length & 0xC0) != 0:
            return ERROR("invalid label type")

        // Regular label
        if length > 63:
            return ERROR("label too long")

        name += buffer[offset+1 : offset+1+length] + "."
        offset += length + 1

    return name
```

---

## 3. EDNS(0) - RFC 6891

### OPT Record Format

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  NAME = 0                     |  (root)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  TYPE = 41                    |  (OPT)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              UDP Payload Size                 |  (CLASS field)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|   Extended RCODE  |  Version  |      DO | Z   |  (TTL field)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    RDATA                      /  (options)
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### EDNS Options

| Code | Name | RFC | Description |
|------|------|-----|-------------|
| 3 | NSID | 5001 | Name Server Identifier |
| 5 | DAU | 6975 | DNSSEC Algorithm Understood |
| 6 | DHU | 6975 | DS Hash Understood |
| 7 | N3U | 6975 | NSEC3 Hash Understood |
| 8 | ECS | 7871 | Client Subnet |
| 9 | EXPIRE | 7314 | Zone expire timer |
| 10 | COOKIE | 7873 | DNS Cookie |
| 11 | TCP-KEEPALIVE | 7828 | TCP Keepalive |
| 12 | PADDING | 7830 | Padding |
| 13 | CHAIN | 7901 | Chain query requests |
| 14 | KEY-TAG | 8145 | Key Tag signaling |
| 15 | EDE | 8914 | Extended DNS Errors |
| 16 | CLIENT-TAG | 8914 | Client Tag |
| 17 | SERVER-TAG | 8914 | Server Tag |

### DNS Cookie Format (RFC 7873)

```
+--+--+--+--+--+--+--+--+
|   Client Cookie (8)   |  Fixed 8 bytes
+--+--+--+--+--+--+--+--+
|                       |
|   Server Cookie       |  Variable 8-32 bytes
|      (8-32)           |
+--+--+--+--+--+--+--+--+

Client Cookie Generation:
  client_cookie = HMAC(client_secret, client_ip | server_ip | random)[:8]

Server Cookie Generation (RFC 9018 recommended):
  server_cookie = Version(1) | Reserved(3) | Timestamp(4) | Hash(8)
  Hash = SipHash-2-4(server_secret, client_cookie | version | timestamp | client_ip)
```

### Extended DNS Errors (RFC 8914)

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|            INFO-CODE (2 bytes)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/              EXTRA-TEXT (variable)            /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Common INFO-CODEs:
  0   Other
  1   Unsupported DNSKEY Algorithm
  2   Unsupported DS Digest Type
  3   Stale Answer (RFC 8767)
  4   Forged Answer (RPZ, blocklist)
  5   DNSSEC Indeterminate
  6   DNSSEC Bogus
  7   Signature Expired
  8   Signature Not Yet Valid
  9   DNSKEY Missing
  10  RRSIGs Missing
  11  No Zone Key Bit Set
  12  NSEC Missing
  13  Cached Error
  14  Not Ready
  15  Blocked
  16  Censored
  17  Filtered
  18  Prohibited
  19  Stale NXDOMAIN Answer
  20  Not Authoritative
  21  Not Supported
  22  No Reachable Authority
  23  Network Error
  24  Invalid Data
```

---

## 4. Transport Protocols

### UDP Transport

```
┌─────────────────────────────────────────────────────────────────┐
│                    UDP Message Flow                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client                                        Server           │
│    │                                              │             │
│    │──────── DNS Query (≤512 or EDNS size) ─────►│             │
│    │                                              │             │
│    │◄─────── DNS Response (≤512 or EDNS) ────────│             │
│    │                                              │             │
│  If TC=1:                                                       │
│    │                                              │             │
│    │══════════════ TCP Connection ═══════════════│             │
│    │                                              │             │
└─────────────────────────────────────────────────────────────────┘

Constraints:
- Traditional limit: 512 bytes (RFC 1035)
- EDNS extended: up to 4096 bytes (practical: 1232 for IPv6 safe)
- Path MTU issues above ~1400 bytes
- Truncation (TC=1) signals client should retry via TCP
```

### TCP Transport (RFC 7766)

```
┌─────────────────────────────────────────────────────────────────┐
│                    TCP Message Framing                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+              │
│  |         Length (2 bytes, network order)      |              │
│  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+              │
│  |                                               |              │
│  /              DNS Message (Length bytes)       /              │
│  |                                               |              │
│  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+              │
│                                                                 │
│  Multiple messages can be pipelined on same connection          │
│  Maximum message size: 65535 bytes                              │
└─────────────────────────────────────────────────────────────────┘

Connection Management:
- Idle timeout: recommended 2-30 seconds
- TCP keepalive EDNS option (RFC 7828)
- Connection reuse for multiple queries
- Server MAY close after single response (RFC 7766 discourages)
```

### TCP Pipelining

```
┌─────────────────────────────────────────────────────────────────┐
│                    TCP Query Pipelining                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client                                        Server           │
│    │                                              │             │
│    │────── Query 1 (ID=1) ──────────────────────►│             │
│    │────── Query 2 (ID=2) ──────────────────────►│             │
│    │────── Query 3 (ID=3) ──────────────────────►│             │
│    │                                              │             │
│    │◄───────────────────────── Response 2 ───────│             │
│    │◄───────────────────────── Response 1 ───────│             │
│    │◄───────────────────────── Response 3 ───────│             │
│    │                                              │             │
│  Responses can arrive out of order                              │
│  Match by transaction ID                                        │
└─────────────────────────────────────────────────────────────────┘
```

### DNS over TLS (DoT) - RFC 7858

```
┌─────────────────────────────────────────────────────────────────┐
│                    DoT Connection Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client                                        Server :853      │
│    │                                              │             │
│    │══════════ TLS Handshake ════════════════════│             │
│    │  ClientHello ──────────────────────────────►│             │
│    │◄──────────────────────────── ServerHello    │             │
│    │◄──────────────────────────── Certificate    │             │
│    │◄──────────────────────────── ServerHelloDone│             │
│    │  ClientKeyExchange ────────────────────────►│             │
│    │  ChangeCipherSpec ─────────────────────────►│             │
│    │  Finished ─────────────────────────────────►│             │
│    │◄───────────────────────── ChangeCipherSpec  │             │
│    │◄───────────────────────── Finished          │             │
│    │                                              │             │
│    │═══════════ DNS over TLS ════════════════════│             │
│    │  [Length][DNS Query] ──────────────────────►│             │
│    │◄────────────────────── [Length][DNS Response]│             │
│    │                                              │             │
└─────────────────────────────────────────────────────────────────┘

Requirements:
- Port 853 (dedicated)
- TLS 1.2+ required, TLS 1.3 recommended
- Server certificate validation (PKIX or DANE)
- Same TCP framing as plain TCP
- ALPN: "dot" (optional but recommended)
```

### DNS over HTTPS (DoH) - RFC 8484

```
┌─────────────────────────────────────────────────────────────────┐
│                    DoH Message Formats                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GET Method (cacheable):                                        │
│  ────────────────────────────────────────────────────────────   │
│  GET /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB │
│  Host: dns.example.com                                          │
│  Accept: application/dns-message                                │
│                                                                 │
│  - dns parameter: base64url encoded DNS query                   │
│  - Suitable for simple queries                                  │
│  - Can be cached by HTTP infrastructure                         │
│                                                                 │
│  POST Method (any query):                                       │
│  ────────────────────────────────────────────────────────────   │
│  POST /dns-query                                                │
│  Host: dns.example.com                                          │
│  Content-Type: application/dns-message                          │
│  Accept: application/dns-message                                │
│  Content-Length: 33                                             │
│                                                                 │
│  <binary DNS message>                                           │
│                                                                 │
│  Response:                                                      │
│  ────────────────────────────────────────────────────────────   │
│  HTTP/2 200                                                     │
│  Content-Type: application/dns-message                          │
│  Cache-Control: max-age=3600                                    │
│  Content-Length: 64                                             │
│                                                                 │
│  <binary DNS response>                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Requirements:
- HTTPS (TLS required)
- HTTP/2 recommended, HTTP/3 supported
- Content-Type: application/dns-message
- Path: typically /dns-query (configurable)
- MIME type registration per RFC 8484
```

### DNS over QUIC (DoQ) - RFC 9250

```
┌─────────────────────────────────────────────────────────────────┐
│                    DoQ Connection Model                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  QUIC Features for DNS:                                         │
│  • 0-RTT connection establishment (after first connection)      │
│  • Multiplexed streams (no head-of-line blocking)              │
│  • Built-in encryption (TLS 1.3)                               │
│  • Connection migration                                         │
│  • Better loss recovery than TCP                               │
│                                                                 │
│  Stream Usage:                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Stream 0: DNS Query 1 ──► Response 1                   │   │
│  │  Stream 4: DNS Query 2 ──► Response 2                   │   │
│  │  Stream 8: DNS Query 3 ──► Response 3                   │   │
│  │  ...                                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  - Each query/response pair uses a new bidirectional stream    │
│  - No length prefix needed (QUIC handles framing)              │
│  - Stream IDs: client-initiated = 0, 4, 8, ...                 │
│                                                                 │
│  ALPN: "doq"                                                    │
│  Port: 853 (same as DoT, different protocol)                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Zone Transfer Protocols

### AXFR (Full Zone Transfer) - RFC 5936

```
┌─────────────────────────────────────────────────────────────────┐
│                    AXFR Message Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Secondary                                     Primary          │
│    │                                              │             │
│    │══════════ TCP Connection ═══════════════════│             │
│    │                                              │             │
│    │────── AXFR Query (QTYPE=252) ──────────────►│             │
│    │       QNAME=example.com                      │             │
│    │                                              │             │
│    │◄──────────── Response 1 ────────────────────│             │
│    │              SOA (start marker)              │             │
│    │              NS records                      │             │
│    │              A records...                    │             │
│    │                                              │             │
│    │◄──────────── Response 2 ────────────────────│             │
│    │              More RRs...                     │             │
│    │                                              │             │
│    │◄──────────── Response N ────────────────────│             │
│    │              More RRs...                     │             │
│    │              SOA (end marker)                │             │
│    │                                              │             │
│    │══════════ Connection Close ═════════════════│             │
│                                                                 │
│  Format:                                                        │
│  - First record: SOA                                           │
│  - Middle: All zone records (any order)                        │
│  - Last record: SOA (same as first)                            │
│  - Multiple DNS messages over single TCP connection            │
└─────────────────────────────────────────────────────────────────┘
```

### IXFR (Incremental Zone Transfer) - RFC 1995

```
┌─────────────────────────────────────────────────────────────────┐
│                    IXFR Message Format                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Query:                                                         │
│  ────────────────────────────────────────────────────────────   │
│  QTYPE=251 (IXFR)                                              │
│  QNAME=example.com                                              │
│  Authority section: Current SOA (serial known by secondary)    │
│                                                                 │
│  Response (incremental):                                        │
│  ────────────────────────────────────────────────────────────   │
│  SOA (new serial: 2024010103)         ← Current version        │
│  SOA (old serial: 2024010101)         ← Start of diff 1        │
│  <deleted RRs>                        ← Records to remove      │
│  SOA (serial: 2024010102)             ← End delete/start add   │
│  <added RRs>                          ← Records to add         │
│  SOA (old serial: 2024010102)         ← Start of diff 2        │
│  <deleted RRs>                                                 │
│  SOA (serial: 2024010103)             ← End of diff 2          │
│  <added RRs>                                                    │
│  SOA (new serial: 2024010103)         ← End marker             │
│                                                                 │
│  Server may respond with AXFR if:                              │
│  - IXFR not supported                                          │
│  - History not available                                       │
│  - AXFR would be smaller                                       │
└─────────────────────────────────────────────────────────────────┘
```

### NOTIFY (RFC 1996)

```
┌─────────────────────────────────────────────────────────────────┐
│                    NOTIFY Message Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Primary                                       Secondary        │
│    │                                              │             │
│    │  Zone updated (serial incremented)          │             │
│    │                                              │             │
│    │────── NOTIFY (opcode=4) ───────────────────►│  (UDP)      │
│    │       QNAME=example.com                      │             │
│    │       QTYPE=SOA                              │             │
│    │       AA=1                                   │             │
│    │       Answer: Current SOA (optional)         │             │
│    │                                              │             │
│    │◄────── NOTIFY Response ─────────────────────│             │
│    │        QR=1, AA=1                           │             │
│    │                                              │             │
│    │                        Secondary checks SOA  │             │
│    │◄─────────────────────── SOA Query ──────────│             │
│    │────────────────────────── SOA Response ────►│             │
│    │                                              │             │
│    │         If serial higher, initiate transfer │             │
│    │◄───────────────────── AXFR/IXFR Request ────│             │
│    │                                              │             │
└─────────────────────────────────────────────────────────────────┘

NOTIFY Retries:
- Send via UDP first
- Retry a bounded, configurable number of times with exponential backoff
- Fall back to TCP once after UDP attempts are exhausted
- Stop retries on response or timeout
- Coalesce repeated changes to the newest SOA per zone
- Require TSIG by default and require a signed success response
```

---

## 6. TSIG Authentication (RFC 8945)

### TSIG Record Format

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   NAME                        |  (key name)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 TYPE = 250                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 CLASS = ANY                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  TTL = 0                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 RDLENGTH                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Algorithm Name                  |  (e.g., hmac-sha256)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Time Signed (48-bit)             |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Fudge                        |  (time tolerance)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 MAC Size                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    MAC                        /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Original ID                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Error                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Other Len                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/               Other Data                      /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### TSIG MAC Calculation

```
Request MAC covers:
┌────────────────────────────────────────────────────────────────┐
│  DNS Message (header + question + answer + authority)          │
│  TSIG Variables:                                               │
│    - Key Name (canonical wire format)                          │
│    - Class (ANY = 255)                                         │
│    - TTL (0)                                                   │
│    - Algorithm Name                                            │
│    - Time Signed                                               │
│    - Fudge                                                     │
│    - Error (0 for requests)                                    │
│    - Other Len (0)                                             │
│    - Other Data (empty)                                        │
└────────────────────────────────────────────────────────────────┘

Response MAC additionally covers:
┌────────────────────────────────────────────────────────────────┐
│  Request MAC (from query TSIG)                                 │
│  DNS Response Message                                          │
│  TSIG Variables (as above)                                     │
└────────────────────────────────────────────────────────────────┘

Algorithms:
- hmac-sha256 (RECOMMENDED)
- hmac-sha384
- hmac-sha512
- hmac-sha1 (legacy, not recommended)
- hmac-md5 (deprecated, insecure)
```

---

## 7. DNSSEC Wire Format

### RRSIG Record

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|        Type Covered (2 bytes)                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Algorithm |         Labels                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Original TTL                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Signature Expiration             |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Signature Inception              |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Key Tag                         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/               Signer's Name                   /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                  Signature                    /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNSKEY Record

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Flags (2 bytes)                  |
|  bit 7: Zone Key   bit 15: Secure Entry Point |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|    Protocol (3)   |       Algorithm           |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                 Public Key                    /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Flags:
  256 (0x0100): Zone Signing Key (ZSK)
  257 (0x0101): Key Signing Key (KSK)
```

### DS Record

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Key Tag (2 bytes)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|  Algorithm (1)    |    Digest Type (1)        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                   Digest                      /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Digest Types:
  1: SHA-1 (deprecated)
  2: SHA-256 (MUST support)
  4: SHA-384 (SHOULD support)
```

### NSEC3 Record

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Hash Alg (1)      |    Flags (1)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Iterations (2 bytes)             |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Salt Length (1)   |                           |
+--+--+--+--+--+--+--+                           +
|                   Salt                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Hash Length (1)   |                           |
+--+--+--+--+--+--+--+                           +
|            Next Hashed Owner                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                 Type Bit Maps                 /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

RFC 9276 Recommendations:
- Iterations: 0 (MUST)
- Salt Length: 0 (SHOULD)
- Flags bit 0 (Opt-Out): 0 for most zones
```

---

## 8. Record Type Wire Formats

### Common Record Types

```
A Record (Type 1):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                IPv4 Address                   |
|                  (4 bytes)                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

AAAA Record (Type 28):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
|               IPv6 Address                    |
|                 (16 bytes)                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

CNAME Record (Type 5):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/              Canonical Name                   /
|             (compressed name)                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

MX Record (Type 15):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|             Preference (2 bytes)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                 Exchange                      /
|             (compressed name)                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

TXT Record (Type 16):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Length (1) |                                  |
+--+--+--+--+                                   +
|                 Text String                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Length (1) |                                  |
+--+--+--+--+     (can repeat)                  +
|              Additional Text                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

SRV Record (Type 33):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              Priority (2 bytes)               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Weight (2 bytes)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                Port (2 bytes)                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                  Target                       /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

CAA Record (Type 257):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| Flags (1) | Tag Length(1)|                    |
+--+--+--+--+--+--+--+--+--+                    +
|                   Tag                         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                  Value                        /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### SVCB/HTTPS Records (RFC 9460)

```
SVCB/HTTPS Record (Type 64/65):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           SvcPriority (2 bytes)               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/              TargetName                       /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/              SvcParams                        /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

SvcParam Format:
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|          SvcParamKey (2 bytes)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|        SvcParamValue Length (2 bytes)         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/             SvcParamValue                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

SvcParamKeys:
  0: mandatory
  1: alpn (Application-Layer Protocol Negotiation)
  2: no-default-alpn
  3: port
  4: ipv4hint
  5: ech (Encrypted ClientHello)
  6: ipv6hint
```

---

## 9. Implementation Considerations

### Buffer Management

```
Recommended Buffer Sizes:
┌────────────────────────────────────────────────────────────────┐
│  Component              │ Size      │ Notes                    │
├─────────────────────────┼───────────┼──────────────────────────┤
│  UDP receive buffer     │ 4096      │ Covers EDNS max          │
│  TCP read buffer        │ 65535     │ Max DNS message          │
│  Name buffer            │ 255       │ Max domain name length   │
│  Label buffer           │ 63        │ Max label length         │
│  Compression table      │ 16384     │ Max offset value         │
│  EDNS buffer            │ 1232      │ IPv6-safe default        │
└────────────────────────────────────────────────────────────────┘
```

### Parsing Safety

```
Security Checks:
1. Maximum name length: 255 bytes (wire format)
2. Maximum label length: 63 bytes
3. Maximum compression pointers followed: 128
4. No forward compression pointers
5. No compression pointer loops
6. RDATA length matches expected
7. Message length matches header counts
8. OPT record only in additional section
9. Only one OPT record per message
10. TSIG only as last record in additional section
```

### Endianness

```
All multi-byte integers are in NETWORK BYTE ORDER (big-endian)

Examples:
  Port 53:        0x00 0x35
  Type A (1):     0x00 0x01
  Class IN (1):   0x00 0x01
  TTL 3600:       0x00 0x00 0x0E 0x10
```

---

## 10. Error Handling

### Parse Error Categories

| Category | Action | Response |
|----------|--------|----------|
| Truncated message | Reject | FORMERR |
| Invalid header | Reject | FORMERR |
| Bad compression | Reject | FORMERR |
| Name too long | Reject | FORMERR |
| Unknown RR type | Process | RFC 3597 handling |
| Unknown EDNS option | Ignore | Process normally |
| Invalid OPT | Ignore OPT | Process without EDNS |
| TSIG verification fail | Reject | BADSIG |

### Graceful Degradation

```
EDNS Fallback Strategy:
1. Send query with EDNS0, buffer size 1232
2. If FORMERR/timeout: retry without EDNS
3. If TC=1: retry over TCP
4. Cache EDNS capability per server

TCP Fallback:
1. UDP query timeout or TC=1
2. Establish TCP connection
3. Retry query over TCP
4. Consider TCP for future queries to this server
```

---

*Document Version: 1.0*
*Specification Coverage: RFC 1035, 6891, 7766, 7858, 8484, 9250, and related*
