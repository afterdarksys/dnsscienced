# DNSScience Server Design Document

> **Document status:** This is an architectural vision document and contains
> target-state components as well as implemented components. It is not the
> current capability matrix. See [README.md](README.md) for verified behavior
> and [ROADMAP.md](ROADMAP.md) for remaining work. In particular, DoQ and
> authoritative online signing must not be inferred as production capabilities
> from diagrams in this document.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [RFC Compliance Matrix](#2-rfc-compliance-matrix)
3. [dnsscience_cached (Recursive Resolver)](#3-dnsscience_cached-recursive-resolver)
4. [dnsscience_authd (Authoritative Server)](#4-dnsscience_authd-authoritative-server)
5. [Configuration File Format](#5-configuration-file-format)
6. [DNSScienced Zone File Format](#6-dnsscienced-zone-file-format)
7. [Conversion Utilities](#7-conversion-utilities)
8. [DNSSEC Implementation](#8-dnssec-implementation)
9. [DDoS Mitigation Architecture](#9-ddos-mitigation-architecture)
10. [Plugin/Module System](#10-pluginmodule-system)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     DNSScience Ecosystem                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────────────┐    │
│  │ dnsscience_cached│◄────────►│    dnsscience_authd      │    │
│  │  (Recursive)     │          │    (Authoritative)       │    │
│  │                  │          │                          │    │
│  │ • Caching        │          │ • Zone serving           │    │
│  │ • DNSSEC valid   │          │ • DNSSEC signing         │    │
│  │ • Query routing  │          │ • Dynamic updates        │    │
│  │ • Response policy│          │ • Zone transfers         │    │
│  │ • DDoS detection │          │ • Catalog zones          │    │
│  └────────┬─────────┘          └────────────┬─────────────┘    │
│           │                                  │                  │
│           └──────────────┬───────────────────┘                  │
│                          │                                      │
│                          ▼                                      │
│           ┌──────────────────────────────┐                     │
│           │    Shared Components          │                     │
│           │                               │                     │
│           │ • libdnsscience (core lib)    │                     │
│           │ • Plugin engine               │                     │
│           │ • Metrics/telemetry           │                     │
│           │ • Config parser               │                     │
│           │ • Zone parser (multi-format)  │                     │
│           │ • DNSSEC crypto engine        │                     │
│           │ • DDoS mitigation core        │                     │
│           └──────────────────────────────┘                     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     CLI Utilities                         │  │
│  │                                                           │  │
│  │  dnsscience-checkzone    Zone file validation            │  │
│  │  dnsscience-convert      BIND/djbdns → dnsscienced       │  │
│  │  dnsscience-keygen       DNSSEC key generation           │  │
│  │  dnsscience-signzone     Zone signing                    │  │
│  │  dnsscience-dig          Enhanced dig replacement        │  │
│  │  dnsscience-stats        Runtime statistics              │  │
│  │  dnsscience-ctl          Runtime control (rndc-like)     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Separation of Concerns**: Recursive and authoritative functions are separate daemons
2. **Security First**: DNSSEC, encrypted transports, and DDoS mitigation are first-class citizens
3. **Observability**: Rich logging, metrics, and integration with monitoring systems
4. **Modern Transports**: Native DoT, DoH, and DoQ support
5. **Backwards Compatible**: Support for BIND zone files during migration
6. **Extensible**: Plugin architecture for custom functionality

---

## 2. RFC Compliance Matrix

### Core DNS RFCs (MUST implement)

| RFC | Title | Priority |
|-----|-------|----------|
| RFC 1034 | Domain Names - Concepts and Facilities | P0 |
| RFC 1035 | Domain Names - Implementation | P0 |
| RFC 2181 | Clarifications to the DNS Specification | P0 |
| RFC 2308 | Negative Caching of DNS Queries | P0 |
| RFC 3597 | Handling Unknown DNS RR Types | P0 |
| RFC 6891 | EDNS(0) Extensions | P0 |
| RFC 7766 | DNS Transport over TCP | P0 |
| RFC 8020 | NXDOMAIN: There Really Is Nothing Underneath | P0 |

### DNSSEC RFCs (MUST implement)

| RFC | Title | Priority |
|-----|-------|----------|
| RFC 4033 | DNS Security Introduction and Requirements | P0 |
| RFC 4034 | Resource Records for DNSSEC | P0 |
| RFC 4035 | Protocol Modifications for DNSSEC | P0 |
| RFC 5155 | NSEC3 Hashed Authenticated Denial | P1 |
| RFC 6781 | DNSSEC Operational Practices | P1 |
| RFC 8624 | Algorithm Implementation Requirements | P0 |
| RFC 9276 | NSEC3 Guidance | P1 |

### Modern DNS Transport

| RFC | Title | Priority |
|-----|-------|----------|
| RFC 7858 | DNS over TLS (DoT) | P1 |
| RFC 8484 | DNS over HTTPS (DoH) | P1 |
| RFC 9250 | DNS over QUIC (DoQ) | P2 |
| RFC 9462 | Discovery of Designated Resolvers (DDR) | P2 |
| RFC 9463 | DHCP and RA Options for DDR | P2 |

### Zone Transfers & Updates

| RFC | Title | Priority |
|-----|-------|----------|
| RFC 1995 | Incremental Zone Transfer (IXFR) | P0 |
| RFC 5936 | DNS Zone Transfer Protocol (AXFR) | P0 |
| RFC 2136 | Dynamic Updates in DNS | P1 |
| RFC 3007 | Secure Dynamic Updates | P1 |
| RFC 9432 | DNS Catalog Zones | P2 |

### Privacy & Security

| RFC | Title | Priority |
|-----|-------|----------|
| RFC 7816 | DNS Query Name Minimisation | P1 |
| RFC 8198 | Aggressive NSEC/NSEC3 Caching | P1 |
| RFC 8310 | Usage Profiles for DoT/DoH | P1 |
| RFC 8914 | Extended DNS Errors (EDE) | P1 |
| RFC 9156 | DNS Query Name Minimisation Improvements | P1 |

### Record Types (Comprehensive)

| RFC | Record Type | Priority |
|-----|------------|----------|
| RFC 1035 | A, NS, CNAME, SOA, PTR, MX, TXT | P0 |
| RFC 3596 | AAAA | P0 |
| RFC 2782 | SRV | P0 |
| RFC 4408/7208 | SPF/TXT | P0 |
| RFC 6844 | CAA | P1 |
| RFC 7871 | EDNS Client Subnet (ECS) | P1 |
| RFC 9460 | SVCB/HTTPS | P1 |
| RFC 8659 | CAA Processing | P1 |
| RFC 8945 | TSIG Secret Key Transaction Auth | P1 |

### Experimental/Draft (P3)

| Spec | Title |
|------|-------|
| draft-ietf-dnsop-dns-error-reporting | Error Reporting |
| RFC 7873 | DNS Cookies |
| RFC 8767 | Serving Stale Data to Improve Resiliency |
| RFC 8806 | Running a Root Server Local |
| RFC 9471 | DNS Glue Requirements |

---

## 3. dnsscience_cached (Recursive Resolver)

### Core Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                    dnsscience_cached                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │  Query Ingress  │    │   Query Engine   │                    │
│  │                 │    │                  │                    │
│  │ • UDP/TCP :53   │───►│ • Iterative res. │                    │
│  │ • DoT :853      │    │ • Query minimiz. │                    │
│  │ • DoH :443      │    │ • QNAME shuffling│                    │
│  │ • DoQ :853/UDP  │    │ • 0x20 encoding  │                    │
│  └─────────────────┘    └────────┬────────┘                    │
│                                  │                              │
│  ┌─────────────────┐    ┌────────▼────────┐                    │
│  │  Cache Layer    │◄───│ DNSSEC Validator │                    │
│  │                 │    │                  │                    │
│  │ • Memory cache  │    │ • Chain of trust │                    │
│  │ • Redis backend │    │ • Algorithm agile│                    │
│  │ • TTL mgmt      │    │ • NSEC/NSEC3     │                    │
│  │ • Serve stale   │    │ • Trust anchors  │                    │
│  │ • Negative cache│    └──────────────────┘                    │
│  └─────────────────┘                                            │
│                                                                 │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Response Policy │    │  DDoS Mitigation │                   │
│  │                 │    │                  │                    │
│  │ • RPZ zones     │    │ • Rate limiting  │                    │
│  │ • Blocklists    │    │ • DNS Cookies    │                    │
│  │ • Allowlists    │    │ • TCP fallback   │                    │
│  │ • Rewrites      │    │ • Amplification  │                    │
│  │ • dnsscience.io │    │ • Query patterns │                    │
│  └─────────────────┘    └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features

#### Query Engine
- **Iterative Resolution**: Full recursive resolution from root servers
- **Query Name Minimization**: RFC 7816/9156 compliant
- **0x20 Encoding**: Mixed-case query names for cache poisoning resistance
- **Parallel Queries**: Concurrent queries to multiple nameservers
- **Query Pipelining**: TCP connection reuse

#### Cache Layer
- **Flexible Backend**: In-memory or Redis for distributed caching
- **Serve Stale**: RFC 8767 compliance for resilience
- **Prefetch**: Proactive refresh of popular records
- **Negative Caching**: RFC 2308 compliant
- **Aggressive NSEC**: RFC 8198 for better negative caching

#### DNSSEC Validation
- **Chain of Trust**: Full validation from root
- **Algorithm Agility**: Support for all RFC 8624 algorithms
- **Trust Anchor Management**: RFC 5011 automated updates
- **Negative Trust Anchors**: For broken DNSSEC domains

---

## 4. dnsscience_authd (Authoritative Server)

### Core Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                    dnsscience_authd                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │  Zone Manager   │    │  Query Processor  │                   │
│  │                 │    │                   │                   │
│  │ • Multi-format  │    │ • Pattern match   │                   │
│  │ • Hot reload    │    │ • Wildcard expand │                   │
│  │ • Validation    │    │ • CNAME chase     │                   │
│  │ • Catalog zones │    │ • ANY responses   │                   │
│  └─────────────────┘    └───────────────────┘                   │
│                                                                 │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Zone Transfer   │    │   DNSSEC Signer  │                   │
│  │                 │    │                  │                    │
│  │ • AXFR primary  │    │ • Online signing │                    │
│  │ • AXFR second.  │    │ • Offline signing│                    │
│  │ • IXFR          │    │ • Key rollover   │                    │
│  │ • NOTIFY        │    │ • Algorithm flex │                    │
│  │ • TSIG auth     │    │ • HSM support    │                    │
│  └─────────────────┘    └──────────────────┘                   │
│                                                                 │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Dynamic Update  │    │   DDoS Defense   │                   │
│  │                 │    │                  │                    │
│  │ • RFC 2136      │    │ • Response rate  │                    │
│  │ • GSS-TSIG      │    │ • TC bit forcing │                    │
│  │ • Update policy │    │ • REFUSED policy │                    │
│  │ • Journal/WAL   │    │ • Query patterns │                    │
│  └─────────────────┘    └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

### Zone Storage Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Zone Storage Backends                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│  │   File     │  │  Database  │  │   Memory   │             │
│  │            │  │            │  │            │              │
│  │ • DNS-SD   │  │ • SQLite   │  │ • Runtime  │             │
│  │ • BIND     │  │ • Postgres │  │ • API push │             │
│  │ • djbdns   │  │ • MySQL    │  │ • Ephemeral│             │
│  │ • JSON/YAML│  │            │  │            │              │
│  └────────────┘  └────────────┘  └────────────┘             │
│         │               │               │                    │
│         └───────────────┴───────────────┘                    │
│                         │                                     │
│                         ▼                                     │
│              ┌──────────────────┐                            │
│              │ Unified Zone API │                            │
│              │                  │                             │
│              │ • RRSet interface│                            │
│              │ • SOA tracking   │                            │
│              │ • Serial mgmt    │                            │
│              │ • Change notify  │                            │
│              └──────────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

### Key Features

#### Zone Management
- **Multi-Format Support**: Native, BIND, djbdns formats
- **Hot Reload**: SIGHUP or control socket triggered
- **Catalog Zones**: RFC 9432 for automated zone management
- **Zone Validation**: Comprehensive checks before loading

#### Zone Transfer
- **AXFR/IXFR**: Full and incremental transfers
- **NOTIFY**: Push notifications to secondaries
- **TSIG Authentication**: Secure zone transfers
- **Transfer Rate Limiting**: Prevent abuse

#### DNSSEC Signing
- **Online Signing**: Sign on-the-fly
- **Offline Signing**: Pre-signed zones
- **Key Rollover**: Automated ZSK/KSK rollover
- **HSM Support**: Hardware security module integration

---

## 5. Configuration File Format

### Design Philosophy

- **Familiarity**: Inspired by BIND/NSD but cleaner
- **Type Safety**: Clear types, validation at parse time
- **Hierarchical**: Nested blocks with inheritance
- **Comments**: `#` and `//` style
- **Includes**: Modular configuration
- **Environment Variables**: `${VAR}` expansion

### dnsscienced.conf (Main Config)

```nginx
# /etc/dnsscienced/dnsscienced.conf
# DNSScience Server Configuration

# Global options apply to all services
global {
    user dnsscienced;
    group dnsscienced;
    directory "/var/lib/dnsscienced";
    pid-file "/run/dnsscienced/dnsscienced.pid";

    # Logging configuration
    logging {
        channel default {
            destination syslog;
            facility daemon;
            severity info;
        };

        channel queries {
            destination file "/var/log/dnsscienced/queries.log";
            severity debug;
            format json;           # json|text|clf
            buffer-size 64KB;
            rotation {
                size 100MB;
                keep 7;
            };
        };

        channel security {
            destination file "/var/log/dnsscienced/security.log";
            severity notice;
        };

        category queries { queries; };
        category security { security; default; };
        category dnssec { default; };
        category xfer { default; };
    };

    # Statistics and metrics
    statistics {
        enabled yes;
        listen-on 127.0.0.1:8053;
        format prometheus;        # prometheus|json|statsd

        # Optional: dnsscience.io integration
        dnsscience-cloud {
            enabled no;
            api-key "${DNSSCIENCE_API_KEY}";  # Env var expansion
            endpoint "https://api.dnsscience.io/v1/telemetry";
            data-level minimal;   # minimal|standard|full
            anonymize yes;
        };
    };
}

# Include additional configuration files
include "/etc/dnsscienced/acl.conf";
include "/etc/dnsscienced/keys.conf";

# Access Control Lists
acl internal {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    fc00::/7;
};

acl transfer-allowed {
    key "xfer-key";
    192.0.2.53;
};

# TSIG Keys (or include from keys.conf)
key "xfer-key" {
    algorithm hmac-sha256;
    secret "base64-encoded-secret==";
};
```

### authd.conf (Authoritative Server)

```nginx
# /etc/dnsscienced/authd.conf

authd {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };

    # Zone defaults (inherited by all zones)
    zone-defaults {
        notify yes;
        notify-delay 5;

        dnssec {
            signing auto;
            algorithm ECDSAP256SHA256;
            nsec3 {
                enabled yes;
                iterations 0;      # RFC 9276 guidance
                salt-length 0;     # RFC 9276: no salt
                opt-out no;
            };
        };
    };

    # Zone definitions
    zone "example.com" {
        type primary;
        file "/var/lib/dnsscienced/zones/example.com.zone";
        format dnsscienced;        # dnsscienced|bind|djbdns

        allow-transfer { transfer-allowed; };
        allow-update { key "update-key"; };

        # Override defaults
        dnssec {
            ksk-directory "/var/lib/dnsscienced/keys/example.com";
            auto-publish yes;
            auto-activate yes;
        };
    };

    zone "0.168.192.in-addr.arpa" {
        type primary;
        file "/var/lib/dnsscienced/zones/192.168.0.rev";
        format bind;               # Backwards compatible
    };

    zone "example.org" {
        type secondary;
        primaries { 192.0.2.1 key "xfer-key"; };
        file "/var/lib/dnsscienced/zones/example.org.zone";

        # IXFR preferences
        request-ixfr yes;
        ixfr-from-differences yes;
    };

    # Catalog zone support
    catalog-zone "catalog.example.com" {
        type primary;
        file "/var/lib/dnsscienced/zones/catalog.zone";
        zone-directory "/var/lib/dnsscienced/zones/catalog/";
    };

    # DDoS mitigation
    rate-limit {
        responses-per-second 10;
        errors-per-second 5;
        nxdomains-per-second 5;
        all-per-second 100;
        window 15;
        slip 2;
        exempt-clients { internal; };
    };
}
```

### cached.conf (Recursive Resolver)

```nginx
# /etc/dnsscienced/cached.conf

cached {
    listen-on port 53 { 127.0.0.1; };
    listen-on-v6 port 53 { ::1; };

    # Encrypted DNS
    listen-on-tls port 853 {
        addresses { any; };
        certificate "/etc/dnsscienced/tls/cert.pem";
        key "/etc/dnsscienced/tls/key.pem";
        protocols TLSv1.3;
    };

    listen-on-https port 443 {
        addresses { any; };
        certificate "/etc/dnsscienced/tls/cert.pem";
        key "/etc/dnsscienced/tls/key.pem";
        path "/dns-query";         # RFC 8484
    };

    # Upstream configuration
    recursion yes;
    allow-recursion { internal; localhost; };

    # Optional: Forwarding mode
    forwarders {
        # Empty = full recursive resolution
        # 8.8.8.8;
        # 1.1.1.1 tls-name "cloudflare-dns.com";  # DoT upstream
    };
    forward-policy first;          # first|only|none

    # Root hints
    root-hints "/etc/dnsscienced/root.hints";

    # Cache configuration
    cache {
        max-size 512MB;
        max-ttl 86400;
        min-ttl 0;
        negative-ttl 3600;

        # Serve stale (RFC 8767)
        serve-stale {
            enabled yes;
            stale-answer-ttl 30;
            max-stale-ttl 86400;
            stale-refresh-time 4;
        };

        # Prefetch popular records before expiry
        prefetch {
            enabled yes;
            threshold 0.75;        # Prefetch at 75% TTL remaining
            max-concurrent 10;
        };

        # Backend selection
        backend memory;            # memory|redis
        # redis {
        #     address "127.0.0.1:6379";
        #     database 0;
        # };
    };

    # DNSSEC validation
    dnssec {
        validation auto;           # auto|yes|no
        trust-anchors-file "/etc/dnsscienced/root.keys";

        # Handle validation failures
        broken-dnssec deny;        # deny|warn-only

        # Negative trust anchors
        negative-trust-anchors {
            # "example.invalid";   # Don't validate this domain
        };

        # Aggressive NSEC caching (RFC 8198)
        aggressive-nsec yes;
    };

    # Query name minimization (RFC 7816)
    qname-minimization strict;     # strict|relaxed|off

    # Privacy
    privacy {
        # 0x20 encoding for query randomization
        use-0x20-encoding yes;

        # ECS (RFC 7871) handling
        ecs-handling {
            forward no;            # Don't forward client subnet
            # scope-prefix-v4 24;
            # scope-prefix-v6 56;
        };
    };

    # Response Policy Zones
    rpz {
        zone "rpz.dnsscience.io" {
            type secondary;
            primaries { rpz.dnsscience.io; };
            policy-override nxdomain;
        };

        zone "local-block" {
            type primary;
            file "/etc/dnsscienced/rpz/local-block.zone";
        };

        break-dnssec yes;          # Allow RPZ to override DNSSEC
    };

    # Security/DDoS
    security {
        rate-limit {
            enabled yes;
            queries-per-second 100;
            window 15;
            action drop;           # drop|tc|refuse
        };

        dns-cookies {
            enabled yes;
            secret auto;           # auto-generated, rotated daily
        };

        # Minimal responses (reduce amplification)
        minimal-responses yes;

        # Maximum UDP response size
        max-udp-size 1232;         # IPv6 safe default

        # Require TCP for large responses
        tc-bit-threshold 1232;
    };
}
```

---

## 6. DNSScienced Zone File Format

### Problems with BIND Zone Files

| Issue | BIND Behavior | DNSScienced Solution |
|-------|--------------|---------------------|
| Origin confusion | `@` changes meaning with `$ORIGIN` | Explicit FQDNs or relative block scope |
| TTL ambiguity | Inherited, `$TTL`, or per-record | Clear precedence, visual indicators |
| Whitespace sensitivity | Tab/space parsing issues | Structured format, tolerant parsing |
| Multi-line records | Parentheses required, confusing | Native multi-value support |
| Serial management | Manual, error-prone | Auto-increment or explicit |
| No comments on records | Only full-line comments | Inline comments supported |
| Cryptic error messages | Line number only | Context-aware errors with suggestions |

### New Format Design: `.dnszone`

```yaml
# /var/lib/dnsscienced/zones/example.com.dnszone
# DNSScienced Zone Format v1

zone: example.com
serial: auto                    # auto|2024010101
ttl: 3600                       # Default TTL
refresh: 3600
retry: 600
expire: 604800
minimum: 300                    # Negative cache TTL

# Nameservers for the zone
nameservers:
  - ns1.example.com
  - ns2.example.com

# Mail exchangers with explicit priority
mx:
  - priority: 10
    host: mail1.example.com
  - priority: 20
    host: mail2.example.com

# Records section - the heart of the zone
records:
  # Apex records (@ in BIND)
  "@":
    A:
      - 192.0.2.1
      - 192.0.2.2
    AAAA: 2001:db8::1
    TXT:
      - "v=spf1 mx -all"
      - "google-site-verification=abc123"
    CAA:
      - flags: 0
        tag: issue
        value: "letsencrypt.org"
      - flags: 0
        tag: issuewild
        value: ";"               # Disallow wildcard certs

  # Named hosts
  www:
    CNAME: "@"                   # Points to apex
    comment: "Main website"      # Inline documentation

  mail1:
    A: 192.0.2.10
    AAAA: 2001:db8::10

  mail2:
    A: 192.0.2.11
    ttl: 7200                    # Override default TTL

  # Nameserver glue records
  ns1:
    A: 192.0.2.53
    AAAA: 2001:db8::53

  ns2:
    A: 198.51.100.53

  # Wildcard
  "*":
    A: 192.0.2.100
    comment: "Catch-all for undefined subdomains"

  # Service records
  _dmarc:
    TXT: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

  _443._tcp.www:
    TLSA:
      usage: 3                   # DANE-EE
      selector: 1                # SPKI
      matching: 1                # SHA-256
      data: "abc123def456..."

  _sip._tcp:
    SRV:
      - priority: 10
        weight: 60
        port: 5060
        target: sip1.example.com
      - priority: 10
        weight: 40
        port: 5060
        target: sip2.example.com

  # HTTPS/SVCB records (RFC 9460)
  "@":
    HTTPS:
      - priority: 1
        target: "."             # Use apex
        params:
          alpn: h2,h3
          ipv4hint: 192.0.2.1
          ipv6hint: 2001:db8::1

  # PTR records (can define reverse in forward zone)
  # Automatically generates reverse zone entries
  db-primary:
    A: 192.0.2.50
    reverse: yes                # Auto-create PTR

# Templates for repetitive records
templates:
  webserver:
    A: "${ip}"
    AAAA: "${ip6}"
    HTTPS:
      - priority: 1
        target: "."
        params:
          alpn: h2,h3

# Apply templates
apply:
  - template: webserver
    to:
      - name: web1
        vars: { ip: 192.0.2.21, ip6: "2001:db8::21" }
      - name: web2
        vars: { ip: 192.0.2.22, ip6: "2001:db8::22" }
      - name: web3
        vars: { ip: 192.0.2.23, ip6: "2001:db8::23" }

# DNSSEC settings (optional, can be in main config)
dnssec:
  enabled: yes
  algorithm: ECDSAP256SHA256
  ksk-lifetime: 365d
  zsk-lifetime: 30d
  nsec3:
    enabled: yes
    iterations: 0
    salt-length: 0
```

### Alternative: Compact Format for Simple Zones

```ini
# /var/lib/dnsscienced/zones/simple.com.dnszone
# Compact format for simple zones

[zone]
name = simple.com
serial = auto
ttl = 3600

[ns]
ns1.simple.com
ns2.simple.com

[mx]
10 mail.simple.com

[records]
# name     type    value                    ; comment
@          A       192.0.2.1                ; apex
@          AAAA    2001:db8::1
@          TXT     "v=spf1 mx -all"
www        CNAME   @
mail       A       192.0.2.10
```

### Format Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    BIND Zone File (Before)                      │
├─────────────────────────────────────────────────────────────────┤
│  $TTL 3600                                                      │
│  @    IN  SOA   ns1.example.com. admin.example.com. (          │
│                 2024010101 ; serial                             │
│                 3600       ; refresh                            │
│                 600        ; retry                              │
│                 604800     ; expire                             │
│                 300 )      ; minimum                            │
│       IN  NS    ns1.example.com.                               │
│       IN  NS    ns2.example.com.                               │
│       IN  MX    10 mail1.example.com.                          │
│       IN  A     192.0.2.1                                      │
│  www  IN  CNAME @                                              │
│  _443._tcp.www IN TLSA 3 1 1 abc123...                         │
│                                                                 │
│  Problems:                                                      │
│  - What's the current origin?                                   │
│  - Is that TTL correct?                                        │
│  - Multi-line SOA is confusing                                 │
│  - TLSA params are cryptic numbers                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  DNSScienced Zone File (After)                  │
├─────────────────────────────────────────────────────────────────┤
│  zone: example.com                                              │
│  serial: auto                                                   │
│  ttl: 3600                                                      │
│                                                                 │
│  nameservers:                                                   │
│    - ns1.example.com                                           │
│    - ns2.example.com                                           │
│                                                                 │
│  mx:                                                            │
│    - priority: 10                                              │
│      host: mail1.example.com                                   │
│                                                                 │
│  records:                                                       │
│    "@":                                                        │
│      A: 192.0.2.1                                              │
│    www:                                                         │
│      CNAME: "@"                                                │
│    _443._tcp.www:                                              │
│      TLSA:                                                      │
│        usage: 3          # DANE-EE                             │
│        selector: 1       # SPKI                                │
│        matching: 1       # SHA-256                             │
│        data: "abc123..."                                       │
│                                                                 │
│  Benefits:                                                      │
│  - Self-documenting                                            │
│  - Clear structure                                              │
│  - Named parameters                                             │
│  - Easy to validate                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Conversion Utilities

### dnsscience-convert

Multi-format zone file converter with validation and best-practice suggestions.

```
Usage: dnsscience-convert [OPTIONS] <INPUT> [OUTPUT]

Arguments:
  <INPUT>   Input zone file path
  [OUTPUT]  Output file path (default: stdout)

Options:
  -f, --from <FORMAT>      Source format [bind|djbdns|auto] (default: auto)
  -t, --to <FORMAT>        Target format [dnsscienced|bind|json] (default: dnsscienced)
  -o, --origin <DOMAIN>    Zone origin (required for some formats)
  -c, --check              Validate input before conversion
  -s, --strict             Fail on warnings (not just errors)
  -p, --pretty             Pretty-print output
  -d, --diff               Show diff between input and output
      --suggest            Show improvement suggestions
      --dry-run            Don't write output, just validate
  -v, --verbose            Verbose output
  -q, --quiet              Suppress non-error output
  -h, --help               Print help
  -V, --version            Print version

Examples:
  # Convert BIND zone to DNSScienced format
  dnsscience-convert -f bind -t dnsscienced example.com.zone -o example.com.dnszone

  # Convert with validation and suggestions
  dnsscience-convert --check --suggest example.com.zone

  # Batch convert all zones
  for f in *.zone; do dnsscience-convert "$f" "${f%.zone}.dnszone"; done

  # Convert djbdns data file
  dnsscience-convert -f djbdns data zones/
```

### Conversion Features

#### BIND to DNSScienced

```
Input (BIND):
┌────────────────────────────────────────┐
│ $ORIGIN example.com.                   │
│ $TTL 3600                              │
│ @  IN  SOA ns1 admin (                 │
│           2024010101                   │
│           3600 600 604800 300 )        │
│    IN  NS  ns1                         │
│    IN  NS  ns2                         │
│    IN  A   192.0.2.1                   │
│ www IN  CNAME @                        │
└────────────────────────────────────────┘
           │
           ▼  dnsscience-convert

Output (DNSScienced):
┌────────────────────────────────────────┐
│ zone: example.com                      │
│ serial: 2024010101                     │
│ ttl: 3600                              │
│                                        │
│ nameservers:                           │
│   - ns1.example.com                    │
│   - ns2.example.com                    │
│                                        │
│ records:                               │
│   "@":                                 │
│     A: 192.0.2.1                       │
│   www:                                 │
│     CNAME: "@"                         │
└────────────────────────────────────────┘
```

#### djbdns to DNSScienced

```
Input (djbdns data):
┌────────────────────────────────────────┐
│ .example.com:192.0.2.53:ns1:3600       │
│ .example.com:198.51.100.53:ns2:3600    │
│ +example.com:192.0.2.1:3600            │
│ @example.com:192.0.2.10:mail:10:3600   │
│ Cwww.example.com:example.com:3600      │
└────────────────────────────────────────┘
           │
           ▼  dnsscience-convert -f djbdns

Output (DNSScienced):
┌────────────────────────────────────────┐
│ zone: example.com                      │
│ ttl: 3600                              │
│                                        │
│ nameservers:                           │
│   - ns1.example.com                    │
│   - ns2.example.com                    │
│                                        │
│ mx:                                    │
│   - priority: 10                       │
│     host: mail.example.com             │
│                                        │
│ records:                               │
│   "@":                                 │
│     A: 192.0.2.1                       │
│   ns1:                                 │
│     A: 192.0.2.53                      │
│   ns2:                                 │
│     A: 198.51.100.53                   │
│   mail:                                │
│     A: 192.0.2.10                      │
│   www:                                 │
│     CNAME: "@"                         │
└────────────────────────────────────────┘
```

### dnsscience-checkzone

Zone file validator with detailed error reporting.

```
Usage: dnsscience-checkzone [OPTIONS] <ZONE_FILE>

Options:
  -f, --format <FORMAT>    Zone format [dnsscienced|bind|djbdns|auto]
  -o, --origin <DOMAIN>    Zone origin (if not in file)
  -l, --level <LEVEL>      Check level [syntax|semantic|full] (default: full)
      --dnssec             Validate DNSSEC records
      --check-ns           Verify NS records are resolvable
      --check-mx           Verify MX records are resolvable
  -w, --warnings           Show warnings (not just errors)
  -j, --json               Output in JSON format
  -v, --verbose            Verbose output
  -q, --quiet              Only show errors

Checks Performed:
  Syntax Level:
    - Valid zone format
    - Record type syntax
    - TTL values
    - Name format

  Semantic Level:
    - SOA record present
    - NS records present
    - CNAME conflicts
    - MX/NS pointing to CNAME
    - Orphan glue records
    - TTL consistency

  Full Level (default):
    - All semantic checks
    - DNSSEC chain validation
    - RFC compliance
    - Best practice suggestions
```

### Error Message Examples

```
$ dnsscience-checkzone example.com.dnszone

Checking zone: example.com
Format: dnsscienced (detected)

✗ ERROR at records.www (line 45):
  CNAME record 'www' conflicts with existing A record

  Found:
    www:
      A: 192.0.2.1        ← line 42
      CNAME: "@"          ← line 45 (conflict)

  Fix: Remove either the A record or the CNAME record.
       A name cannot have both CNAME and other record types.

  RFC: RFC 1034 Section 3.6.2

⚠ WARNING at records._dmarc:
  DMARC policy 'p=none' provides no protection

  Found:
    _dmarc:
      TXT: "v=DMARC1; p=none; ..."

  Suggestion: Consider 'p=quarantine' or 'p=reject' for production

✓ PASS: SOA record present
✓ PASS: NS records present (2 nameservers)
✓ PASS: All MX hosts have A/AAAA records
✓ PASS: No orphan glue records

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Results: 1 error, 1 warning, 47 records checked
Zone is INVALID - cannot be loaded
```

### dnsscience-zonediff

Compare zone files and show changes.

```
Usage: dnsscience-zonediff [OPTIONS] <FILE1> <FILE2>

Options:
  -f, --format <FORMAT>    Force format interpretation
  -c, --context <N>        Lines of context (default: 3)
      --ignore-serial      Ignore serial number changes
      --ignore-ttl         Ignore TTL changes
      --ignore-comments    Ignore comment changes
  -s, --summary            Show summary only
  -j, --json               Output in JSON format
      --ixfr               Generate IXFR-style diff
```

---

## 8. DNSSEC Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNSSEC Subsystem                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Key Management                         │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │  │
│  │  │     KSK     │  │     ZSK     │  │  Trust      │      │  │
│  │  │             │  │             │  │  Anchors    │      │  │
│  │  │ • Generate  │  │ • Generate  │  │             │      │  │
│  │  │ • Rollover  │  │ • Rollover  │  │ • RFC 5011  │      │  │
│  │  │ • DS submit │  │ • Auto-sign │  │ • Manual    │      │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Signing Engine                         │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │  │
│  │  │   Online    │  │   Offline   │  │    HSM      │      │  │
│  │  │   Signing   │  │   Signing   │  │   Support   │      │  │
│  │  │             │  │             │  │             │      │  │
│  │  │ • On-the-fly│  │ • Pre-sign  │  │ • PKCS#11   │      │  │
│  │  │ • Dynamic   │  │ • Batch     │  │ • Cloud KMS │      │  │
│  │  │ • Low latency│ │ • Verified  │  │ • Vault     │      │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   Validation Engine                       │  │
│  │                                                           │  │
│  │  • Chain of trust verification                           │  │
│  │  • Algorithm support (per RFC 8624)                      │  │
│  │  • NSEC/NSEC3 proof verification                         │  │
│  │  • Aggressive NSEC caching (RFC 8198)                    │  │
│  │  • Trust anchor management                                │  │
│  │  • Negative trust anchors                                 │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Algorithm Support (RFC 8624)

| Algorithm | Number | Status | Support |
|-----------|--------|--------|---------|
| RSASHA256 | 8 | MUST | ✓ |
| RSASHA512 | 10 | MUST | ✓ |
| ECDSAP256SHA256 | 13 | MUST | ✓ (recommended) |
| ECDSAP384SHA384 | 14 | MAY | ✓ |
| ED25519 | 15 | RECOMMENDED | ✓ |
| ED448 | 16 | MAY | ✓ |

### Key Rollover Automation

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZSK Rollover Timeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Day 0        Day 7        Day 14       Day 21       Day 28    │
│    │            │            │            │            │        │
│    ▼            ▼            ▼            ▼            ▼        │
│  ┌────┐      ┌────┐      ┌────┐      ┌────┐      ┌────┐       │
│  │Gen │      │Pub │      │Act │      │Inact│     │Del │       │
│  │ZSK2│ ──► │ZSK2│ ──► │ZSK2│ ──► │ZSK1│ ──► │ZSK1│       │
│  └────┘      └────┘      └────┘      └────┘      └────┘       │
│                                                                 │
│  States:                                                        │
│    Generated → Published → Active → Inactive → Deleted         │
│                                                                 │
│  Pre-publication method (RFC 6781 recommended)                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    KSK Rollover Timeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Day 0      Day 30      Day 60      Day 90     Day 120         │
│    │           │           │           │           │            │
│    ▼           ▼           ▼           ▼           ▼            │
│  ┌────┐     ┌────┐     ┌────┐     ┌────┐     ┌────┐           │
│  │Gen │     │Pub │     │Submit│    │Wait │    │Del │           │
│  │KSK2│ ─► │KSK2│ ─► │DS   │ ─► │for  │ ─► │KSK1│           │
│  └────┘     └────┘     └────┘     │prop │     └────┘           │
│                                    └────┘                       │
│                                                                 │
│  Double-DS method for KSK rollover                             │
│  Requires parent zone DS record update                         │
└─────────────────────────────────────────────────────────────────┘
```

### NSEC3 Configuration (RFC 9276 Compliant)

```yaml
# Modern NSEC3 settings per RFC 9276
dnssec:
  nsec3:
    enabled: yes
    iterations: 0        # RFC 9276: MUST be 0
    salt-length: 0       # RFC 9276: SHOULD be 0
    opt-out: no          # Only for very large zones

# Why these values?
# - iterations=0: Additional iterations provide no meaningful security
#   against offline dictionary attacks while impacting performance
# - salt-length=0: Salts provided no practical security benefit
#   and complicated key rollovers
```

### CLI Tools

#### dnsscience-keygen

```
Usage: dnsscience-keygen [OPTIONS] <ZONE>

Options:
  -a, --algorithm <ALG>    Algorithm [ECDSAP256SHA256|ED25519|...]
                           (default: ECDSAP256SHA256)
  -k, --ksk                Generate Key Signing Key
  -z, --zsk                Generate Zone Signing Key (default)
  -b, --bits <N>           Key size (RSA only)
  -d, --directory <DIR>    Key directory
  -t, --ttl <TTL>          DNSKEY TTL
      --hsm <CONFIG>       Use HSM for key storage
  -v, --verbose            Verbose output

Output:
  Kexample.com.+013+12345.key      # Public key (DNSKEY)
  Kexample.com.+013+12345.private  # Private key
  Kexample.com.+013+12345.ds       # DS record for parent
```

#### dnsscience-signzone

```
Usage: dnsscience-signzone [OPTIONS] <ZONE_FILE>

Options:
  -k, --ksk <KEY>          KSK private key file
  -z, --zsk <KEY>          ZSK private key file
  -d, --directory <DIR>    Key directory (auto-find keys)
  -o, --output <FILE>      Output signed zone
  -e, --expire <DURATION>  Signature expiration (default: 30d)
  -i, --inception <TIME>   Signature inception (default: now-1h)
  -r, --refresh <DURATION> Re-sign when <DURATION> until expiry
      --nsec3              Use NSEC3 (default: NSEC)
      --serial <ACTION>    Serial handling [keep|increment|unixtime]
  -v, --verbose            Verbose output

Example:
  dnsscience-signzone -d /etc/dnsscienced/keys/example.com \
                      -o example.com.signed \
                      example.com.dnszone
```

---

## 9. DDoS Mitigation Architecture

### Attack Vector Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNS Attack Vectors                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Amplification Attacks                                          │
│  ├── ANY queries (deprecated by RFC 8482)                      │
│  ├── Large TXT records                                          │
│  ├── DNSSEC responses (large RRSIG)                            │
│  └── Zone transfers (AXFR)                                      │
│                                                                 │
│  Resource Exhaustion                                            │
│  ├── Query floods                                               │
│  ├── Random subdomain attacks (NXDOMAIN)                       │
│  ├── TCP connection exhaustion                                  │
│  └── DNSSEC validation load                                     │
│                                                                 │
│  Cache Poisoning                                                │
│  ├── Birthday attacks                                           │
│  ├── Kaminsky attack                                            │
│  └── Side-channel attacks                                       │
│                                                                 │
│  Protocol Abuse                                                 │
│  ├── Reflection attacks                                         │
│  ├── Water torture (slow drip)                                 │
│  └── Phantom domain attacks                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Layer Defense

```
┌─────────────────────────────────────────────────────────────────┐
│                    Defense Layers                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: Network/Transport                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • SYN cookies for TCP                                    │   │
│  │ • UDP source validation                                  │   │
│  │ • BPF/XDP packet filtering                              │   │
│  │ • Connection limits per IP                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│                          ▼                                      │
│  Layer 2: DNS Protocol                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • DNS Cookies (RFC 7873)                                │   │
│  │ • Response Rate Limiting (RRL)                          │   │
│  │ • TC bit forcing (force TCP)                            │   │
│  │ • EDNS buffer size limits                               │   │
│  │ • Minimal responses                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│                          ▼                                      │
│  Layer 3: Application Logic                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • Query pattern analysis                                 │   │
│  │ • NXDOMAIN rate limiting                                │   │
│  │ • Recursive client quotas                               │   │
│  │ • Zone transfer restrictions                            │   │
│  │ • Allowlist/blocklist                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│                          ▼                                      │
│  Layer 4: Intelligence                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • Anomaly detection (ML-based)                          │   │
│  │ • Threat intelligence feeds                             │   │
│  │ • Reputation scoring                                     │   │
│  │ • dnsscience.io integration                             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Response Rate Limiting (RRL)

```nginx
# RRL Configuration
rate-limit {
    # Authoritative server settings
    responses-per-second 10;      # Identical responses/sec
    errors-per-second 5;          # SERVFAIL, FORMERR/sec
    nxdomains-per-second 5;       # NXDOMAIN responses/sec
    referrals-per-second 10;      # Referral responses/sec
    nodata-per-second 10;         # NODATA responses/sec
    all-per-second 100;           # Total responses/sec

    # Timing
    window 15;                    # Sliding window (seconds)

    # Slip: 1 in N responses sent with TC bit
    # slip=0: drop all, slip=1: all TC, slip=2: 50% TC
    slip 2;

    # Exemptions
    exempt-clients {
        127.0.0.0/8;
        ::1/128;
        trusted-networks;
    };

    # Logging
    log-only no;                  # Set to yes to test
    log-threshold 10;             # Log when >N dropped
}
```

### DNS Cookies (RFC 7873)

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNS Cookie Exchange                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Initial Query (no cookie):                                     │
│  Client ──────────────────────────────────────────────► Server  │
│          Query: example.com A                                   │
│          OPT: COOKIE=<client-cookie>                           │
│                                                                 │
│  Response (with server cookie):                                 │
│  Client ◄────────────────────────────────────────────── Server  │
│          Answer: 192.0.2.1                                      │
│          OPT: COOKIE=<client-cookie><server-cookie>            │
│                                                                 │
│  Subsequent Query (with valid cookie):                          │
│  Client ──────────────────────────────────────────────► Server  │
│          Query: www.example.com A                               │
│          OPT: COOKIE=<client-cookie><server-cookie>            │
│                                                                 │
│  Benefits:                                                      │
│  • Proves client IP is not spoofed                             │
│  • Enables stateless TCP-like verification                     │
│  • Allows bypassing rate limits for valid clients              │
│  • Server cookie rotates periodically (security)               │
└─────────────────────────────────────────────────────────────────┘
```

### Attack Detection Heuristics

```go
// Pseudo-code for attack detection

type AttackDetector struct {
    // Sliding window counters
    queryRates    map[string]*RateCounter  // per-client
    nxdomainRates map[string]*RateCounter  // per-zone
    patternDB     *PatternDatabase

    // Thresholds
    thresholds AttackThresholds
}

type AttackThresholds struct {
    QueriesPerSecond      int     // Normal: 50-100
    NXDomainRatio         float64 // Normal: <10%
    RandomSubdomainRatio  float64 // Normal: <5%
    UniqueQNamesRatio     float64 // Normal: varies
    ResponseSizeAvg       int     // Normal: <512 bytes
}

// Random subdomain attack detection
func (d *AttackDetector) detectRandomSubdomain(zone string) bool {
    // High ratio of unique query names = random subdomain attack
    window := d.queryWindows[zone]

    uniqueRatio := float64(window.UniqueNames) / float64(window.TotalQueries)
    nxRatio := float64(window.NXDOMAINs) / float64(window.TotalQueries)

    // Attack signature: many unique names, high NXDOMAIN rate
    return uniqueRatio > 0.8 && nxRatio > 0.7
}

// Amplification attack detection
func (d *AttackDetector) detectAmplification(client string) bool {
    window := d.clientWindows[client]

    // Attack signature: requests for ANY/large records from many sources
    amplificationTypes := []string{"ANY", "TXT", "DNSKEY", "RRSIG"}

    typeRatio := window.CountTypes(amplificationTypes) / window.TotalQueries
    avgResponseSize := window.TotalResponseBytes / window.TotalQueries

    return typeRatio > 0.5 && avgResponseSize > 2000
}
```

### Metrics and Alerting

```yaml
# Prometheus metrics exposed
dns_queries_total{type, rcode, transport}
dns_responses_latency_seconds{quantile}
dns_cache_hits_total
dns_cache_misses_total
dns_rate_limit_drops_total{reason}
dns_cookie_valid_total
dns_cookie_invalid_total
dns_attack_detected_total{type}
dns_dnssec_validations_total{result}

# Alert rules
groups:
  - name: dns_ddos_alerts
    rules:
      - alert: DNSQueryRateHigh
        expr: rate(dns_queries_total[5m]) > 10000
        for: 2m
        labels:
          severity: warning

      - alert: DNSNXDomainRateHigh
        expr: rate(dns_queries_total{rcode="NXDOMAIN"}[5m]) / rate(dns_queries_total[5m]) > 0.3
        for: 5m
        labels:
          severity: critical

      - alert: DNSAmplificationDetected
        expr: dns_attack_detected_total{type="amplification"} > 0
        for: 1m
        labels:
          severity: critical
```

---

## 10. Plugin/Module System

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Plugin Architecture                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Plugin Manager                        │   │
│  │                                                          │   │
│  │  • Plugin discovery and loading                         │   │
│  │  • Lifecycle management (init, start, stop, reload)     │   │
│  │  • Dependency resolution                                 │   │
│  │  • Hot reload support                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│           ┌──────────────┴──────────────┐                      │
│           ▼                              ▼                      │
│  ┌─────────────────┐          ┌─────────────────┐             │
│  │  Native Plugins │          │  Script Plugins │             │
│  │    (Go)         │          │   (Lua/Starlark)│             │
│  │                 │          │                 │              │
│  │ • Compiled .so  │          │ • Interpreted   │             │
│  │ • Full API      │          │ • Sandboxed     │             │
│  │ • High perf     │          │ • Safe reload   │             │
│  └─────────────────┘          └─────────────────┘             │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Hook Points                           │   │
│  │                                                          │   │
│  │  Query Processing Pipeline:                             │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐         │   │
│  │  │PreQ  │→│Route │→│Resolve│→│PostR │→│Log   │         │   │
│  │  │Hook  │ │Hook  │ │Hook   │ │Hook  │ │Hook  │         │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘         │   │
│  │                                                          │   │
│  │  Server Events:                                         │   │
│  │  • OnStart, OnStop, OnReload                           │   │
│  │  • OnZoneLoad, OnZoneUpdate                            │   │
│  │  • OnCacheHit, OnCacheMiss                             │   │
│  │  • OnValidationSuccess, OnValidationFailure            │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Plugin Interface (Go)

```go
// Plugin interface for native Go plugins
package plugin

import (
    "github.com/dnsscience/dnsscienced/dns"
)

// Plugin is the interface all plugins must implement
type Plugin interface {
    // Metadata
    Name() string
    Version() string
    Description() string

    // Lifecycle
    Init(config map[string]interface{}) error
    Start() error
    Stop() error
    Reload(config map[string]interface{}) error
}

// QueryPlugin hooks into query processing
type QueryPlugin interface {
    Plugin

    // PreQuery is called before query processing
    // Return modified query or nil to use original
    // Return error to reject query
    PreQuery(ctx *QueryContext) (*dns.Msg, error)

    // PostResponse is called after response is generated
    // Return modified response or nil to use original
    PostResponse(ctx *QueryContext, response *dns.Msg) (*dns.Msg, error)
}

// QueryContext provides query metadata
type QueryContext struct {
    Query       *dns.Msg
    Client      net.Addr
    Transport   Transport  // UDP, TCP, DoT, DoH, DoQ
    Timestamp   time.Time
    Metadata    map[string]interface{}
}

// ZonePlugin hooks into zone management
type ZonePlugin interface {
    Plugin

    OnZoneLoad(zone *Zone) error
    OnZoneUpdate(zone *Zone, changes []RRChange) error
}

// CachePlugin hooks into caching
type CachePlugin interface {
    Plugin

    OnCacheHit(key string, entry *CacheEntry) error
    OnCacheMiss(key string) error
    OnCacheEvict(key string, entry *CacheEntry) error
}
```

### Example Plugins

#### GeoIP Plugin

```go
// Plugin: geoip
// Returns different responses based on client location

package main

import (
    "github.com/dnsscience/dnsscienced/plugin"
    "github.com/oschwald/geoip2-golang"
)

type GeoIPPlugin struct {
    db       *geoip2.Reader
    mappings map[string]map[string][]string  // zone -> country -> IPs
}

func (p *GeoIPPlugin) Name() string { return "geoip" }
func (p *GeoIPPlugin) Version() string { return "1.0.0" }

func (p *GeoIPPlugin) Init(config map[string]interface{}) error {
    dbPath := config["database"].(string)
    var err error
    p.db, err = geoip2.Open(dbPath)
    if err != nil {
        return err
    }

    // Load country -> IP mappings from config
    p.mappings = loadMappings(config["mappings"])
    return nil
}

func (p *GeoIPPlugin) PostResponse(ctx *plugin.QueryContext, resp *dns.Msg) (*dns.Msg, error) {
    // Get client country
    ip := extractIP(ctx.Client)
    record, err := p.db.Country(ip)
    if err != nil {
        return nil, nil  // Use original response
    }

    country := record.Country.IsoCode
    zone := dns.Fqdn(resp.Question[0].Name)

    // Check if we have geo-specific IPs for this zone
    if zoneMap, ok := p.mappings[zone]; ok {
        if ips, ok := zoneMap[country]; ok {
            return p.rewriteResponse(resp, ips), nil
        }
    }

    return nil, nil  // Use original response
}

// Export plugin
var Plugin GeoIPPlugin
```

#### Blocklist Plugin

```go
// Plugin: blocklist
// Blocks queries to domains on blocklist

package main

type BlocklistPlugin struct {
    blocklist  *bloom.Filter
    blocklistFile string
    action     string  // NXDOMAIN, REFUSED, redirect
    redirectIP net.IP
}

func (p *BlocklistPlugin) PreQuery(ctx *plugin.QueryContext) (*dns.Msg, error) {
    qname := ctx.Query.Question[0].Name

    if p.blocklist.Contains([]byte(qname)) {
        switch p.action {
        case "NXDOMAIN":
            return p.nxdomainResponse(ctx.Query), nil
        case "REFUSED":
            return p.refusedResponse(ctx.Query), nil
        case "redirect":
            return p.redirectResponse(ctx.Query, p.redirectIP), nil
        }
    }

    return nil, nil  // Continue normal processing
}

var Plugin BlocklistPlugin
```

### Lua Plugin Example

```lua
-- Plugin: custom-logging
-- Custom query logging with additional metadata

local plugin = {
    name = "custom-logging",
    version = "1.0.0"
}

local log_file = nil

function plugin.init(config)
    log_file = io.open(config.log_path, "a")
    return true
end

function plugin.post_response(ctx, response)
    local log_entry = {
        timestamp = os.date("%Y-%m-%dT%H:%M:%S"),
        client = ctx.client,
        qname = ctx.query.question[1].name,
        qtype = ctx.query.question[1].type,
        rcode = response.rcode,
        response_time_ms = ctx.response_time * 1000,
        cache_hit = ctx.cache_hit,
        dnssec_validated = ctx.dnssec_validated
    }

    log_file:write(json.encode(log_entry) .. "\n")
    log_file:flush()

    return nil  -- Don't modify response
end

function plugin.stop()
    if log_file then
        log_file:close()
    end
end

return plugin
```

### Plugin Configuration

```nginx
# In dnsscienced.conf

plugins {
    directory "/usr/lib/dnsscienced/plugins";

    # Native Go plugin
    plugin geoip {
        enabled yes;
        database "/var/lib/dnsscienced/GeoLite2-Country.mmdb";
        mappings {
            "cdn.example.com" {
                US { 192.0.2.1; 192.0.2.2; };
                EU { 198.51.100.1; 198.51.100.2; };
                default { 203.0.113.1; };
            };
        };
    };

    # Lua script plugin
    plugin custom-logging {
        enabled yes;
        type lua;
        script "/etc/dnsscienced/plugins/custom-logging.lua";
        config {
            log_path "/var/log/dnsscienced/custom.log";
        };
    };

    # Blocklist plugin
    plugin blocklist {
        enabled yes;
        source "https://blocklist.dnsscience.io/malware.txt";
        update-interval 1h;
        action NXDOMAIN;
    };
}
```

---

## Appendix A: Directory Structure

```
/etc/dnsscienced/
├── dnsscienced.conf          # Main configuration
├── authd.conf                # Authoritative server config
├── cached.conf               # Recursive resolver config
├── acl.conf                  # Access control lists
├── keys.conf                 # TSIG keys (mode 0600)
├── root.hints                # Root server hints
├── root.keys                 # DNSSEC trust anchors
├── tls/
│   ├── cert.pem              # TLS certificate
│   └── key.pem               # TLS private key
├── rpz/
│   └── local-block.zone      # Local RPZ blocklist
└── plugins/
    └── custom-logging.lua    # Custom plugins

/var/lib/dnsscienced/
├── zones/
│   ├── example.com.dnszone   # Zone files
│   ├── example.com.signed    # Signed zones
│   └── catalog/              # Catalog zone directory
├── keys/
│   └── example.com/          # DNSSEC keys per zone
│       ├── Kexample.com.+013+12345.key
│       └── Kexample.com.+013+12345.private
├── cache/                    # Persistent cache (optional)
└── journal/                  # Dynamic update journals

/var/log/dnsscienced/
├── dnsscienced.log           # General log
├── queries.log               # Query log
└── security.log              # Security events

/run/dnsscienced/
├── dnsscienced.pid           # PID file
├── authd.sock                # Control socket (authd)
└── cached.sock               # Control socket (cached)
```

---

## Appendix B: CLI Quick Reference

```bash
# Zone management
dnsscience-checkzone example.com.dnszone
dnsscience-convert -f bind example.com.zone -o example.com.dnszone
dnsscience-zonediff old.dnszone new.dnszone

# DNSSEC
dnsscience-keygen -a ECDSAP256SHA256 -k example.com  # Generate KSK
dnsscience-keygen -a ECDSAP256SHA256 example.com     # Generate ZSK
dnsscience-signzone -d /etc/dnsscienced/keys/example.com example.com.dnszone

# Runtime control
dnsscience-ctl status
dnsscience-ctl reload                    # Reload all
dnsscience-ctl reload zone example.com   # Reload specific zone
dnsscience-ctl freeze zone example.com   # Freeze for editing
dnsscience-ctl thaw zone example.com     # Thaw after editing
dnsscience-ctl flush cache               # Flush resolver cache
dnsscience-ctl stats                     # Show statistics

# Debugging
dnsscience-dig @localhost example.com A
dnsscience-dig +dnssec @localhost example.com A
dnsscience-dig +trace example.com A
dnsscience-stats -i 1                    # Live statistics
```

---

## Appendix C: Migration Checklist

### From BIND

- [ ] Convert named.conf → dnsscienced.conf + authd.conf/cached.conf
- [ ] Convert zone files → dnsscienced format (or keep as bind format)
- [ ] Migrate TSIG keys
- [ ] Update firewall rules if port changes
- [ ] Test zone transfers with secondaries
- [ ] Verify DNSSEC chain if signed
- [ ] Update monitoring/alerting
- [ ] Plan cutover window

### From djbdns/tinydns

- [ ] Convert data file → dnsscienced zones
- [ ] Create proper SOA records (djbdns auto-generates)
- [ ] Add missing NS glue records
- [ ] Configure zone transfers (djbdns uses rsync)
- [ ] Set up DNSSEC (djbdns doesn't support)
- [ ] Configure logging (replace multilog)

---

*Document Version: 1.0*
*Last Updated: 2024*
*Authors: DNSScience Team*
