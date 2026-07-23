# Response Policy Zones

DNSScienced loads all five standard RPZ trigger families from ordinary BIND or
DNSZone files. RPZ loading is disabled by default.

```yaml
server:
  rpz:
    enabled: true
    # NSDNAME/NSIP data-path discovery controls. min_ns_dots: 1 skips root.
    min_ns_dots: 1
    max_ns_lookups: 64
    nameserver_lookup_timeout: 2s
    zones:
      - name: security-policy
        file: /etc/dnsscienced/rpz/security-policy.bind
        reason: operator security policy
        priority: 10
        regex_rules:
          - pattern: '(^|\.)blocked-[0-9]+\.example\.$'
            action: nxdomain
            reason: generated blocked hostnames
```

Lower priority values are evaluated first. Configuration order breaks ties.
The first matching zone determines the result, including `rpz-passthru`.

Policy files use standard QNAME CNAME actions:

```dns
$ORIGIN rpz.example.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60
@ IN NS localhost.

malware.example.com IN CNAME .                  ; NXDOMAIN
telemetry.example.com IN CNAME *.               ; NODATA
safe.example.com IN CNAME rpz-passthru.         ; allow
abusive.example.com IN CNAME rpz-drop.          ; silent drop
sinkholed.example.com IN CNAME sinkhole.local.  ; CNAME rewrite
*.tracking.example.com IN CNAME .               ; wildcard

24.0.2.0.192.rpz-client-ip IN CNAME .           ; client 192.0.2.0/24
24.0.113.0.203.rpz-ip IN CNAME .                 ; answer 203.0.113.0/24
ns.hostile.example.rpz-nsdname IN CNAME .        ; nameserver name
*.bad-ns.example.rpz-nsdname IN CNAME .          ; nameserver-name wildcard
24.0.51.100.198.rpz-nsip IN CNAME .              ; nameserver 198.51.100.0/24
```

Send `SIGHUP` to atomically reload all configured policy zones. DNSScienced
parses every source before swapping the live policy. If any source is invalid,
the reload fails and the last valid aggregate remains active.

Policy responses include Extended DNS Error code 17 (`Filtered`) when the
client sends EDNS. Matches are exported as
`dnsscienced_rpz_hits_total{zone,action,source}`.

Regex rules are checked after exact and wildcard rules in the same policy zone.
Supported actions are `nxdomain`, `nodata`, `passthru`, `drop`, and `rewrite`;
`rewrite` also requires `target`.

Policy zones are ordered first. Within one zone, trigger precedence is
client-IP, QNAME, response-IP, NSDNAME, then NSIP. IP rules use longest
internal-prefix matching; NSDNAME ties use RFC 4034 canonical DNS name order.
Exact NSDNAME rules beat wildcard rules, and a `*.` rule does not match its
apex.

NSDNAME and NSIP require data that usually is not present in the client-facing
answer. When either family is configured, the recursive server walks ancestor
NS names for every answer RRset and resolves nameserver addresses only when an
NSIP rule requires them. These internal requests use the normal cache,
singleflight suppression, DNSSEC validation, worker limits, and upstream mode.
`min_ns_dots` controls where the walk stops (`1` skips root; `0` includes it),
`max_ns_lookups` bounds total internal NS/A/AAAA requests to 1–256, and
`nameserver_lookup_timeout` bounds the whole walk to 10ms–30s. Defaults are
`1`, `64`, and `2s`. A timeout or failed internal lookup leaves any already
discovered, truthful data eligible for matching and otherwise preserves the
original response.

RPZ is described by the archived IETF DNSOP RPZ Internet-Draft rather than a
standards-track RFC. DNSScienced follows its trigger encoding, data-path model,
and precedence rules.
