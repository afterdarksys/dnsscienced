# Response Policy Zones

DNSScienced can load QNAME policies from ordinary BIND or DNSZone files. RPZ
loading is disabled by default.

```yaml
server:
  rpz:
    enabled: true
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

Current support is limited to QNAME triggers. Response-IP, client-IP,
nameserver-name, and nameserver-IP triggers are not yet enforced.
