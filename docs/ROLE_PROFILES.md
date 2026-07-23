# Validated deployment roles

Set the top-level `role` field to make DNSScienced apply secure mode defaults
and reject incompatible configuration before opening listeners.

| Role | Applied mode | Fail-closed checks |
|---|---|---|
| `authoritative` | authoritative on, recursion off | Rejects recursion and all forwarding configuration |
| `recursive` | recursion on, authoritative off | Rejects primary/secondary zones, catalogs, and `zones_dir` |
| `forwarder` | recursion on, authoritative off, global `forward_mode: only` | Requires a global upstream and rejects direct fallback or authoritative data |
| `local-root` | authoritative on, recursion off | Requires exactly one explicit `.` primary/secondary zone, loopback-only listeners, no forwarding, catalogs, or RPZ |
| `public-root` | authoritative on, recursion off | Requires exactly one explicit `.` primary/secondary zone and rejects forwarding, catalogs, `zones_dir`, and tenant RPZ policy |
| `custom` | no mode changes | Explicit opt-in for intentionally combined roles |

An omitted role preserves legacy configuration compatibility. Carrier-grade
deployments should select a role explicitly.

## Examples

Authoritative primary:

```yaml
role: authoritative
server:
  udp_addr: "0.0.0.0:53"
  tcp_addr: "0.0.0.0:53"
zones:
  - name: example.
    type: primary
    file: /etc/dnsscienced/zones/example.bind
```

Strict forwarder that never falls back to direct iteration:

```yaml
role: forwarder
server:
  recursion_allowed_cidrs:
    - 10.0.0.0/8
forwarders:
  "":
    - 9.9.9.9:53
    - 149.112.112.112:53
```

Local root:

```yaml
role: local-root
server:
  udp_addr: "127.0.0.1:53"
  tcp_addr: "127.0.0.1:53"
zones:
  - name: "."
    type: secondary
    masters:
      - 192.0.2.53:53
    transfer_tsig_key: root-transfer.
```

The profile validates daemon-level isolation; it does not by itself establish
RFC 7720 public-root readiness or RFC 8806 operational conformance. Those gates
also require current authenticated root-zone distribution, DNSSEC material,
protocol interoperability, external monitoring, and deployment evidence.
