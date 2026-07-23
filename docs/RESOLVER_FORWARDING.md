# Resolver Forwarding Modes

DNSScienced supports explicit upstream routing without consulting the host or
ISP resolver:

- `direct` performs iterative resolution from root hints. This is the default
  and bypasses ISP recursive resolvers.
- `first` queries configured recursive forwarders first, then falls back to
  direct iteration if every forwarder times out, refuses, or returns SERVFAIL.
- `only` queries configured forwarders exclusively and fails closed if they are
  unavailable.

Global policy is configured under `server.recursive`; the legacy top-level
`forwarders` map supplies global and conditional upstream lists:

```yaml
server:
  enable_recursive: true
  recursive:
    forward_mode: only

forwarders:
  "":
    - 1.1.1.1:53
    - 9.9.9.9:53
  corp.example:
    - 192.0.2.53:53
```

Conditional forward zones can set their own policy:

```yaml
zones:
  - name: private.example
    type: forward
    forwarders: [192.0.2.54:53]
    forward_mode: only
```

The longest matching suffix wins. Conditional rules default to `only`, which
prevents private names from leaking into public iterative DNS when an internal
resolver is down. Choose `first` explicitly when direct fallback is desired.

Forwarder endpoints must be IP literals with an optional port; DNS hostnames
are rejected so bootstrapping cannot silently depend on the operating system's
ISP-provided resolver. Outbound queries use randomized transaction IDs and
source ports, optional 0x20 case validation, EDNS0 size limits, exact response
question validation, and TCP fallback for truncated UDP replies.
