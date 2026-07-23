# Secondary Zones

DNSScienced can serve secondary authoritative zones acquired from one or more
primary servers. It completes an initial full transfer before opening DNS
listeners, publishes the validated zone atomically, and refreshes it from the
transferred SOA timers or an ordinary RFC 1996 SOA NOTIFY.

```yaml
tsig_keys:
  - name: "secondary-xfer.example."
    algorithm: "hmac-sha256"
    secret: "<base64-secret>"

zones:
  - name: "secondary.example."
    type: "secondary"
    masters:
      - "192.0.2.10:53"
      - "[2001:db8::10]:53"
    transfer_source: "192.0.2.20"
    transfer_tsig_key: "secondary-xfer.example."
    allow_axfr_fallback: true
    min_refresh_time: 5m
    max_refresh_time: 24h
    min_retry_time: 30s
    max_retry_time: 1h
```

`masters` is required. A missing port defaults to 53. Master hostnames are
resolved at startup and their addresses form the inbound NOTIFY allowlist.
Using fixed IP addresses avoids DNS-dependent startup and makes authorization
changes explicit.

When `transfer_tsig_key` is set:

- outbound AXFR is signed with that named key;
- an inbound SOA NOTIFY must have a valid TSIG with the same key name; and
- the NOTIFY source address must match a configured master.

Without a transfer key, the source-address allowlist still applies, but the
transfer and NOTIFY are unauthenticated. Use TSIG in production.

The manager coalesces repeated NOTIFY messages per zone and serializes transfers,
so a NOTIFY flood cannot create concurrent transfers for the same zone. A newly
transferred serial replaces the current zone only when RFC 1982 serial arithmetic
considers it newer. Malformed transfers, wrong origins, non-IN records, missing
SOA/NS records, and transfer failures leave the last valid zone active.

`refresh_interval` overrides the SOA refresh value when nonzero. Otherwise the
manager uses SOA refresh and retry values, constrained by the optional min/max
bounds.

After the initial AXFR, refresh requests use IXFR with the currently published
serial. A complete, ordered delta chain is applied to a clone and validated
before one atomic publish. If a primary has purged the required history, a full
AXFR is accepted when `allow_axfr_fallback` is true. Set it to false to fail the
refresh and retain the last valid zone instead.

DNSScienced also serves IXFR from a bounded in-memory journal of the 100 most
recent zone replacements. Dynamic updates, admin replacements, and secondary
refreshes generate deleted/added RR deltas. A client with the current or a newer
RFC 1982 serial receives one SOA; a client with an available history receives
oldest-to-newest RFC 1995 difference sequences; otherwise normal AXFR fallback
policy applies.

The journal is intentionally not persisted yet. After restart, existing
secondaries fall back to AXFR until new deltas accumulate.
