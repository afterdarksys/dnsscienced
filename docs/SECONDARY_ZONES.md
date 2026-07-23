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

Current limitation: refresh uses a complete AXFR. True IXFR delta generation and
consumption remains tracked separately.
