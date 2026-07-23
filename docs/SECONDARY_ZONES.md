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
      - "192.0.2.10:853"
      - "[2001:db8::10]:853"
    transfer_source: "192.0.2.20"
    transfer_tsig_key: "secondary-xfer.example."
    transfer_tls:
      server_name: "primary.example.net"
      ca_file: "/etc/dnsscienced/tls/transfer-ca.pem"
      # Optional: configure both fields for mutual TLS.
      cert_file: "/etc/dnsscienced/tls/secondary.pem"
      key_file: "/etc/dnsscienced/tls/secondary-key.pem"
    allow_axfr_fallback: true
    min_refresh_time: 5m
    max_refresh_time: 24h
    min_retry_time: 30s
    max_retry_time: 1h
```

`masters` is required. A missing port defaults to 53 for TCP transfers and to
the RFC 9103 port 853 when `transfer_tls` is configured. Master hostnames are
resolved at startup and their addresses form the inbound NOTIFY allowlist.
Using fixed IP addresses avoids DNS-dependent startup and makes authorization
changes explicit.

`transfer_tls` enables strict RFC 9103 AXFR/IXFR over TLS. DNSScienced requires
TLS 1.3 or later, requires the peer to select ALPN `dot`, verifies
`server_name`, and never falls back to a cleartext transfer. `ca_file` selects
an explicit private trust store; when omitted, the operating system trust store
is used. Configure both `cert_file` and `key_file` to present a client identity
for mutual TLS. There is intentionally no certificate-verification bypass.

TSIG remains required by default even with TLS. This authenticates transfer
requests at the DNS message layer and also secures UDP NOTIFY, while TLS
protects transfer confidentiality and authenticates the channel. Keep the same
strict XoT policy for AXFR and IXFR on every primary and secondary in the
transfer group.

## Primary XFR-over-TLS

Primary servers expose a dedicated streaming XoT listener. It is separate from
general-purpose DoT so AXFR and IXFR retain their multi-message transfer
semantics.

```yaml
server:
  xot:
    enabled: true
    address: ":853"
    cert_file: "/etc/dnsscienced/tls/primary.pem"
    key_file: "/etc/dnsscienced/tls/primary-key.pem"
    client_ca_file: "/etc/dnsscienced/tls/secondary-ca.pem"
    require_client_cert: true

tsig_keys:
  - name: "secondary-xfer.example."
    algorithm: "hmac-sha256"
    secret: "<base64-secret>"

zones:
  - name: "primary.example."
    type: "primary"
    file: "/etc/dnsscienced/zones/primary.example.zone"
    allow_transfer:
      - "192.0.2.0/24"
    transfer_tls_only: true
```

The listener accepts only TLS 1.3 or later with ALPN `dot`. Non-transfer DNS
traffic receives REFUSED with RFC 8914 EDE 21 (Not Supported). The existing
per-zone source ACL and TSIG validation still authorize every AXFR/IXFR
request. When `require_client_cert` is true, the TLS handshake additionally
requires a certificate chaining to `client_ca_file`.

Set `transfer_tls_only: true` on every confidential primary zone. This refuses
AXFR and IXFR on the ordinary TCP listener and prevents a cleartext weak link
in the transfer group. During a controlled migration it may remain false, but
that mode does not provide end-to-end XoT confidentiality. If general DoT is
also enabled, configure it on a different address or port from the dedicated
XoT listener.

`transfer_tsig_key` is required by default:

- outbound AXFR is signed with that named key;
- an inbound SOA NOTIFY must have a valid TSIG with the same key name; and
- the NOTIFY source address must match a configured master.

For a legacy primary that cannot use TSIG, `allow_unsigned_transfer: true`
explicitly permits unauthenticated transfers and NOTIFY. The configured master
source-address allowlist still applies, but source addresses are not
cryptographic identities and UDP source addresses can be spoofed. Do not use
this compatibility mode across an untrusted network.

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

## Primary NOTIFY

Primary zones can notify explicitly configured secondaries after startup,
RFC 2136 UPDATE, or an atomic zone replacement through the admin APIs:

```yaml
tsig_keys:
  - name: "notify-key.example."
    algorithm: "hmac-sha256"
    secret: "<base64-secret>"

server:
  primary_notify_workers: 4

zones:
  - name: "example."
    type: "primary"
    file: "/etc/dnsscienced/zones/example.zone"
    also_notify:
      - "192.0.2.20:53"
      - "[2001:db8::20]:53"
    notify_tsig_key: "notify-key.example."
    notify_timeout: 2s
    notify_retry_backoff: 250ms
    notify_attempts: 3
```

The fixed worker pool routes each zone to one worker, preserving per-zone order
without creating one goroutine per zone. Repeated changes coalesce to the newest
SOA. Each target is tried over UDP with bounded exponential backoff and then
once over TCP. Signed requests require a valid, signed success response.

`notify_tsig_key` is required whenever `also_notify` is configured. A legacy
secondary can be reached without TSIG only when
`allow_unsigned_notify: true` is set explicitly.
