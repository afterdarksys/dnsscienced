# Dynamic DNS Updates

DNSScienced supports RFC 2136 UPDATE for primary authoritative zones. UPDATE is
disabled unless the zone explicitly configures both a source-address allowlist
and one or more TSIG identities:

```yaml
tsig_keys:
  - name: "update-key.example."
    algorithm: "hmac-sha256"
    secret: "<base64-secret>"

zones:
  - name: "example."
    type: "primary"
    file: "/etc/dnsscienced/zones/example.zone"
    allow_update:
      - "192.0.2.0/24"
      - "2001:db8:1234::/48"
    update_tsig_keys:
      - "update-key.example."
    persist_updates: true
```

The request must carry a valid TSIG, the authenticated key name must appear in
that zone's `update_tsig_keys`, and the client address must match
`allow_update`. An empty or missing list denies all updates. Key references are
validated at startup, so a misspelled or missing key stops the daemon instead of
silently weakening authorization.

TSIG processing follows RFC 8945: BADKEY and BADSIG errors carry an unsigned
TSIG error record, while BADTIME and acceptable-but-policy-short truncation
errors carry signed BADTIME/BADTRUNC responses. BADTIME includes the server's
48-bit current time. SHA-2 MAC truncation is accepted only at or above the RFC
minimum (the larger of 10 octets and half the algorithm output).

Prerequisites are evaluated against the live zone while updates for that zone
are serialized. Mutations are applied in order to a clone, structural
invariants are validated, the SOA serial is advanced, and the replacement is
published atomically. A failed prerequisite or invalid mutation leaves the live
zone unchanged. Successful responses are signed with the request key.

Authenticated UPDATE request MACs are remembered until their TSIG validity
window expires. Exact duplicates—including concurrent delivery and replay
within TSIG's normal clock-skew allowance—wait for the original transaction and
receive its response code without applying the mutation or advancing the SOA
serial again. The sharded replay cache defaults to 65,536 entries and can be
tuned with `server.update_replay_cache_size`. Size it above the maximum number
of authenticated UPDATEs expected during the largest allowed TSIG window. If
every slot is still valid, new UPDATEs fail closed with SERVFAIL rather than
evicting replay protection. `UpdateReplays` and `UpdateReplayFull` server
statistics plus the `dnsscienced_update_replays_total` and
`dnsscienced_update_replay_cache_saturated_total` Prometheus counters expose
duplicates and saturation.

When `persist_updates` is true, the validated replacement is written to the
configured zone file before it is published or acknowledged. DNSScienced
writes and synchronizes a mode-`0600` temporary file, atomically renames it,
and synchronizes the parent directory. A serialization, write, sync, or rename
failure returns SERVFAIL and leaves the live zone and IXFR journal unchanged.
After the durable commit, the in-memory snapshot is swapped atomically and the
TSIG-signed NOERROR response is sent.

All UPDATE prerequisite evaluation and zone publication share a stable server
mutation boundary with administrative and catalog zone replacements. The lock
is not stored in the replaceable zone snapshot, preventing concurrent requests
that observed an older generation from overwriting a newer committed update.
