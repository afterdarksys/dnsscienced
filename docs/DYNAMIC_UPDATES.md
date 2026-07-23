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

Prerequisites are evaluated against the live zone while updates for that zone
are serialized. Mutations are applied in order to a clone, structural
invariants are validated, the SOA serial is advanced, and the replacement is
published atomically. A failed prerequisite or invalid mutation leaves the live
zone unchanged. Successful responses are signed with the request key.

When `persist_updates` is true, the validated replacement is written to the
configured zone file using a temporary file and atomic rename. The in-memory
update is acknowledged before disk persistence, so a host crash in that short
window can leave the on-disk serial one update behind. Deployments that require
strict write-ahead durability should keep dynamic updates disabled until a
persistent journal is configured.
