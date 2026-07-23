# RFC 5011 trust-anchor maintenance

DNSScienced can maintain a validating resolver's root trust anchors with the
authenticated state machine from RFC 5011. Configure an initial root DNSKEY
out of band, enable automatic maintenance, and provide a durable state path:

```yaml
server:
  enable_recursive: true
  recursive:
    enable_dnssec: true
    dnssec:
      trust_anchor_file: /etc/dnsscienced/root.key
      auto_trust_anchor: true
      trust_anchor_state_file: /var/lib/dnsscienced/managed-keys.json
      trust_anchor_update: 168h
```

The initial file bootstraps trust only when the state file does not yet exist.
After that, the versioned state file is authoritative. DNSScienced refuses
automatic mode without a state path, rejects corrupt or broadly permissioned
state, writes updates atomically with mode `0600`, and synchronizes both the file
and its directory before publishing a changed in-memory anchor set.

New SEP keys remain pending for at least 30 days (or the original DNSKEY TTL,
whichever is longer) and must appear in every authenticated observation. A fresh
authenticated observation after the deadline promotes the key. A valid
self-signed REVOKE transition disables a key immediately; removed keys remain
tombstoned so they cannot be learned again.

Active refresh and retry delays are derived from the DNSKEY TTL and RRSIG
expiration interval and are clamped to RFC 5011's one-hour minimum. The optional
`trust_anchor_update` value can request a shorter interval but cannot violate
that minimum.
