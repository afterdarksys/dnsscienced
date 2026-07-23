# Catalog Zones

DNSScienced's catalog model implements RFC 9432 schema version 2. Catalog zones
are parsed as ordinary IN-class DNS zones and then validated as catalogs before
any reconciliation is planned.

The model recognizes:

- the mandatory single `version.$CATZ TXT "2"` RR;
- member PTR records at `<unique>.zones.$CATZ`;
- zero or more complete TXT RDATA values at
  `group.<unique>.zones.$CATZ`;
- an optional single change-of-ownership PTR at
  `coo.<unique>.zones.$CATZ`; and
- global and member private-use properties with one-or-more-label prefixes
  below `ext`.

Unsupported records and properties are ignored. Invalid data for a supported
property, duplicate member labels, duplicate member-zone targets, non-IN
records, or an invalid ordinary zone make the snapshot unusable as a catalog.
The runtime retains the last accepted catalog snapshot and its published
members when a newly transferred snapshot is broken, expired, or temporarily
unreachable.

Reconciliation is deterministic and side-effect free. It emits explicit
actions for add, remove, reconfigure, member-label reset, change-of-ownership,
and clash reporting. A catalog can remove only zones it originally created.
Existing ownership wins a name clash. A member-label change removes associated
state and recreates the member. Change-of-ownership occurs only while the old
catalog still publishes `coo` and the destination catalog simultaneously lists
the member; a different destination label resets associated state.

Catalog and member transfers use the same IXFR/AXFR and RFC 1996 refresh engine
as explicit secondaries. TSIG is required by default for both layers; legacy
unsigned transfer requires an explicit `allow_unsigned_transfer: true` at the
specific catalog, default-member, or group boundary. Catalog zones remain
private and are never answered from the authoritative zone store.

```yaml
catalog_state_file: /var/lib/dnsscienced/catalog-state.json

tsig_keys:
  - name: catalog-xfer.example.
    algorithm: hmac-sha256
    secret: BASE64_SECRET

catalog_zones:
  - name: catalog.example.
    masters: [192.0.2.10]
    transfer_tsig_key: catalog-xfer.example.
    member_allow_suffixes: [customer.example.]
    member_deny_suffixes: [suspended.customer.example.]

    member_defaults:
      masters: [192.0.2.20]
      transfer_tsig_key: catalog-xfer.example.

    groups:
      blue:
        masters: [192.0.2.21, 192.0.2.22]
        transfer_tsig_key: catalog-xfer.example.
```

Each `group` key matches the concatenated character-strings of one RFC 9432
group TXT RDATA. The first configured match in the catalog's deterministic
group order wins; otherwise `member_defaults` applies.

When `member_allow_suffixes` is non-empty, every member must be at or below one
of those DNS suffixes. `member_deny_suffixes` is evaluated first and overrides
the allow list. A scope violation rejects the complete catalog snapshot and
retains the last-valid fleet state.

State is written atomically with mode `0600` and includes last-valid catalog
records, member-zone records, and catalog ownership. Startup restores those
zones before attempting refresh, so a temporary primary outage does not empty
the authoritative service. Operator-configured primary and secondary names
are reserved: a catalog clash is reported internally and cannot replace them.
