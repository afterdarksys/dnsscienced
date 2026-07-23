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
The runtime integration retains the last accepted catalog snapshot when a
newly transferred snapshot is broken or expired.

Reconciliation is deterministic and side-effect free. It emits explicit
actions for add, remove, reconfigure, member-label reset, change-of-ownership,
and clash reporting. A catalog can remove only zones it originally created.
Existing ownership wins a name clash. A member-label change removes associated
state and recreates the member. Change-of-ownership occurs only while the old
catalog still publishes `coo` and the destination catalog simultaneously lists
the member; a different destination label resets associated state.

Catalog transfer, refresh, zone provisioning, and persisted ownership state are
wired in the subsequent catalog runtime layer. That layer consumes this model
rather than duplicating RFC parsing or ownership decisions.
