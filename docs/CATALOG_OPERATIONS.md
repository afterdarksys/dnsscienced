# Catalog Zone Operations Runbook

This runbook covers production rollout, migration, rollback, backup, and
disaster recovery for DNSScienced RFC 9432 catalog consumers. Read
`CATALOG_ZONES.md` first for the data model and configuration reference.

## Safety invariants

Treat a catalog producer as a privileged control-plane principal. One valid
catalog change can provision or withdraw a large authoritative fleet.

- Authenticate catalog and member transfers with separate TSIG keys.
- Limit member names with `member_allow_suffixes` and
  `member_deny_suffixes`.
- Start every migration in `dry_run` mode.
- Set `approval_required_above` below the number of zones whose simultaneous
  loss would violate the service SLO.
- Bind exceptional approval to the exact incoming SOA serial with
  `approved_serial`.
- Back up the catalog state file and configuration before changing ownership.
- Monitor catalog health, transfer failures, pending action counts, and audit
  events throughout a rollout.
- Never place TSIG secrets in catalog records or custom properties.

Catalog zones stay outside the authoritative query store. Operators inspect
them through the authenticated admin API rather than exposing their contents
over ordinary DNS QUERY.

## Complete consumer configuration

```yaml
role: authoritative
catalog_state_file: /var/lib/dnsscienced/catalog-state.json

tsig_keys:
  - name: catalog-transfer.example.
    algorithm: hmac-sha256
    secret: BASE64_CATALOG_SECRET
  - name: standard-members.example.
    algorithm: hmac-sha256
    secret: BASE64_STANDARD_SECRET
  - name: regulated-members.example.
    algorithm: hmac-sha512
    secret: BASE64_REGULATED_SECRET

catalog_zones:
  - name: catalog-east.example.
    masters:
      - 192.0.2.10:53
      - 192.0.2.11:53
    transfer_source: 192.0.2.53
    transfer_tsig_key: catalog-transfer.example.
    refresh_interval: 5m
    min_refresh_time: 30s
    max_refresh_time: 1h
    min_retry_time: 10s
    max_retry_time: 5m
    allow_axfr_fallback: true
    max_transfer_records: 1000000
    max_transfer_bytes: 268435456

    member_allow_suffixes:
      - customer.example.
    member_deny_suffixes:
      - suspended.customer.example.
    max_members: 100000
    max_reconcile_actions: 200000
    reconcile_actions_per_minute: 10000
    reconcile_action_burst: 20000

    # Initial rollout setting. Change only after inspecting the pending plan.
    dry_run: true
    approval_required_above: 100
    # approved_serial: 2026072301

    member_defaults:
      masters:
        - 192.0.2.20:53
        - 192.0.2.21:53
      transfer_tsig_key: standard-members.example.
      min_refresh_time: 1m
      max_refresh_time: 12h
      min_retry_time: 30s
      max_retry_time: 30m
      max_transfer_records: 1000000
      max_transfer_bytes: 268435456

    groups:
      regulated:
        masters:
          - 192.0.2.30:53
          - 192.0.2.31:53
        transfer_tsig_key: regulated-members.example.
        min_refresh_time: 30s
        max_refresh_time: 1h
        min_retry_time: 10s
        max_retry_time: 5m
        max_transfer_records: 2000000
        max_transfer_bytes: 536870912
```

The state directory should be owned by the daemon account and inaccessible to
other users:

```sh
install -d -m 0750 -o dnsscienced -g dnsscienced /var/lib/dnsscienced
```

DNSScienced writes the state file atomically with mode `0600`.

## Complete RFC 9432 schema-v2 zone

The producer can publish the following ordinary primary zone. Member labels
are opaque stable identifiers; do not derive operational meaning from them.
`invalid.` is an appropriate NS target when the catalog is not intended for
ordinary delegation or querying.

```dns
$ORIGIN catalog-east.example.
$TTL 0

@ IN SOA invalid. hostmaster.catalog-east.example. (
    2026072301 ; serial
    300        ; refresh
    60         ; retry
    86400      ; expire
    0          ; negative TTL
)
@ IN NS invalid.

; Exactly one supported schema version RR.
version IN TXT "2"

; Standard member using member_defaults.
01J3A8M8Y8P4KQ1R7W7H9X2J4C.zones IN PTR alpha.customer.example.

; Group-selected member. The complete TXT RDATA is the group value.
01J3A8QH5G2CMN1F0V3S6Z8B9D.zones IN PTR beta.customer.example.
group.01J3A8QH5G2CMN1F0V3S6Z8B9D.zones IN TXT "regulated"

; Multiple groups are legal. DNSScienced sorts complete TXT RDATA values
; deterministically, uses the first locally configured match, and ignores
; unknown values.
01J3A8T2E4F6G8H0J2K4M6N8P0.zones IN PTR gamma.customer.example.
group.01J3A8T2E4F6G8H0J2K4M6N8P0.zones IN TXT "future-policy"
group.01J3A8T2E4F6G8H0J2K4M6N8P0.zones IN TXT "regulated"

; Global and member custom properties must live below ext.
environment.operator-x.ext IN TXT "production"
ticket.operator-x.ext.01J3A8QH5G2CMN1F0V3S6Z8B9D.zones IN TXT "CHG-1042"
```

The producer must advance the SOA serial according to RFC 1982. DNSScienced
rejects equal, stale, or undefined half-range transitions and retains the last
accepted fleet.

## Initial migration from explicit secondaries

### 1. Inventory and freeze

Export the current BIND, NSD, or DNSScienced secondary inventory, including:

- zone names;
- primary endpoints and transfer source addresses;
- TSIG key names and algorithms;
- refresh/retry overrides;
- transfer size exceptions;
- DNSSEC or other zone-associated state.

Freeze unrelated provisioning changes until the migration completes. Generate
stable member labels and preserve the mapping in the producer's source data.

### 2. Publish without withdrawing anything

Create the schema-v2 catalog at the producer and transfer it with a dedicated
TSIG key. Configure the DNSScienced consumer with:

- explicit member allow/deny suffixes;
- resource and reconciliation limits;
- `dry_run: true`; and
- an approval threshold appropriate for the deployment.

Keep existing explicit secondaries configured during this phase. They will
appear as reserved-name conflicts in the dry-run plan, which is expected.

### 3. Inspect the plan

```sh
dnsscienced-admin catalog list
dnsscienced-admin catalog members catalog-east.example. 500
```

Verify:

- catalog serial and freshness;
- expected member count;
- no unexpected suffixes;
- effective group and master selection for representative members;
- TSIG key identities and algorithms;
- pending action counts;
- `dnsscienced_catalog_transfers_total`;
- `dnsscienced_catalog_reconciles_total`; and
- structured `catalog audit` records.

Resolve every unexpected conflict before proceeding.

### 4. Canary conversion

On one consumer:

1. Stop DNSScienced cleanly.
2. Back up the configuration and catalog state file.
3. Remove the explicit secondary stanzas for the catalog-managed members.
4. Set `dry_run: false`.
5. If the plan crosses the destructive threshold, set `approved_serial` to the
   exact inspected catalog SOA serial.
6. Start DNSScienced.
7. Verify authoritative answers, SOA serials, transfers, NOTIFY processing,
   DNSSEC behavior, and admin status.

Do not configure the same zone both explicitly and through a catalog.
DNSScienced fails closed on persisted catalog ownership that conflicts with an
operator-configured primary or secondary.

### 5. Fleet rollout

Roll consumers in small failure-domain-aware batches. Hold each batch long
enough to observe at least one refresh cycle and representative NOTIFY events.
Remove `approved_serial` after the approved serial commits; later destructive
serials require a new explicit approval.

## Moving a zone between catalogs

Use the RFC 9432 `coo` handshake when every consumer supports it.

Old catalog:

```dns
01J3A8M8Y8P4KQ1R7W7H9X2J4C.zones.catalog-old.example. 0 IN PTR alpha.customer.example.
coo.01J3A8M8Y8P4KQ1R7W7H9X2J4C.zones.catalog-old.example. 0 IN PTR catalog-new.example.
```

Destination catalog, published at the same time:

```dns
01J3A8M8Y8P4KQ1R7W7H9X2J4C.zones.catalog-new.example. 0 IN PTR alpha.customer.example.
```

Keep the old `coo` record present until all consumers have committed the
destination snapshot. Reusing the same member label preserves associated state;
using a different label deliberately resets it. DNSScienced rejects
self-references and deterministic cross-catalog ownership cycles.

## Routine backups

Back up these items together:

- the complete daemon configuration;
- catalog and member TSIG material from the secret manager;
- `catalog_state_file`;
- operator-managed primary/secondary zone files; and
- the producer database or source used to generate catalogs.

The state file is replaced atomically, so copying the named file observes
either the previous complete state or the next complete state. Protect backups
as secrets because the state reveals customer zone inventory even though it
does not contain TSIG secrets.

Perform restore drills. A backup that has never passed a startup and answer
verification is not a recovery asset.

## Rollback

### Roll back before catalog activation

Leave `dry_run: true` or remove the `catalog_zones` stanza. Existing explicit
secondaries remain authoritative and no catalog plan has been committed.

### Roll back after activation

1. Stop the affected consumer.
2. Preserve the current catalog state file for investigation.
3. Remove or disable the `catalog_zones` configuration.
4. Restore the previous explicit secondary configuration and any associated
   state.
5. Start the daemon and verify every restored zone.

Do not enable explicit zones with the same names while persisted catalog
ownership is active; the startup conflict check intentionally rejects that
ambiguous state.

To resume catalog operation later, restore the known-good catalog state and
configuration, start in dry-run mode, inspect the current producer serial, and
perform a new canary activation.

## Disaster recovery

### Catalog primary unavailable

DNSScienced retains and serves the last valid persisted member fleet. Transfer
failures make catalog health unhealthy but do not withdraw members. Restore
primary reachability or fail over to another configured master, then confirm
the next serial advances normally.

### State file corrupted or unreadable

Startup fails closed rather than guessing ownership.

1. Stop the daemon.
2. Preserve the damaged file.
3. Restore the latest tested state backup with owner-only permissions.
4. Start the daemon and compare catalog/member counts and serials.
5. Force or wait for an authenticated catalog refresh.

### State file lost

Do not immediately activate a large catalog against an empty ownership
database. Restore a backup if possible. Otherwise:

1. start with catalog processing disabled and explicit zones restored, or on an
   isolated replacement consumer;
2. configure the catalog in dry-run mode;
3. inspect the complete plan and validate member transfers;
4. authorize the exact serial if necessary; and
5. canary the rebuilt ownership state before production rollout.

### Empty or catastrophically changed producer output

The per-snapshot action limit, rate budget, dry-run mode, and serial-bound
approval threshold are independent controls. If a bad serial is blocked:

1. do not approve it;
2. correct the producer data;
3. publish a strictly newer SOA serial;
4. inspect the replacement plan; and
5. verify the last-valid fleet remained served.

### Conflicting ownership or suspected compromise

Freeze catalog changes, revoke the affected transfer key, preserve logs and
state, and switch the consumer to dry-run or explicit configuration. Use audit
events and the admin member view to reconstruct the accepted serial, ownership,
group selection, and pending actions. Rotate catalog and member keys
independently.

## Recovery acceptance checklist

A migration or recovery is complete only when:

- all configured catalogs are fresh and have no last error;
- accepted serials match the intended producer serials;
- member and ownership counts match the source of truth;
- pending action counts are empty;
- representative zones answer over UDP and TCP with correct authoritative
  flags and SOA serials;
- authenticated AXFR/IXFR and NOTIFY work for catalog and member zones;
- no unexpected conflicts, resets, or migrations appear in audit records;
- a full daemon restart restores the same fleet before refresh; and
- backup artifacts and rollback steps have been tested.
