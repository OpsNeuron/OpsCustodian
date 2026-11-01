# Control-plane upgrades

OpsCustodian applies forward-only production migrations at process startup.
Migration files and their SHA-256 checksums are embedded in the binary. Startup
holds a PostgreSQL advisory lock, verifies every applied checksum, rejects gaps
or unknown future versions, and commits the complete migration plan in one
transaction.

## Upgrade procedure

The current verified source is `v0.5.0-alpha`, whose database contains schema
versions 1 and 2. The current development line adds schema versions 3 and 4.

Before upgrading:

1. complete and verify a logical backup using the
   [backup and restore runbook](BACKUP_RESTORE.md);
2. stop all control-plane writers and scheduled ingestion replicas;
3. record the binary version and `schema_migrations` ledger;
4. deploy exactly one new control-plane instance with
   `OPSCUSTODIAN_DATABASE_MIGRATE=true`; and
5. wait for `/readyz` before enabling traffic or additional replicas.

After readiness, verify repository inventory, snapshot history, Findings, audit
queries, and the migration ledger. Repeating startup with the same binary is
idempotent and must not add or alter migration records.

## Failure and rollback boundary

An older binary fails closed when the database contains a migration it does not
recognize. A current binary also fails closed if the ledger contains an unknown
future migration. Do not delete ledger rows or run embedded down migrations as
an ad-hoc production rollback.

Application rollback after a schema upgrade requires restoring the verified
pre-upgrade backup into a new database and starting the older binary against
that restored database. Mixed-version rolling upgrades, in-place production
schema downgrade, multi-replica migration contention, and skip-version upgrade
paths are not yet supported claims.

## Disposable verification

The repository includes an opt-in Docker harness that builds the source binary
from the immutable `v0.5.0-alpha` tag, creates a version-2 database with real
repository data, upgrades the same volume with the current binary, compares
snapshot count and content digest, verifies authenticated API reads and legacy
audit identity backfill, replays a real pending event from the durable spool,
repeats startup to prove migration and event idempotency, and confirms
downgrade and unknown-future rejection:

```bash
sh ./integration/verify_upgrade.sh
```

This complete schema-2-through-schema-4 path passed on 2026-11-01. The script
uses a unique temporary source-image tag and a validated temporary build
directory. It removes its containers, source image, network, database and
audit-spool volumes, and build directory unless
`OPSCUSTODIAN_INTEGRATION_KEEP=true` is explicitly set.
