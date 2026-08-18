# PostgreSQL persistence

OpsCustodian v0.5 uses PostgreSQL as the planned durable control-plane store.
The initial schema and migration runner are embedded in the binary, but no
database driver or network connection is enabled yet.

## Schema model

The first migration creates:

- `organizations`: explicit tenant boundary;
- `repositories`: tenant-scoped source identity;
- `snapshots`: immutable Agent BOM JSONB plus indexed revision metadata;
- `snapshot_findings`: immutable, queryable Finding projections; and
- `schema_migrations`: runner-owned version and checksum ledger.

Repository and snapshot foreign keys include `organization_id`; this prevents a
record from referencing another organization's parent even if IDs collide.
Agent BOM JSONB is retained as the canonical artifact, while selected Finding
columns support severity, repository, remediation, and lifecycle queries.

## Migration guarantees

Migration files are compiled into the binary and must be paired as `up` and
`down` files with contiguous numeric versions. The runner:

1. opens one transaction;
2. obtains a PostgreSQL transaction-scoped advisory lock;
3. verifies the immutable SHA-256 checksum ledger;
4. rejects databases containing migrations unknown to the running binary;
5. applies pending migrations and records their checksums; and
6. commits only after the complete plan succeeds.

Rollback is explicit, step-counted, checksum-verified, reverse-ordered, and
transactional. A published migration must never be edited; corrections require
a new migration.

## Immutability and retention

Database triggers reject updates to snapshot and snapshot-Finding rows. Future
retention workflows may delete complete snapshots, which cascades only to that
snapshot's Finding projections. Repository and organization deletion remains
restricted by foreign keys and will require an explicit governed workflow.

## Validation status

Catalog parsing, ordering, checksums, multi-tenant key structure, immutability
triggers, indexes, rollback presence, and newer-database rejection are covered
by deterministic tests. Applying and rolling back against a real PostgreSQL
instance is intentionally deferred to the final integration test phase.
