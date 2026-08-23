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

The second migration adds `scheduler_leases`, a tenant-scoped coordination
primitive for active/standby ingestion schedulers. Acquisition and renewal use
PostgreSQL server time, lease takeover increments a monotonic fencing token,
and stale holders cannot renew or release a newer lease generation. This is the
persistence foundation only: the scheduler renewal/cancellation loop is wired
in a separate increment, so Kubernetes remains intentionally single-replica.

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
triggers, scheduler lease fencing/expiry structure, indexes, rollback presence,
and newer-database rejection are covered by deterministic tests. Applying and
rolling back against a real PostgreSQL instance, including concurrent lease
contention, is intentionally deferred to the final integration test phase.

## Scheduler lease adapter

The PostgreSQL adapter exposes bounded acquire, renew, and release operations.
Lease names and opaque process holder IDs are validated before database access;
TTLs must be between 15 seconds and 24 hours. A contended acquire, expired
renewal, or stale release is a normal `false` result rather than an operational
error. SQL uses one tenant-scoped statement per transition and never trusts the
application host clock for ownership decisions.

Deterministic driver-neutral tests verify tenant arguments, fencing-token use,
contention behavior, validation, and fail-closed expiry predicates. A fencing
token is not yet attached to snapshot writes; full stale-writer exclusion is
therefore not claimed until scheduler integration and commit-time ownership
checks are implemented.

## Snapshot writer

The initial PostgreSQL `Writer` uses `database/sql` without selecting a driver.
It validates the Agent BOM before beginning a transaction, derives stable
repository and snapshot IDs, upserts the tenant and repository, stores the
immutable BOM, and writes queryable Finding projections in one transaction.

Re-ingesting identical content for the same repository revision is idempotent.
Reusing that revision with different BOM content is rejected rather than
silently overwriting history. Unit tests exercise transaction ordering,
pre-database validation, commit, rollback, and immutable-revision conflicts
through a driver-neutral fake transaction.

## Snapshot reader

The PostgreSQL adapter also implements the persistence-neutral `Reader`
contract. Every query is constrained by `organization_id`, repository and
snapshot lists use bounded keyset pagination, and missing records map to the
same public `ErrNotFound` contract as the in-memory store. Stored Agent BOM
JSON is decoded and validated again before it crosses the storage boundary.

Repository inventory, latest and historical snapshots, current findings, and
episode-aware Finding lifecycle projections are computed without loading an
organization's full history into process memory. The lifecycle query uses the
immutable snapshot ingestion sequence to distinguish reintroduction from a
continuously persisting Finding.

Driver-neutral tests cover row decoding, tenant arguments, pagination cursors,
not-found behavior, and rejection of invalid persisted BOMs. SQL execution,
query plans, migration application, concurrent ingestion, and rollback against
a real PostgreSQL server remain explicitly deferred to final integration
validation.

## Operational configuration contract

Control-plane database settings are environment-only so credentials do not
need to appear in command arguments or repository configuration. The contract
currently recognizes:

| Variable | Default | Constraint |
| --- | --- | --- |
| `OPSCUSTODIAN_ORGANIZATION_ID` | required | `organization-` plus 16 lowercase hexadecimal characters |
| `OPSCUSTODIAN_ORGANIZATION_DISPLAY_NAME` | organization ID | 1 to 200 characters |
| `OPSCUSTODIAN_DATABASE_DSN` | required | non-empty; never included in safe configuration output |
| `OPSCUSTODIAN_DATABASE_ALLOW_INSECURE` | `false` | explicit isolated-development override |
| `OPSCUSTODIAN_DATABASE_MIGRATE` | `true` | boolean |
| `OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT` | `5s` | positive, at most one minute |
| `OPSCUSTODIAN_DATABASE_MIGRATION_TIMEOUT` | `2m` | positive, at most 15 minutes |
| `OPSCUSTODIAN_SHUTDOWN_TIMEOUT` | `10s` | positive, at most one minute |
| `OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS` | `20` | 1 to 1000 |
| `OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS` | `5` | 0 to max open connections |
| `OPSCUSTODIAN_DATABASE_CONN_MAX_LIFETIME` | `30m` | positive, at most 24 hours |

Configuration parsing is side-effect free and does not open a database. A
separate safe projection exposes only operational metadata and a boolean
indicating whether a DSN was configured; it cannot serialize the DSN or its
credentials.

OpsCustodian uses the official pgx v5 `database/sql` adapter, pinned in the Go
module dependency graph. Registering the driver and constructing a lazy SQL
handle are covered by offline tests; no connection is attempted until the
bootstrap's bounded ping stage.

### Transport security

Production configuration is fail-closed: the effective pgx configuration must
use TLS with certificate-chain and hostname verification for the primary host
and every failover host. Consequently, implicit `prefer` and explicit
`disable`, `allow`, `require`, or `verify-ca` modes are rejected; use
`sslmode=verify-full` with an appropriate system or explicit CA trust source.

`OPSCUSTODIAN_DATABASE_ALLOW_INSECURE=true` bypasses this guard only for an
isolated local development database. The override is visible in the safe
configuration projection, while the DSN remains secret. Invalid DSN errors are
sanitized and never include credentials or the original connection string.

## Bootstrap lifecycle

The driver-neutral control-plane bootstrap validates configuration before any
I/O, opens the database, applies pool bounds, performs a timeout-bounded ping,
optionally runs migrations under a separate bounded context, and constructs a
combined snapshot Reader/Writer. Every failure after open closes the database;
successful runtimes provide an idempotent close operation.

Lifecycle ordering, skipped migrations, deadline propagation, early
cancellation, dependency validation, and cleanup on ping, migration, and store
construction failures are covered without a database process. Registering a
PostgreSQL driver and exercising this lifecycle against a real server remain
part of final integration validation.
