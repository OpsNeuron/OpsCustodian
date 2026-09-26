# PostgreSQL backup and restore

OpsCustodian stores organization inventory, immutable Agent BOM snapshots,
Finding projections, scheduler leases, and minimized audit history in
PostgreSQL. Back up the database as one consistency boundary; copying selected
tables is unsupported.

## Supported logical procedure

Use PostgreSQL client tools from the same major version as the server. Configure
TLS and credentials through a restricted `pg_service.conf` and `.pgpass` (or an
equivalent secret-injection mechanism), not command-line passwords or committed
files. The examples assume a source service named `opscustodian-production`, a
destination maintenance service named `opscustodian-restore-admin`, and a
destination service named `opscustodian-restore` whose `dbname` is
`opscustodian_restore`.

Create a custom-format logical backup and a separate checksum:

```bash
pg_dump --dbname=service=opscustodian-production \
  --format=custom --no-owner --no-privileges \
  --file=opscustodian.dump
sha256sum opscustodian.dump > opscustodian.dump.sha256
```

Encrypt the backup with the organization's approved backup system before it
leaves the protected host. Treat it as confidential: Agent BOM evidence and
audit identities are operationally sensitive even though raw API tokens,
authorization headers, GitHub App private keys, and repository credentials are
excluded from the database contract.

Restore into a newly created empty database rather than overwriting the active
database:

```bash
sha256sum --check opscustodian.dump.sha256
createdb --maintenance-db=service=opscustodian-restore-admin opscustodian_restore
pg_restore --dbname=service=opscustodian-restore \
  --exit-on-error --no-owner --no-privileges opscustodian.dump
```

Start the same or newer compatible OpsCustodian release against the restored
database with migrations enabled. Do not point two active control planes at the
same repository schedule during validation. Verify `/readyz`, authenticate a
repository-list request, compare repository/snapshot/Finding/audit counts, and
check `schema_migrations` before cutover. Keep the source database unchanged
until application-level verification succeeds.

## Recovery objectives and exclusions

Operators own backup frequency, retention, encryption, off-site replication,
and restore access controls. The logical procedure does not establish an RPO or
RTO. PostgreSQL physical base backup, WAL archiving and point-in-time recovery,
cross-major-version restore, managed-provider snapshots, key rotation, large-
database performance, and regional disaster recovery remain environment-
specific release gates.

## Disposable verification

The repository includes an opt-in Docker test that creates independent source
and destination PostgreSQL volumes, performs a custom-format dump/restore,
compares migration and content fingerprints, validates the tenant boundary,
and starts a second control plane against the restored database:

```bash
sh ./integration/verify_backup_restore.sh
```

The script uses ephemeral credentials, publishes no host ports, and removes
only the `opscustodian-integration` Compose resources unless
`OPSCUSTODIAN_INTEGRATION_KEEP=true` is explicitly set. It creates no backup
artifact in the workspace.
