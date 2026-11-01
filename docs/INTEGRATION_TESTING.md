# Disposable integration harness

The `integration` Compose project prepares the final environment-backed test
phase without sharing ports, networks, volumes, or credentials with unrelated
Docker Desktop workloads. Its fixed project name is
`opscustodian-integration`, its network is internal, and it publishes no host
ports.

The harness covers:

- real pgx connection, PostgreSQL bootstrap, and migration ledger;
- scheduled repository ingestion persisted to and read from PostgreSQL;
- `/healthz` and dependency-aware `/readyz` behavior;
- real OPA parsing and built-in Rego tests;
- authenticated server-side policy evaluation through the pinned OPA runtime;
- real OTLP/HTTP export through an OpenTelemetry Collector;
- secret-free generated Agent BOM and audit-event fixtures.

## Verified environment

On 2026-10-08 the complete disposable harness was re-run on Docker Desktop
4.44.1 with Linux Engine 28.3.2 from the current working tree. The main run
passed PostgreSQL bootstrap and migrations, authenticated ingestion, policy
evaluation, historical drift, graph filtering, persistent audit queries,
snapshot retention, and Collector export. The isolated backup/restore run and
the schema upgrade-compatibility run also passed, including restored API reads,
history preservation, idempotent restart, and fail-closed version checks. All
Compose containers, networks, and volumes were removed after each run; no
generated evidence or credentials were written to the repository.

On 2026-08-23 the complete harness passed on Docker Desktop 4.44.1 with Linux
Engine 28.3.2. The observed services were PostgreSQL 17.4, OPA 1.7.1, and
OpenTelemetry Collector 0.123.0. Both committed migrations were present,
authenticated repository ingestion became ready, all three built-in OPA tests
passed, the Collector rendered a 27-record OpsCustodian log batch, and cleanup
removed only the Compose project's containers, internal network, and volumes.

On 2026-09-23 the harness was repeated with Linux Engine 28.3.2. Supplemental
disposable tests also proved `sslmode=verify-full` with an explicit test CA,
transactional rollback and reapplication of the latest migration, clean and
escalated control-plane policy decisions, fail-closed behavior when the OPA
executable is unavailable, and server-side admission of both Kubernetes
Kustomize variants. The temporary PostgreSQL container, certificates,
namespace, Compose containers, network, and volumes were removed after the
run. No secret or generated evidence file was committed.

A subsequent disposable runtime deployment on the same Docker Desktop cluster
reached Ready with the restricted Pod settings, PostgreSQL dependency, probes,
Service, and Envoy TLS sidecar. A client in the labeled namespace reached
`/healthz` over HTTPS. The negative NetworkPolicy check did not pass: an
unlabeled namespace also reached the Service, and the cluster exposed
`kube-proxy` but no policy-enforcing CNI/controller. All three temporary
namespaces and the supporting PostgreSQL container were removed. This is a
recorded environment limitation and must not be reported as policy
enforcement.

The connectivity test was then repeated on an isolated Kind v1.32.2 cluster
with Calico v3.32.1. The single-replica workload became Ready, the labeled
client received the expected HTTPS health response, and the unlabeled client
timed out and failed as required. PostgreSQL ran as a disposable container on
the Kind network so the application egress path remained constrained to port
5432. The Kind cluster, PostgreSQL container, temporary certificates, downloaded
tools, and image archives were removed after the successful run.

On 2026-09-24 a separate secret-safe real-provider harness used a disposable
public repository and GitHub App installation. It observed installation-token
exchange, cache reuse, private API ingestion, and unchanged-revision handling.
A negative run with an invalid installation returned the expected rejection,
persisted no snapshot, and passed bounded audit-output secret checks. Both runs
removed their Compose containers, internal network, and volumes. The cached
disposable PAT returned `401`, so PAT parity was not claimed and requires a new
least-privilege credential.

On the same date a disposable Kind v1.32.2 cluster compared the offline
effective-access result for the `production/ops-agent` ServiceAccount with
live Kubernetes authorization decisions. Namespaced Pod read, cluster-wide Job
watch, `/healthz` non-resource URL read, and wildcard-derived Secret deletion
were all allowed as predicted. No discrepancy was observed. The Kind cluster,
kubeconfig, and comparison output were removed after the run.

A Docker Compose failure test then stopped PostgreSQL while the control plane
remained running. The database readiness probe changed `/readyz` to `503`
within its bounded polling window while `/healthz` continued to report process
liveness. Restarting PostgreSQL restored readiness and authenticated repository
reads without restarting the control plane. The Compose containers, network,
and volumes were removed after the successful recovery.

A bounded read-load baseline sent 2,000 authenticated repository-list requests
at concurrency 20 through the control plane loopback boundary. All 2,000
requests succeeded, readiness remained healthy, throughput was 2,407.6
requests/second, and observed latency was 5.374 ms p50, 24.526 ms p95, and
30.822 ms p99 on this Docker Desktop host. This is a regression baseline for
one machine, not a capacity, soak, or service-level objective claim. The
Compose resources were removed after the run.

The policy-runtime phase then rebuilt the application image with the pinned OPA
1.7.1 executable, mounted the reviewed built-in policy bundle read-only, and
called the authenticated `POST /api/v1/policy/evaluate` endpoint through the
running control-plane process. The valid fixture returned `allowed: true`, all
three Rego contract tests passed, the request audit contained only the bounded
allowed outcome and decision counts, and the disposable containers, network,
and volumes were removed.

The repository-authorization phase then ran the control plane with a
repository-scoped multi-credential entry against real PostgreSQL. Collection
pagination returned only the granted repository, the scoped findings query
executed through the PostgreSQL allowlist filter, and a direct request for an
ungranted repository returned `403`. The disposable resources were removed
after the successful run.

The historical-drift phase extends the same disposable harness with two
immutable scope-expansion snapshots submitted through the authenticated API.
The control plane reads both snapshots from PostgreSQL and returns the expected
semantic capability-escalation change through the repository-authorized drift
endpoint. The comparison neither rescans a repository nor accepts a client
supplied comparison result.

The organization-graph phase queries the latest persisted graph material from
the same PostgreSQL-backed repositories. The harness verifies that the bounded
graph page contains the authorized scope-expansion repository after ingestion;
the query uses its exact Kubernetes deployment-update capability action, while
repository filtering remains enforced by the shared collection boundary.

The persistent-audit phase applies the third migration, writes request events
to PostgreSQL in addition to the JSONL operational sink, and queries a
repository-scoped snapshot-ingestion event through the authenticated
`audit:read` API. Raw authorization headers, tokens, request bodies, and query
strings remain outside the retained event contract.

The audit-retention phase adds bounded tenant-scoped pruning with deterministic
unit coverage for age and batch limits. The Docker harness validates the
retention-capable schema and startup worker initialization; long-duration
wall-clock expiry remains a release-candidate soak-test gate rather than being
simulated as proof in this short-lived harness.

The snapshot-retention phase adds tenant-scoped, bounded pruning based on the
server-controlled ingestion timestamp. Deterministic tests prove the deletion
batch limit, per-repository minimum history, and latest-snapshot preservation.
The Docker harness inserts two expired snapshots, restarts the control plane,
and proves that the startup worker deletes only the oldest bounded candidate,
preserves the newer and latest snapshots, and cascades its dependent Finding.
Multi-day wall-clock expiry and sustained ingestion remain release-candidate
soak gates.

The backup/restore phase uses two independent PostgreSQL 17.4 volumes. It takes
a complete custom-format logical dump without owner or ACL metadata, restores
it into an empty destination, compares migration counts, table counts, and
content digests for snapshots and audit events, verifies the expected tenant,
and starts a second control plane that reads the restored repository through
the authenticated API. The test creates no host backup file and removes both
database volumes. This proves the documented logical path on one version; it
does not prove physical backup, point-in-time recovery, cross-version upgrade,
large-database recovery time, or a production RPO/RTO.

The upgrade-compatibility phase builds the immutable `v0.5.0-alpha` tag, uses
that binary to create a schema-version-2 database with repository history, and
then starts the current binary on the same PostgreSQL volume. The harness
verifies migration 3, unchanged snapshot count and content digest,
authenticated API reads, and idempotent restart. It also proves that the old
binary rejects the newer schema and the current binary rejects an injected
unknown future migration. This is a direct one-step upgrade result; mixed-
version rolling upgrades, skip-version upgrades, production downgrade, and
large-database migration duration remain open.

Schema 4 adds audit-event idempotency and file-spool replay. The existing
upgrade evidence predates this migration, so the harness must be extended and
re-run before the beta upgrade gate can be checked again.

This is one environment-backed result, not a compatibility matrix or a
production-readiness claim. Re-run it from the exact release candidate.

The committed Compose harness itself does not cover GitHub PAT/App provider
behavior, PostgreSQL TLS/CA compatibility, migration rollback, Kubernetes
workload readiness, load, or failure injection. The supplemental result above
closes the TLS, rollback, policy-runtime, Kubernetes API-admission, and listed
GitHub App checks for this environment only. Certificate rotation/trust
validation, PAT parity, expiry-driven App refresh, real-provider redirect,
cancellation and rate-limit observations, broader authorization compatibility,
HA contention, sustained/maximum load, and broader failure injection remain
explicit gates rather than implied by a passing harness.

## Execution boundary

Do not run these harnesses as part of ordinary unit tests. They pull container
images, build OpsCustodian, and create an isolated network. The primary harness
creates two named volumes; the recovery and upgrade profiles each add one
isolated database volume. The verification scripts remove only resources
belonging to the fixed Compose project. Set
`OPSCUSTODIAN_INTEGRATION_KEEP=true` only when you need to inspect the
disposable environment after a failure.

Linux or CI:

```bash
sh ./integration/verify.sh
sh ./integration/verify_backup_restore.sh
sh ./integration/verify_upgrade.sh
```

Windows CMD manual startup uses ephemeral values supplied by the operator:

```cmd
set OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD=REPLACE_EPHEMERAL_DATABASE_PASSWORD
set OPSCUSTODIAN_INTEGRATION_API_TOKEN=REPLACE_EPHEMERAL_API_TOKEN_AT_LEAST_32_CHARACTERS
docker compose --project-directory integration -f integration\compose.yaml up --detach --build --wait postgres collector opscustodian
docker compose --project-directory integration -f integration\compose.yaml ps
```

Cleanup is scoped and destructive only to this disposable project:

```cmd
docker compose --project-directory integration -f integration\compose.yaml down --volumes --remove-orphans
```

Before cleanup, `docker compose ... ps` is the read-only scope check. The blast
radius is the `opscustodian-integration` containers, its internal network, and
its `postgres-data`, optional `postgres-restore-data`, optional
`postgres-upgrade-data`, and `integration-output` volumes. Volume deletion is
not recoverable and must never be used against another Compose project.

The committed image tags and the complete harness must be refreshed and tested
again from the final release candidate before any production-readiness claim. The
Collector verification matches the exported log body because the Collector
`debug` exporter does not render the OTLP `eventName` field in its text output;
the Go OTLP contract tests separately verify that the wire payload contains it.
