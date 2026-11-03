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

On 2026-11-02 the primary harness also exercised durable audit crash recovery.
It isolated scheduler and health-check traffic, stopped PostgreSQL, and issued
one authenticated repository request. The request returned `500`; bounded
audit delivery exhausted its retries; and the control plane stopped fail
closed while retaining exactly one private spool file. After PostgreSQL
recovery, startup replayed the validated event before serving, persisted it
exactly once, removed the acknowledged file, and remained duplicate-free after
a second restart. The harness then removed its containers, network, and named
volumes.

A bounded read-load baseline sent 2,000 authenticated repository-list requests
at concurrency 20 through the control plane loopback boundary. All 2,000
requests succeeded, readiness remained healthy, throughput was 2,407.6
requests/second, and observed latency was 5.374 ms p50, 24.526 ms p95, and
30.822 ms p99 on this Docker Desktop host. This is a regression baseline for
one machine, not a capacity, soak, or service-level objective claim. The
Compose resources were removed after the run.

On 2026-11-02 the separate bounded mixed-load smoke ran for 30 seconds with
eight authenticated repository-read workers, two snapshot-write workers, and
one readiness observer. It completed 4,150 reads, 1,036 writes, and 29 readiness
checks with zero observed errors, approximately 173 successful requests per
second. The post-run database check matched all generated revisions to stored
snapshots, found no missing or mismatched audit event identity, found no
tenant-scoped duplicate event IDs, and found an empty durable spool. This short
correctness smoke is not sustained-load, latency, saturation, or capacity
evidence.

On 2026-11-02 the controlled write-contention harness submitted 32 concurrent
copies of one immutable snapshot and then 32 concurrent conflicting snapshots
using the same repository revision. All identical requests returned `201`, all
conflicting requests returned `409`, PostgreSQL retained exactly one canonical
snapshot, and the database contained exactly 32 persisted plus 32 conflict
audit outcomes with no orphan Findings or duplicate audit IDs. Readiness
remained healthy and the durable spool was empty. This run exposed and closed
a transaction-snapshot visibility race without weakening the immutable-row
trigger. It is bounded correctness evidence, not sustained-load or capacity
evidence.

The rate-limited soak probe was then validated for 60 seconds at 100 reads and
10 writes per second with eight read workers and two write workers. It
completed 6,000 reads, 600 writes, and 61 readiness checks without error;
measured read p99 was 71.853 ms and write p99 was 93.289 ms. The database held
all 600 generated snapshots with no orphan Finding, audit identity violation,
duplicate event ID, or pending spool file. CPU, memory, and PID sampling also
completed for the control plane, PostgreSQL, and Collector. This short run
validates the reproducible measurement harness, not the sustained beta gate.

The default five-minute profile subsequently completed 25,200 reads, 3,000
writes, and 301 readiness checks without an error. It achieved 94 completed
requests per second, with read p99 278.343 ms and write p99 296.639 ms. All
generated snapshots were present, no orphan Finding or audit identity/duplicate
violation existed, and the durable spool was empty. Twenty-eight resource
samples observed peak control-plane CPU of 39.19% and peak PostgreSQL CPU of
114.56% on this Docker Desktop allocation. This closes validation of the
default five-minute profile, not the longer beta soak gate.

On 2026-11-03 the fixed `beta-reference-v1` profile ran for 30 minutes on
Docker Desktop 28.3.2 with 16 logical CPUs and 33,534,070,784 bytes assigned
memory. It completed 145,425 reads, 17,991 writes, and 1,800 readiness checks
without error. Read p99 was 340.654 ms, write p99 was 374.199 ms, and readiness
p99 was 371.652 ms. All 17,991 generated snapshots were retained, with no
orphan Finding, audit identity violation, duplicate event ID, or pending spool
entry. Across 166 samples, control-plane CPU peaked at 37.14% and PostgreSQL
CPU at 114.43%; control-plane and PostgreSQL memory peaked at 0.20% and 0.91%
of the Docker allocation respectively. The measured aggregate completion rate
was 90.787 requests per second, below the configured aggregate ceiling of 110,
so this closes the sustained correctness profile but not the saturation or
safe-capacity boundary.

The `capacity-ramp-v1` harness then increased rate ceilings and concurrency in
two-minute steps. Its 110-request ceiling profile achieved 107.2 requests per
second, or 97.455% of target, without request/readiness errors or data-integrity
violations; read and write p99 were 345.461 ms and 346.896 ms. The next
220-request ceiling profile remained error-free and preserved every invariant,
but achieved 93.317 requests per second, or 42.417% of target, and therefore
became the first boundary under the harness's 95% attainment criterion. Its
read/write/readiness p99 remained near 592 ms, so this was throughput target
non-attainment rather than timeout, corruption, or demonstrated resource
saturation. A one-minute recovery profile then achieved 99.697% of its
55-request ceiling with zero errors and clean snapshot/audit/spool state.

The active-load failure/recovery harness then disabled scheduled ingestion,
ran authenticated reads and unique writes, and stopped PostgreSQL after ten
seconds. Before fail-closed shutdown it completed 192 reads and 19 writes; the
probe subsequently observed 108 read failures, 12 write failures, and
readiness failure. Eleven private audit-spool events were replayed exactly once
after PostgreSQL recovery. A post-recovery profile completed 399 reads and 39
writes without error, every generated post-recovery snapshot was present, and
no orphan Finding, audit identity violation, duplicate event ID, or pending
spool entry remained. A second application restart did not duplicate any
replayed event.

The controlled latency/recovery harness then kept PostgreSQL available while
adding 200 ms only to probe-generated snapshot inserts. The baseline write p50
was 11.292 ms; the delayed phase completed without read, write, or readiness
errors at 212.085 ms write p50 and 238.325 ms write p99; and write p50 returned
to 10.553 ms after removing the delay. Delayed read p99 was 39.2 ms and maximum
readiness latency was 10.789 ms. PostgreSQL retained exactly 39 baseline, 59
delayed, and 40 recovery snapshots, matching every successful write, with no
orphan Finding, audit identity violation, duplicate event ID, or pending spool
entry. This proves one bounded slow-write and clean-recovery path, not storage
saturation, packet loss, connection-pool exhaustion, or managed-database
failover behavior.

The connection-pool recovery harness then recreated the application with two
database connections and held both slots with authenticated snapshot
transactions for ten seconds. PostgreSQL directly reported two active
application queries, including one delayed snapshot insert; the second
transaction was waiting on the shared organization-row lock. An authenticated
repository read waited 9,779 ms, database readiness transitioned from ready to
degraded after the bounded two-second ping timeout, and both recovered without
an application restart after the transactions completed. A post-recovery
profile completed 196 reads, 19 writes, and ten readiness checks without error;
all 20 baseline, two holder, and 19 recovery snapshots were retained with no
orphan Finding, audit identity violation, duplicate event ID, or pending spool
entry. This proves one bounded two-slot pool-exhaustion and recovery path, not
PostgreSQL server connection-limit exhaustion, unbounded queue behavior,
storage saturation, or managed-database failover.

The read-only recovery harness then changed the disposable PostgreSQL database
default for new sessions to `transaction_read_only=on`, terminated old pooled
connections, and proved that the database remained reachable for queries. An
authenticated snapshot request returned `500`, persisted no partial snapshot,
and left exactly one minimized failed-ingestion audit event in the private
spool before the process stopped fail-closed. After restoring read-write mode,
startup replayed the event exactly once and emptied the spool. A recovery
profile completed 200 reads, 20 writes, and 11 readiness checks without error;
all 20 snapshots were present and no orphan Finding, audit identity violation,
or duplicate event ID existed. A second restart did not duplicate the replayed
event. Because public health endpoints are also audited, the harness lengthens
the automatic Docker healthcheck interval only after verified startup so the
explicit snapshot request remains the deterministic failure trigger. This
proves one controlled primary read-only transition, not replica routing,
managed failover, or recovery from an actual standby promotion.

The server-enforced connection-limit harness then created a separately
privileged runtime login after owner-led bootstrap and migrations, verified
that it could persist an audited health request, set its PostgreSQL
`CONNECTION LIMIT` to zero, and terminated its existing sessions. An
authenticated repository read returned `500`; PostgreSQL reported
`SQLSTATE 53300`, one minimized authenticated/authorized request event remained
in the private spool, and the process stopped fail-closed. Restoring the role
limit to 20 allowed startup to replay the event exactly once. A recovery
profile completed 199 reads, 19 writes, and 11 readiness checks without error;
all 19 snapshots were retained with no orphan Finding, audit identity
violation, duplicate event ID, or pending spool entry. A second restart did not
duplicate the replayed event. This proves runtime-role connection admission and
recovery; it does not exercise global `max_connections`, reserved connection
slots, a large waiter population, or a managed connection proxy.

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
then applies the published schema-3 migration fixture before starting the
current binary on the same PostgreSQL volume. On 2026-11-01 the harness
verified migration 4, unchanged snapshot count and content digest,
authenticated API reads, deterministic legacy-audit identity backfill, and
idempotent restart. It also wrote a real pending audit event to the private
spool volume, proved that startup persisted it exactly once and removed the
acknowledged file, and proved a second restart did not duplicate it. The old
binary rejected the newer schema and the current binary rejected an injected
unknown future migration. This is a direct one-step upgrade result; mixed-
version rolling upgrades, skip-version upgrades, production downgrade, and
large-database migration duration remain open.

This is one environment-backed result, not a compatibility matrix or a
production-readiness claim. Re-run it from the exact release candidate.

The primary `verify.sh` Compose path does not itself cover GitHub PAT/App
provider behavior, PostgreSQL TLS/CA compatibility, migration rollback,
Kubernetes workload readiness, sustained load, or failure injection. The
supplemental scripts and results above close the listed load/failure cases plus
TLS, rollback, policy-runtime, Kubernetes API-admission, and GitHub App checks
for this environment only. Certificate rotation/trust
validation, PAT parity, expiry-driven App refresh, real-provider redirect,
cancellation and rate-limit observations, broader authorization compatibility,
HA contention, maximum load, and broader failure injection remain
explicit gates rather than implied by a passing harness.

## Execution boundary

Do not run these harnesses as part of ordinary unit tests. They pull container
images, build OpsCustodian, and create an isolated network. The primary harness
creates three named volumes; the recovery profile adds one isolated database
volume and the upgrade profile adds isolated database and audit-spool volumes.
The verification scripts remove only resources
belonging to the fixed Compose project. Set
`OPSCUSTODIAN_INTEGRATION_KEEP=true` only when you need to inspect the
disposable environment after a failure.

Linux or CI:

```bash
sh ./integration/verify.sh
sh ./integration/verify_backup_restore.sh
sh ./integration/verify_upgrade.sh
sh ./integration/verify_load.sh
sh ./integration/verify_contention.sh
sh ./integration/verify_soak.sh
sh ./integration/verify_beta_soak.sh
sh ./integration/verify_capacity.sh
sh ./integration/verify_failure_recovery.sh
sh ./integration/verify_latency_recovery.sh
sh ./integration/verify_pool_recovery.sh
sh ./integration/verify_readonly_recovery.sh
sh ./integration/verify_connection_limit_recovery.sh
```

## Clean operator rehearsal

The final beta candidate must be exercised from a committed, clean worktree
rather than from a developer directory containing uncommitted source. The
operator rehearsal refuses dirty tracked or untracked state, resolves the exact
commit, creates an isolated local clone without network access, and runs source
validation, the offline Quick Start, base integration, backup/restore,
consecutive upgrade, and active-outage recovery in sequence:

```bash
sh ./integration/verify_operator_rehearsal.sh
```

The run requires Docker, Git, Go, `tar`, `od`, and `mktemp`. It refuses to start
when resources labeled for the `opscustodian-integration` Compose project
already exist. Every child phase uses ephemeral credentials and destructive
cleanup is limited to that disposable Compose project and the validated
temporary clone. The final check fails if a project container or volume
remains.

By default the evidence summary is written only to standard output and contains
the commit, UTC start/end timestamps, tool versions, completed stage names, and
cleanup result. To retain it, provide a pre-existing absolute destination
outside the repository:

```bash
OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE=/secure/evidence/operator-rehearsal.txt \
  sh ./integration/verify_operator_rehearsal.sh
```

The script intentionally cannot satisfy the beta checklist before the candidate
changes are committed. Its successful output must be retained from the exact
release-candidate commit.

When dependency downloads require an operator-controlled HTTP proxy, the soak,
failure/recovery, latency/recovery, pool-recovery, read-only-recovery, and
connection-limit harnesses accept its URL only through the optional
`OPSCUSTODIAN_INTEGRATION_BUILD_PROXY` environment variable and does not retain
it in evidence or repository files.

Windows CMD manual startup uses ephemeral values supplied by the operator:

```cmd
set OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD=REPLACE_EPHEMERAL_DATABASE_PASSWORD
set OPSCUSTODIAN_INTEGRATION_API_TOKEN=REPLACE_EPHEMERAL_API_TOKEN_AT_LEAST_32_CHARACTERS
docker compose --project-directory integration -f integration\compose.yaml run --rm --no-deps --build --entrypoint sh opscustodian -c "chmod 700 /audit-spool"
docker compose --project-directory integration -f integration\compose.yaml up --detach --build --wait postgres collector opscustodian
docker compose --project-directory integration -f integration\compose.yaml ps
```

Cleanup is scoped and destructive only to this disposable project:

```cmd
docker compose --project-directory integration -f integration\compose.yaml down --volumes --remove-orphans
```

Before cleanup, `docker compose ... ps` is the read-only scope check. The blast
radius is the `opscustodian-integration` containers, its internal network, and
its `postgres-data`, `audit-spool`, optional `postgres-restore-data`, optional
`postgres-upgrade-data`, optional `upgrade-audit-spool`, and
`integration-output` volumes. Volume deletion is
not recoverable and must never be used against another Compose project.

The committed image tags and the complete harness must be refreshed and tested
again from the final release candidate before any production-readiness claim. The
Collector verification matches the exported log body because the Collector
`debug` exporter does not render the OTLP `eventName` field in its text output;
the Go OTLP contract tests separately verify that the wire payload contains it.
