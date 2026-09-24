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
repository filtering remains enforced by the shared collection boundary.

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

Do not run this harness as part of ordinary unit tests. It pulls container
images, builds OpsCustodian, creates an isolated network, and creates two named
volumes. The verification script removes only resources belonging to the fixed
Compose project. Set `OPSCUSTODIAN_INTEGRATION_KEEP=true` only when you need to
inspect the disposable environment after a failure.

Linux or CI:

```bash
sh ./integration/verify.sh
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
its `postgres-data` and `integration-output` volumes. Volume deletion is not
recoverable and must never be used against another Compose project.

The committed image tags and the complete harness must be refreshed and tested
again from the final release candidate before any production-readiness claim. The
Collector verification matches the exported log body because the Collector
`debug` exporter does not render the OTLP `eventName` field in its text output;
the Go OTLP contract tests separately verify that the wire payload contains it.
