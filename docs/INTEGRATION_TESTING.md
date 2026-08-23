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
- real OTLP/HTTP export through an OpenTelemetry Collector;
- secret-free generated Agent BOM and audit-event fixtures.

## Verified environment

On 2026-08-23 the complete harness passed on Docker Desktop 4.44.1 with Linux
Engine 28.3.2. The observed services were PostgreSQL 17.4, OPA 1.7.1, and
OpenTelemetry Collector 0.123.0. Both committed migrations were present,
authenticated repository ingestion became ready, all three built-in OPA tests
passed, the Collector rendered a 27-record OpsCustodian log batch, and cleanup
removed only the Compose project's containers, internal network, and volumes.

This is one environment-backed result, not a compatibility matrix or a
production-readiness claim. Re-run it from the exact release candidate.

It does not cover GitHub PAT/App provider behavior, Kubernetes API access,
PostgreSQL TLS/CA compatibility, migration rollback, load, or failure injection.
Those remain explicit final gates rather than implied by a passing harness.

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
