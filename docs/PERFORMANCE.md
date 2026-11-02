# Performance evidence

OpsCustodian treats performance results as reproducible evidence, not as an
availability or capacity promise. Every published result must identify the
exact commit, Go version, operating system, architecture, workload, duration,
concurrency, and backing services.

## Current integration baseline

The disposable Docker Desktop harness sent 2,000 authenticated repository-list
requests at concurrency 20 through the loopback control-plane boundary. All
requests succeeded, readiness remained healthy, throughput was 2,407.6
requests/second, and observed latency was 5.374 ms p50, 24.526 ms p95, and
30.822 ms p99. This one-host result is a regression baseline only; it is not a
capacity, soak, multi-tenant, or service-level objective claim.

The exact integration context and remaining load gaps are recorded in
[Integration Testing](INTEGRATION_TESTING.md).

## Mixed read/write correctness smoke

The disposable mixed-load harness runs authenticated repository reads and
unique snapshot writes concurrently, polls readiness throughout the run, and
then verifies snapshot counts, tenant-scoped audit-event identity uniqueness,
and an empty durable spool directly against PostgreSQL:

```bash
sh ./integration/verify_load.sh
```

The default is intentionally bounded to 30 seconds, eight read workers, and two
write workers. Operators may set
`OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS` from 10 to 3,600 seconds,
`OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS` from 1 to 64, and
`OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS` from 1 to 16, with a combined
ceiling of 64. The harness creates no retained report or credential file and
removes only its fixed Compose project unless the documented keep flag is set.

On 2026-11-02 the default profile completed 4,150 reads, 1,036 writes, and 29
readiness checks without an observed error. Approximate successful throughput
was 173 requests per second. Snapshot and audit integrity checks passed. This
short one-host run is correctness evidence only, not a latency distribution,
capacity envelope, saturation result, soak test, or service-level objective.

## Security-boundary microbenchmarks

The source suite measures two bounded operations that occur on authenticated
control-plane paths:

- constant-time Bearer authentication with 1, 10, and the supported maximum of
  100 credentials, for both a last-entry match and an unknown token;
- atomic credential-registry reload with 1, 10, and 100 credentials;
- shared audit-envelope validation and its bounded JSON-size check.

Run a local comparison without executing ordinary tests:

```bash
go test -run='^$' -bench='^Benchmark(BearerAuthentication|CredentialRegistryReload)$' -benchmem -benchtime=2s -count=5 ./internal/server
go test -run='^$' -bench='^BenchmarkAuditEventValidation$' -benchmem -benchtime=2s -count=5 ./internal/audit
```

The manually dispatched `Performance evidence` workflow runs the same commands
on a hosted Linux runner and retains the raw output, environment metadata, and
SHA-256 checksums for 90 days. Results from different runner classes must not be
compared as if they used identical hardware.

## Beta evidence still required

Microbenchmarks and the bounded read/mixed-write smoke tests do not close the
beta performance gate. Before the first beta, the supported deployment still needs sustained
read/write load, database contention, dependency outage, recovery, and resource
saturation tests on a declared reference environment. The resulting envelope
must state safe workload limits and observed failure behavior without implying
production high availability.
