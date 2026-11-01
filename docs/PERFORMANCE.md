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

Microbenchmarks and the bounded read baseline do not close the beta performance
gate. Before the first beta, the supported deployment still needs sustained
read/write load, database contention, dependency outage, recovery, and resource
saturation tests on a declared reference environment. The resulting envelope
must state safe workload limits and observed failure behavior without implying
production high availability.
