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

## Controlled write contention

The disposable contention harness exercises one immutable repository revision
under concurrent identical and conflicting authenticated writes:

```bash
sh ./integration/verify_contention.sh
```

The default profile uses 32 workers. On 2026-11-02 all 32 identical writes
succeeded, all 32 conflicting writes returned the expected immutable conflict,
and PostgreSQL retained one canonical snapshot. The harness also verified no
orphan Findings, no duplicate audit event IDs, exactly 32 persisted and 32
conflict audit outcomes, healthy readiness, and an empty durable spool. This
closes the bounded snapshot-write contention correctness case; it does not
measure saturation, maximum concurrency, sustained throughput, or latency.

## Measured load and soak probe

The rate-limited Docker probe preserves the loopback-only server boundary by
sharing the control-plane network namespace. It records read, write, and
readiness success/error counts; p50, p95, p99, and maximum client-observed
latency; snapshot/audit/spool integrity; and sampled peak CPU, memory, and PID
usage for the control plane, PostgreSQL, and the Collector:

```bash
sh ./integration/verify_soak.sh
```

The default profile is five minutes at a maximum aggregate rate of 100 reads
and 10 writes per second, using 16 read and four write workers. Duration,
workers, target rates, and resource-sample interval are bounded environment
inputs. The probe does not publish credentials or retain local evidence files.
The manually dispatched `Performance evidence` workflow runs a 60-second
profile and retains its environment, result, and checksums for 90 days.

On 2026-11-02 a 60-second Docker Desktop validation completed 6,000 reads and
600 writes with no request or readiness error at the target 110 requests per
second. Read latency was 32.298 ms p50, 58.370 ms p95, and 71.853 ms p99;
write latency was 38.955 ms p50, 74.910 ms p95, and 93.289 ms p99. Snapshot,
audit identity, orphan-Finding, and spool checks passed. The observed sampled
peaks were 31.67% CPU for the control plane and 78.98% CPU for PostgreSQL on
this Docker Desktop allocation. This validates the harness and a short
reference point only; it is not the sustained beta envelope or an SLO.

The default five-minute profile also passed on 2026-11-02 with 25,200 reads,
3,000 writes, and 301 readiness checks without error. It achieved 94 completed
requests per second against the configured ceiling of 110. Read latency was
186.425 ms p50, 241.188 ms p95, and 278.343 ms p99; write latency was 205.797
ms p50, 256.753 ms p95, and 296.639 ms p99. All persistence and audit checks
passed and the spool remained empty. Across 28 resource samples, peak control
plane CPU was 39.19% and peak PostgreSQL CPU was 114.56%, where values above
100% represent use of more than one logical CPU. This is a useful single-host
baseline, but five minutes remains insufficient for a beta soak or capacity
claim.

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

Microbenchmarks and the bounded read/mixed-write/contention/latency smoke tests do not
close the beta performance gate. Before the first beta, the supported
deployment still needs sustained read/write load, dependency outage, recovery,
and resource saturation tests on a declared reference environment. The resulting envelope
must state safe workload limits and observed failure behavior without implying
production high availability.
