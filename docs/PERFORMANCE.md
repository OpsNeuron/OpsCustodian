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

The fixed `beta-reference-v1` profile uses the same concurrency and target
rates for 30 minutes:

```bash
sh ./integration/verify_beta_soak.sh
```

The wrapper deliberately overrides exploratory soak inputs so that two runs of
the named profile represent the same workload. Its summary records the Docker
CPU and memory allocation, engine/OS/architecture, workload, latency,
correctness invariants, and sampled service peaks. It still creates no retained
repository artifact. Run `verify_soak.sh` directly for other bounded profiles.
Passing this profile establishes a single-host sustained baseline only; it does
not establish a saturation point, safe tenant count, high-availability claim,
or service-level objective.

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

On 2026-11-03 the fixed 30-minute `beta-reference-v1` profile passed on Docker
Desktop 28.3.2 with 16 logical CPUs and 33,534,070,784 bytes assigned memory.
It completed 145,425 reads, 17,991 writes, and 1,800 readiness checks without
an error. Every successful write had exactly one retained snapshot; no orphan
Finding, audit identity violation, tenant-scoped duplicate event ID, or pending
spool entry remained. Read p99 was 340.654 ms, write p99 was 374.199 ms, and
readiness p99 was 371.652 ms. Across 166 samples, peak control-plane CPU was
37.14%, peak PostgreSQL CPU was 114.43%, peak control-plane memory was 0.20%,
and peak PostgreSQL memory was 0.91% of the Docker allocation.

The measured aggregate completion rate was 90.787 requests per second against
configured ceilings of 100 reads and 10 writes per second. The write ceiling
was nearly reached, while the 16 read workers did not sustain the full read
ceiling at the observed latency. This closes the fixed single-host sustained
correctness baseline; it does not establish the saturation boundary or a safe
production capacity. The next capacity experiment must increase concurrency
and workload progressively, record the first violated latency/resource/error
condition, and preserve the same integrity checks.

The fixed `capacity-ramp-v1` experiment implements that next step:

```bash
sh ./integration/verify_capacity.sh
```

It runs up to four two-minute profiles with progressively higher rate ceilings
and concurrency, stops at the first boundary, and then requires a one-minute
low-pressure recovery profile to pass. A profile passes only with zero request
and readiness errors, at least 95% aggregate target-rate attainment, read/write
and readiness p99 at or below 1,000 ms, exact snapshot persistence, no orphan
Finding or duplicate/invalid audit identity, and an empty spool. These are
versioned experimental boundary criteria for this harness, not a published SLO.
The harness emits only secret-free summaries, retains no repository artifact,
and records the same Docker allocation and per-service resource peaks as the
soak probe.

On 2026-11-03 `capacity-ramp-v1` found its first target-attainment boundary on
the same 16-CPU, 33,534,070,784-byte Docker Desktop allocation. The first
profile, configured for 100 reads and 10 writes per second with 24 read and
four write workers, completed 11,664 reads and 1,200 writes without error. It
achieved 107.2 aggregate requests per second, or 97.455% of the configured
ceiling; read p99 was 345.461 ms, write p99 was 346.896 ms, and readiness p99
was 334.750 ms. PostgreSQL CPU peaked at 136.09%. Snapshot, Finding, audit, and
spool invariants all passed.

The next profile raised the configured ceilings to 200 reads and 20 writes per
second with 40 read and eight write workers. It remained error-free and
preserved every integrity invariant, but completed only 93.317 aggregate
requests per second, or 42.417% of target, with p99 near 592 ms. This is the
first measured boundary because target attainment fell below the experimental
95% criterion; it is not a crash, data-integrity failure, or demonstrated
CPU/memory saturation point. A subsequent 50-read/5-write recovery profile
achieved 54.833 requests per second, or 99.697% of target, with zero errors,
clean readiness, and intact data.

The initial beta envelope for this exact allocation is therefore:

- a validated sustained point of 90.787 aggregate requests per second for 30
  minutes with 16 read/four write workers;
- a validated two-minute point of 107.2 aggregate requests per second with 24
  read/four write workers; and
- a first target-attainment boundary at the 220-request configured ceiling.

These are measured operating points, not guaranteed production throughput. A
deployment with different CPU, memory, storage, PostgreSQL tuning, tenant data,
or request mix must rerun both the fixed soak and capacity ramp before adopting
an operating limit.

## Dependency failure under load

The disposable failure/recovery harness runs a bounded healthy phase, stops
PostgreSQL while authenticated reads and writes remain active, requires the
control plane to fail closed, validates every private spool entry, restores the
database, and runs a second healthy load phase:

```bash
sh ./integration/verify_failure_recovery.sh
```

On 2026-11-02 the pre-failure phase completed 192 reads and 19 writes before
the outage produced 108 read failures and 12 write failures. Eleven spooled
audit events were replayed exactly once. The recovery phase completed 399 reads
and 39 writes without error, with intact snapshot, Finding, audit-identity,
duplicate, readiness, and spool invariants. This proves one controlled hard
database outage and restart path; it is not evidence for packet loss,
connection exhaustion, slow queries, storage stalls, or regional failure.

## Controlled dependency latency and recovery

The disposable latency/recovery harness keeps PostgreSQL online and applies a
temporary, revision-scoped trigger to delay only probe-generated snapshot
inserts. It measures a healthy baseline, the delayed interval, and recovery
after removing the trigger while authenticated reads, writes, and readiness
checks continue:

```bash
sh ./integration/verify_latency_recovery.sh
```

On 2026-11-02 a 200 ms injected delay increased write p50 from 11.292 ms to
212.085 ms while write p99 remained 238.325 ms. Delayed read p99 was 39.2 ms,
maximum readiness latency was 10.789 ms, and no request or readiness check
failed. After the trigger was removed, write p50 returned to 10.553 ms. The
three phases retained exactly 39, 59, and 40 snapshots respectively, matching
all successful writes, with no orphan Finding, audit identity violation,
duplicate event ID, or pending spool entry. This is bounded slow-write recovery
evidence on one Docker Desktop allocation; it is not a storage-saturation,
connection-exhaustion, packet-loss, failover, capacity, or SLO claim.

## Controlled application-pool exhaustion and recovery

The disposable pool-recovery harness recreates only the integration control
plane with a two-connection database pool. Two authenticated snapshot
transactions hold both slots while the harness directly verifies active
PostgreSQL queries, observes database readiness, and times a queued
authenticated read:

```bash
sh ./integration/verify_pool_recovery.sh
```

On 2026-11-02 PostgreSQL reported both application slots occupied, including
one snapshot insert delayed for ten seconds while the second transaction waited
on its shared organization-row lock. The authenticated read waited 9,779 ms;
readiness transitioned from ready to degraded after its bounded database ping
timeout and returned to ready without restarting the process. The recovery
profile then completed 196 reads and 19 writes without request or readiness
error, with read p99 38.3 ms and write p99 35.228 ms. Baseline, holder, and
recovery snapshot counts exactly matched successful writes, and no orphan
Finding, audit identity violation, duplicate event ID, or pending spool entry
remained. This is an intentionally tiny application-pool recovery test, not a
safe production pool-size recommendation, database server connection-limit
test, saturation envelope, or SLO.

## Read-only database transition and recovery

The disposable read-only harness forces new PostgreSQL sessions into read-only
transactions after a verified healthy startup. It proves query reachability,
submits one authenticated snapshot, checks fail-closed audit retention, restores
read-write mode, and exercises recovery load:

```bash
sh ./integration/verify_readonly_recovery.sh
```

On 2026-11-02 the write returned `500`, no rejected snapshot was retained, and
one minimized failed-ingestion audit event remained in the private spool before
the process stopped fail-closed. Startup after restoring read-write mode
replayed that event exactly once and removed its spool file. The recovery phase
completed 200 reads, 20 writes, and 11 readiness checks without error; read p99
was 38.272 ms and write p99 was 43.997 ms. All generated snapshots were present
with no orphan Finding, audit identity violation, duplicate event ID, or replay
duplication after a second restart. This is controlled single-primary behavior,
not evidence for replica routing, standby promotion, managed failover, or an
availability SLO.

## Server-enforced runtime connection limit

The disposable connection-limit harness bootstraps the schema with the database
owner and runs the control plane through a separately privileged PostgreSQL
login. It reduces that login's server-enforced `CONNECTION LIMIT` to zero,
terminates existing runtime sessions, checks fail-closed audit retention, and
then restores normal admission before recovery load:

```bash
sh ./integration/verify_connection_limit_recovery.sh
```

On 2026-11-03 the authenticated repository read returned `500` and PostgreSQL
reported `SQLSTATE 53300`. One minimized authenticated/authorized request event
remained in the private spool before fail-closed shutdown. Restoring the role
limit to 20 replayed the event exactly once; the recovery phase then completed
199 reads, 19 writes, and 11 readiness checks without error. Read p99 was
45.756 ms and write p99 was 55.513 ms. All generated snapshots were retained
with no orphan Finding, audit identity violation, duplicate event ID, pending
spool entry, or replay duplication after restart. This is role-level admission
evidence, not a global `max_connections`, reserved-slot, large-queue,
connection-proxy, capacity, or SLO result.

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

## Beta performance evidence status

The fixed reference soak and progressive ramp now provide a reproducible,
allocation-specific single-replica envelope with an observed target-attainment
boundary and clean post-pressure recovery. Before tagging the first beta, rerun
both harnesses from the exact release-candidate commit and retain their
secret-free output with the candidate evidence. True CPU/memory/storage
saturation, multi-hour behavior, other allocations, and high availability
remain outside this envelope and must not be inferred from the passing result.
