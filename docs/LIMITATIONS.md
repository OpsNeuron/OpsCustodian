# Public alpha limitations

OpsCustodian `v0.5.0-alpha` is intended for evaluation, local analysis, CI
feedback, and compatibility testing. It is not yet a sole production security
control or an availability-critical authorization service.

## Supported evaluation scope

- The offline CLI is the primary supported path: scan repositories, generate an
  Agent BOM, inspect HTML/SARIF output, evaluate built-in policy, and compare
  semantic drift.
- Released archives, checksums, CycloneDX SBOM, and provenance have passed the
  documented release verification process.
- The single-replica control plane, PostgreSQL persistence, OPA execution,
  OTLP export, GitHub App ingestion, and Kubernetes deployment have passed
  disposable environment tests documented in
  [Integration Testing](INTEGRATION_TESTING.md).

## Contracts may change

The Agent BOM, findings, policy decision, audit event, HTTP API, configuration,
and database contracts are alpha interfaces. Changes before `v1.0` may require
regenerating baselines or updating integrations. Release notes will identify
intentional compatibility breaks.

## Offline evidence is not live authorization

Effective access is derived from repository configuration and retained source
evidence. It does not query every provider at decision time and must not replace
Kubernetes admission, cloud IAM, GitHub protection rules, or human review.

A disposable Kubernetes fixture produced matching offline and live
authorization results for representative namespaced, cluster-wide,
non-resource URL, and wildcard-derived capabilities. That sample validates the
model path; it is not a universal provider compatibility guarantee.

## Parser coverage is conservative

Unsupported syntax, generated configuration, remote indirection, or provider
features may produce diagnostics or incomplete inventory. Absence of an asset,
capability, finding, or access path is not proof of absence. Review diagnostics
and retained evidence before acting on a result.

## The organization server is experimental

The server is loopback-bound by default and requires authenticated,
scope-authorized access. The supported evaluation topology is one replica.
The two-replica overlay and lease/fencing design are experimental and do not
constitute a production HA, failover, disaster-recovery, or multi-region claim.

PostgreSQL outage/recovery and a bounded authenticated read-load baseline have
passed on one Docker Desktop host. A separate audited-request outage also
proved fail-closed process termination, private durable retention, exactly-once
replay after database recovery, acknowledgement, and duplicate-free restart.
Those observations are regression evidence, not a capacity plan, soak result,
latency objective, or availability SLA.
The 30-second mixed read/write smoke also passed with zero request/readiness
errors and no snapshot or audit-identity integrity violation. Its duration and
single-host scope are insufficient for a sustained-load or capacity claim.
A bounded contention run additionally accepted 32 concurrent identical writes,
rejected 32 concurrent conflicting writes, and preserved one canonical
immutable snapshot with exact audit outcomes. It does not establish maximum
safe concurrency, sustained throughput, latency objectives, or saturation
behavior.
A separate rate-limited 60-second measurement completed at 110 requests per
second without request/readiness or persistence-integrity errors and produced
client-observed latency percentiles plus sampled container resources. The
result is specific to one Docker Desktop allocation and is too short to define
a supported capacity envelope, SLO, or long-duration stability claim.
Custom-format logical backup and restore between isolated PostgreSQL 17.4
volumes has also passed with content fingerprint and authenticated API checks.
Physical backups, WAL-based point-in-time recovery, cross-version restore,
managed-provider snapshots, and production RPO/RTO remain unvalidated.
The direct `v0.5.0-alpha` schema-2 to current schema-4 upgrade has passed with
history preservation, legacy audit identity backfill, durable spool replay,
event idempotency, and fail-closed version-skew checks. Mixed-version rolling
upgrades, skip-version paths, in-place production downgrade, and migration
timing on large databases remain unvalidated.

Bounded CI fuzzing covers credential JSON, RepositorySet JSON, and OPA decision
output. Module checksum, tidy-diff, reachable Go vulnerability, final-image
vulnerability, Go dependency-license, and CodeQL Go/GitHub Actions gates also
run in CI. The image gate rebuilds digest-pinned bases
and rejects known high or critical findings in the final runtime, including
operating-system and embedded binary packages. These gates do not cover private
advisories, non-Go and deployment dependency licenses, legal compliance,
penetration testing, sustained resource exhaustion, every parser input, or
vulnerabilities absent from their databases at execution time.

## Provider validation is incomplete

Real GitHub App token exchange, cache reuse, private-repository ingestion,
unchanged-revision handling, and invalid-installation rejection have passed on
a disposable repository. The remaining real-provider gates include PAT parity
with a fresh least-privilege token, expiry-driven App refresh, redirect and
cancellation observation, and rate-limit behavior. Deterministic local contract
tests cover those paths but do not replace real-provider evidence.

## Operational responsibility remains with the user

Use disposable or sanitized repositories for evaluation. Keep credentials in
the documented secret boundaries, review generated reports before sharing, and
retain an independent authorization and deployment control. Do not treat an
alpha finding, policy decision, or lack of findings as the sole basis for a
production change.

## Exit criteria for a later stability milestone

A later beta or stable claim requires broader parser/provider compatibility,
fresh real-provider credential tests, sustained read/write and failure testing,
upgrade and rollback evidence, documented support boundaries, and feedback from
independent repositories. Production HA remains a separate milestone unless it
is explicitly tested and documented.
