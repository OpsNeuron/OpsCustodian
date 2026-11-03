# Beta release readiness checklist

This checklist is the evidence gate for the first OpsCustodian beta. A checked
item must be backed by retained command output, a hosted workflow run, or a
reviewed release artifact. Source code or static configuration alone does not
satisfy a real-environment item.

The beta promise is a stable, single-replica control plane with tested upgrade,
recovery, and policy-enforcement paths. Production high availability remains a
separate experimental gate and does not block beta when that limitation is
published explicitly.

## 1. Product and contract freeze

- [ ] Complete the alpha exit gate in [Roadmap](ROADMAP.md). The deterministic
  [representative Finding review](BETA_FINDING_REVIEW.md) classifies all 11
  fixture Findings as evidence-backed intentional detections and is locked by
  a regression test. An independent user must still complete the Quick Start
  from a clean checkout before this item can be checked.
- [x] Review the Agent BOM, finding, policy, audit, ingestion, preflight, and API
  contracts; document every required migration and remove known imminent
  redesigns. The reviewed inventory, compatibility rules, migrations 1 through
  4, and required change procedure are frozen in
  [First-beta contract freeze](BETA_CONTRACT_FREEZE.md).
- [x] Keep repository scan, Agent BOM, HTML report, semantic drift, and policy
  evaluation deterministic and usable without network access.
- [x] Publish the beta support matrix and explicitly list experimental or
  unsupported deployment modes. The narrow contract is recorded in
  [Beta support matrix](BETA_SUPPORT_MATRIX.md) and is required by the beta
  preflight profile.
- [ ] Confirm that no critical or high-severity defect compromises evidence
  integrity, tenant isolation, credential handling, or fail-closed enforcement.

## 2. Deterministic and hosted source gate

Run from the exact release-candidate commit in a clean checkout:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
go build -trimpath -o ./bin/opscustodian ./cmd/opscustodian
./bin/opscustodian doctor --profile beta --format json
git diff --exit-code
```

- [x] Deterministic unit, contract, parser, policy-runtime, and local-mock tests
  exist for the supported source contracts.
- [ ] Hosted Linux tests and race detector pass on the exact candidate commit.
- [ ] Hosted Windows and macOS tests pass on the exact candidate commit.
- [ ] The manual extended-fuzz workflow passes all twelve targets on the exact
  candidate commit and retains all checksummed evidence artifacts.
- [ ] CodeQL analysis and SARIF upload pass. Analysis currently runs, but GitHub
  Code Scanning enablement still blocks the upload and this item must remain
  open until the repository setting is available.
- [ ] Dependency, vulnerability, license, container, and module-integrity gates
  have no unresolved release blocker.

## 3. Installation, upgrade, and recovery gate

- [x] Fresh PostgreSQL bootstrap, forward migration, authenticated ingestion,
  restart recovery, OPA execution, and OTLP export passed in the disposable
  Docker Desktop harness on 2026-10-08.
- [x] Backup, restore, migration rollback/reapplication, and idempotent restart
  passed in the disposable Docker Desktop harness on 2026-10-08.
- [x] Upgrade from the immutable `v0.5.0-alpha` schema-2 binary through the
  current schema-4 audit-idempotency migration while preserving history passed
  in the disposable Docker Desktop harness on 2026-11-01. The run also verified
  legacy audit identity backfill, durable spool replay/removal, and idempotent
  restart without duplicate audit records.
- [x] PostgreSQL outage during an authenticated audited request passed on
  2026-11-02: the control plane failed closed, retained the event in its private
  spool, replayed and acknowledged it after recovery, and did not duplicate it
  on a second restart.
- [x] A bounded 30-second mixed read/write load smoke passed on 2026-11-02 with
  zero request or readiness errors and no snapshot/audit integrity violation.
  This does not replace the sustained reference-environment gate below.
- [x] Controlled snapshot-write contention passed on 2026-11-02 with 32
  concurrent identical writes accepted, 32 concurrent conflicting writes
  rejected, one canonical immutable snapshot retained, exact audit outcomes,
  and no orphan Finding or duplicate audit identity.
- [x] A rate-limited latency/resource probe passed for 60 seconds on
  2026-11-02 at 100 reads and 10 writes per second, with zero request or
  readiness errors and all snapshot/audit/spool integrity checks passing. This
  validates the harness but does not replace the sustained beta profile.
- [x] The default five-minute profile passed on 2026-11-02 with 25,200 reads,
  3,000 writes, 301 readiness checks, zero errors, and intact
  snapshot/audit/spool state.
- [x] The fixed 30-minute `beta-reference-v1` profile passed on 2026-11-03 on
  Docker Desktop 28.3.2 with 16 logical CPUs and 33,534,070,784 bytes assigned
  memory. It completed 145,425 reads, 17,991 writes, and 1,800 readiness checks
  without error; snapshot/audit/spool invariants remained intact. This closes
  sustained correctness evidence, not the capacity-envelope item below.
- [x] The fixed `capacity-ramp-v1` profile passed on 2026-11-03. The
  110-request ceiling achieved 107.2 requests per second with zero errors and
  intact invariants; the 220-request ceiling was the first boundary at 42.417%
  target attainment without corruption or timeout; and the recovery profile
  returned to 99.697% target attainment with clean state.
- [x] PostgreSQL failure under active read/write load passed on 2026-11-02:
  the service failed closed, retained 11 bounded audit events, replayed each
  exactly once after recovery, then completed 399 reads and 39 writes without
  error or snapshot/audit/spool integrity violation.
- [x] Controlled PostgreSQL write latency and recovery passed on 2026-11-02:
  a 200 ms injected delay raised write p50 from 11.292 ms to 212.085 ms without
  request, readiness, snapshot, audit, or spool failure; write p50 returned to
  10.553 ms after the delay was removed.
- [x] Controlled application connection-pool exhaustion passed on 2026-11-02:
  both slots of a two-connection pool were occupied for ten seconds, an
  authenticated read waited 9,779 ms, readiness degraded and recovered without
  restart, and a subsequent 196-read/19-write profile passed every integrity
  check.
- [x] Controlled PostgreSQL read-only transition passed on 2026-11-02: the
  snapshot write returned `500` without partial persistence, one failed audit
  event survived fail-closed shutdown and replayed exactly once, and a
  subsequent 200-read/20-write profile plus second restart remained clean.
- [x] PostgreSQL runtime-role connection admission passed on 2026-11-03: a
  zero role connection limit produced `SQLSTATE 53300` and an audited `500`,
  the event survived fail-closed shutdown and replayed exactly once, and a
  subsequent 199-read/19-write recovery profile remained clean.
- [x] Repeat fresh install, upgrade, rollback, backup, and restore on every
  database-bearing environment in the published beta support matrix. The
  first-beta contract contains one such environment: single-replica Linux
  amd64 with PostgreSQL 17.4. Offline CLI platform rows have no database
  lifecycle, and other database/runtime combinations remain unsupported.
- [x] Exercise sustained load, dependency outage, partial failure, and recovery
  without data-integrity or authorization failure on the declared reference
  environment. The retained evidence covers the fixed 30-minute profile plus
  hard outage, controlled latency, application-pool exhaustion, read-only
  transition, and server-enforced runtime-role connection rejection. Global
  resource saturation remains outside this measured-envelope claim.
- [x] Define and test the supported skip-version upgrade path, or explicitly
  state that only consecutive-version upgrades are supported. The first-beta
  contract supports `v0.5.0-alpha` to the first beta; later betas support only
  the immediately preceding published beta unless retained evidence expands
  the source-version set. Skip-version upgrades are explicitly unsupported.

## 4. Provider and deployment gate

- [x] GitHub App token exchange, cache reuse, private-repository ingestion,
  unchanged-revision handling, and invalid-installation rejection passed
  against disposable resources.
- [ ] Observe real-provider expiry refresh, redirect, cancellation, and rate
  limiting without leaking credential or repository secrets.
- [x] Keep GitHub PAT outside the first-beta support promise until public and
  private parity plus fresh real-provider evidence pass. The beta matrix lists
  PAT authentication as unsupported instead of implying unverified parity.
- [x] Kubernetes admission, single-replica readiness, TLS sidecar access,
  effective-access comparison, and Calico NetworkPolicy behavior passed in
  disposable clusters.
- [ ] Re-run the supported GitHub App path on the exact release candidate.
  Kubernetes is explicitly outside the beta support matrix, so no Kubernetes
  runtime version is part of this release gate.
- [x] Decide whether API OIDC authentication is beta-supported; either validate
  it end to end or list it explicitly outside the beta support promise. OIDC is
  not implemented and is explicitly outside the first-beta support promise.

## 5. Security and operational gate

- [x] Audit events are secret-minimized, bounded, schema-validated, persistent,
  retention-aware, and isolated across fan-out sinks.
- [x] Credential identities are stable and secret-free across authentication,
  authorization, audit, reload, and operational projection.
- [x] Complete a focused threat-model and security review of tenant isolation,
  credential lifecycle, policy failure modes, ingestion, and audit integrity.
  The reviewed controls, accepted residual risks, trust assumptions, and
  scope-changing triggers are recorded in
  [First-beta threat model](THREAT_MODEL.md). This is not a penetration-test or
  production-security claim.
- [x] Publish measured performance and capacity envelopes for the supported
  single-replica deployment using the reproducible process in
  [Performance evidence](PERFORMANCE.md). The envelope is allocation-specific,
  records sustained and short-burst operating points plus the first observed
  target-attainment boundary, and is explicitly not a production SLO.
- [ ] Review installation, upgrade, rollback, backup, restore, and incident
  runbooks by executing them from a clean operator environment. The
  fail-closed `verify_operator_rehearsal.sh` now reproduces the reviewed paths
  from an isolated clone, but it must pass on the exact committed candidate
  before this item is checked.
- [ ] Confirm logs, reports, workflow artifacts, release archives, and examples
  contain no token, private key, signed URL, local absolute path, or generated
  test artifact. Tracked source and release archives now have fail-closed
  deterministic hygiene checks; hosted logs and exact-candidate workflow
  artifacts still require final inspection.

## 6. Release candidate and publication

- [ ] `doctor --profile beta --format json` reports ready in the intended
  release environment and its secret-free output is retained.
- [ ] Release notes and limitations describe the supported beta contract,
  known limitations, migration requirements, and non-HA boundary. Tag
  publication now fails closed when reviewed notes are absent, contain template
  placeholders, or omit the required beta boundaries. The candidate
  `v0.6.0-beta.1` notes are complete and pass the deterministic verifier; final
  review against the exact candidate diff remains required before checking this
  item.
- [ ] The candidate commit is reviewed on protected `main`; all required hosted
  checks pass before its annotated tag is created. Tag verification now fails
  closed unless exact-commit successful `main` push runs exist for CI, Go
  vulnerability, dependency license, container vulnerability, and CodeQL, plus
  the twelve-artifact extended-fuzz run; it retains a checksummed candidate
  evidence manifest for 90 days.
- [ ] Release archives, `SHA256SUMS`, CycloneDX SBOM, and provenance are verified
  from a disposable consumer environment. Publication now fails closed through
  the deterministic release-asset verifier before provenance and upload, but
  the exact-candidate consumer run is still required.
- [ ] At least one external adopter completes the supported deployment and
  runbooks without an unresolved data-integrity or access-control failure.

## Exit rule

The first beta may be tagged only when every unchecked required item above has
retained evidence or has been explicitly removed from the beta support promise
in reviewed documentation. Experimental multi-replica HA is not a beta blocker,
but no beta material may imply an HA or production-readiness guarantee without
passing the separate [HA test plan](HA_TEST_PLAN.md).
