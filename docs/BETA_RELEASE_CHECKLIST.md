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

- [ ] Complete the alpha exit gate in [Roadmap](ROADMAP.md), including an
  independent-user Quick Start and representative false-positive review.
- [ ] Review the Agent BOM, finding, policy, audit, and API contracts; document
  every required migration and remove known imminent redesigns.
- [x] Keep repository scan, Agent BOM, HTML report, semantic drift, and policy
  evaluation deterministic and usable without network access.
- [ ] Publish the beta support matrix and explicitly list experimental or
  unsupported deployment modes.
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
- [x] Upgrade from the immutable `v0.5.0-alpha` schema-2 binary to the current
  schema-3 binary passed while preserving snapshot history on 2026-10-08.
- [ ] Repeat fresh install, upgrade, rollback, backup, and restore on every
  environment in the published beta support matrix.
- [ ] Exercise sustained load, write contention, dependency outage, partial
  failure, and recovery without data-integrity or authorization failure.
- [ ] Define and test the supported skip-version upgrade path, or explicitly
  state that only consecutive-version upgrades are supported.

## 4. Provider and deployment gate

- [x] GitHub App token exchange, cache reuse, private-repository ingestion,
  unchanged-revision handling, and invalid-installation rejection passed
  against disposable resources.
- [ ] Observe real-provider expiry refresh, redirect, cancellation, and rate
  limiting without leaking credential or repository secrets.
- [ ] Validate GitHub PAT parity for public and private disposable repositories.
- [x] Kubernetes admission, single-replica readiness, TLS sidecar access,
  effective-access comparison, and Calico NetworkPolicy behavior passed in
  disposable clusters.
- [ ] Repeat Kubernetes and external-provider checks for every version in the
  published beta support matrix.
- [ ] Decide whether API OIDC authentication is beta-supported; either validate
  it end to end or list it explicitly outside the beta support promise.

## 5. Security and operational gate

- [x] Audit events are secret-minimized, bounded, schema-validated, persistent,
  retention-aware, and isolated across fan-out sinks.
- [x] Credential identities are stable and secret-free across authentication,
  authorization, audit, reload, and operational projection.
- [ ] Complete a focused threat-model and security review of tenant isolation,
  credential lifecycle, policy failure modes, ingestion, and audit integrity.
- [ ] Publish measured performance and capacity envelopes for the supported
  single-replica deployment.
- [ ] Review installation, upgrade, rollback, backup, restore, and incident
  runbooks by executing them from a clean operator environment.
- [ ] Confirm logs, reports, workflow artifacts, release archives, and examples
  contain no token, private key, signed URL, local absolute path, or generated
  test artifact.

## 6. Release candidate and publication

- [ ] `doctor --profile beta --format json` reports ready in the intended
  release environment and its secret-free output is retained.
- [ ] Release notes and limitations describe the supported beta contract,
  known limitations, migration requirements, and non-HA boundary.
- [ ] The candidate commit is reviewed on protected `main`; all required hosted
  checks pass before its annotated tag is created.
- [ ] Release archives, `SHA256SUMS`, CycloneDX SBOM, and provenance are verified
  from a disposable consumer environment.
- [ ] At least one external adopter completes the supported deployment and
  runbooks without an unresolved data-integrity or access-control failure.

## Exit rule

The first beta may be tagged only when every unchecked required item above has
retained evidence or has been explicitly removed from the beta support promise
in reviewed documentation. Experimental multi-replica HA is not a beta blocker,
but no beta material may imply an HA or production-readiness guarantee without
passing the separate [HA test plan](HA_TEST_PLAN.md).
