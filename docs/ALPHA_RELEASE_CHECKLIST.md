# v0.5.0-alpha release checklist

This checklist is the evidence gate for the first public alpha. A checked item
must link to or retain command output; source code or static configuration alone
does not satisfy a real-environment item.

## 1. Product onboarding

- [x] Five-minute offline Quick Start exists for Windows, Linux, and macOS.
- [x] Demo fixtures produce a self-contained HTML inventory.
- [x] Scope-expansion demo produces an explainable critical semantic drift.
- [x] Installation paths distinguish source, release archive, and Action image.
- [x] Reviewed `v0.5.0-alpha` release notes are wired into tag publication.
- [ ] Capture one current HTML report screenshot for the README.
- [ ] Record a short terminal-to-report demo for the GitHub release.

## 2. Repository and legal

- [x] Apache License 2.0 text is included as the project `LICENSE`.
- [ ] Confirm README, SECURITY, CONTRIBUTING, and repository links.
- [ ] Confirm generated demo/report files remain ignored.
- [x] Docker build context excludes local caches, binaries, reports, and
  generated scan artifacts.
- [ ] Protect `main` and require the CI workflow plus review.
- [ ] Review dependency licenses and the generated CycloneDX SBOM.

## 3. Deterministic source gate

Run from a clean checkout:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
go build -trimpath -o ./bin/opscustodian ./cmd/opscustodian
./bin/opscustodian doctor --profile release --format json
git diff --exit-code
```

- [ ] Linux source gate passes, including the race detector.
- [ ] Windows amd64 source gate passes, excluding the unsupported local race
  detector and relying on the Linux CI race job.
- [ ] Release doctor reports ready with no secret material in its output.
- [ ] GitHub CI passes from a clean protected-branch commit.

## 4. Docker Desktop integration gate

Start Docker Desktop with the Linux engine and sufficient disposable resources.
Use only the repository integration harness and preserve unrelated workloads.

- [x] PostgreSQL 17.4 bootstrap and forward migrations pass in the disposable
  Docker Desktop harness.
- [ ] PostgreSQL rollback/reapply and persistence-after-restart pass.
- [ ] PostgreSQL TLS certificate and hostname verification pass.
- [x] OPA 1.7.1 executes the built-in policy suite successfully (`3/3`).
- [ ] Control-plane policy requests succeed and fail closed as expected.
- [x] OTLP/HTTP events reach OpenTelemetry Collector 0.123.0 and its debug
  backend with resource, scope, body, severity, and OpsCustodian attributes.
- [ ] Kubernetes manifests render, apply, become ready, and enforce network/TLS
  boundaries in the Docker Desktop cluster.
- [ ] Single-replica server ingestion and restart recovery pass.
- [ ] Experimental two-replica lease takeover/fencing tests pass; failures do
  not block the offline alpha, but must prevent any HA-ready claim.

Follow [Integration Testing](INTEGRATION_TESTING.md),
[Kubernetes Deployment](KUBERNETES_DEPLOYMENT.md), and the experimental
[HA Test Plan](HA_TEST_PLAN.md). Record exact image versions and commands.

## 5. Real provider gate

- [ ] GitHub PAT scans public and private disposable repositories.
- [ ] GitHub App installation authentication and token refresh pass.
- [ ] Redirect, cancellation, unchanged-revision, and provider rate-limit
  behavior are observed against the real provider.
- [ ] Live GitHub Action produces the expected SARIF/check result on a pull
  request containing a known risky fixture.
- [ ] At least one real Kubernetes authorization result is compared with the
  offline effective-access result; discrepancies are documented.

Use only disposable repositories and least-privilege credentials. Never retain
tokens, private keys, secret values, or signed download URLs in release evidence.

## 6. Release candidate and publication

- [ ] Build and inspect all Linux, macOS, and Windows archives.
- [ ] Verify `SHA256SUMS`, SBOM, and provenance from a disposable consumer.
- [ ] Confirm `opscustodian version` reports `v0.5.0-alpha` in every archive.
- [ ] Confirm the Quick Start succeeds using the archive, not the source tree's
  development binary.
- [ ] Create annotated tag `v0.5.0-alpha` from the approved commit.
- [ ] Observe the complete Release workflow before announcing availability.
- [ ] Publish limitations: alpha contracts, experimental server, unsupported
  production HA, and the difference between offline evidence and live runtime
  authorization.

The alpha is ready to announce only when sections 1–3 and the applicable
single-instance portions of sections 4–6 have evidence. Experimental HA is not
an alpha release blocker and must not expand the initial product promise.
