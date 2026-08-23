# Release process

OpsCustodian release automation is intentionally tag-driven and fail-closed.
Only tags matching a semantic `vMAJOR.MINOR.PATCH` form enter the workflow.
The workflow independently repeats formatting, vet, unit/contract tests, and
the Linux race detector before building artifacts.

## Artifacts

The release matrix produces statically linked CLI archives for:

- Linux amd64 and arm64;
- macOS amd64 and arm64;
- Windows amd64.

Every binary is built with `-trimpath` and its tag is injected into the version
contract. Release assets include SHA-256 checksums, a CycloneDX module SBOM, and
GitHub artifact provenance. v0 tags are published as prereleases.

GitHub Actions have root `contents: read` permission, use full commit SHA pins,
and disable checkout credential persistence. Only the final publish job obtains
scoped `contents: write`, `id-token: write`, and `attestations: write` access.
Dependabot tracks Go modules and Actions pins.

## Required gates

Before creating a public tag:

1. run `opscustodian doctor --profile release --format json` and retain the
   secret-free result with the release evidence;
2. select and commit the project `LICENSE`; release automation intentionally
   fails while this legal decision is unresolved;
3. require the CI workflow and review on the protected `main` branch;
4. run the deferred real PostgreSQL migration/rollback and container tests;
5. run `opa fmt --fail policies/builtin` and `opa test policies/builtin -v`;
6. validate a real OpenTelemetry Collector/backend path;
7. validate real Kubernetes ingestion and readiness behavior;
8. validate GitHub PAT and GitHub App access against public/private test
   repositories, including provider rate limits;
9. verify the release archives, `SHA256SUMS`, SBOM, and provenance from a
   disposable consumer environment.

The local deterministic suite does not satisfy these environment-backed gates.
The workflow itself remains source-level implementation until it has completed
successfully in GitHub Actions.

The disposable starting point for PostgreSQL, OPA, and Collector validation is
documented in [`INTEGRATION_TESTING.md`](INTEGRATION_TESTING.md). Its current
source contract is tested, but its containers have deliberately not been run
during the source-development phase.
