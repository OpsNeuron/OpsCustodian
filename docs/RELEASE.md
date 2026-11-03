# Release process

OpsCustodian release automation is intentionally tag-driven and fail-closed.
Only tags matching semantic `vMAJOR.MINOR.PATCH` or prerelease
`vMAJOR.MINOR.PATCH-SUFFIX` forms enter the workflow. The first public alpha is
planned as `v0.5.0-alpha`; its evidence gate is the
[`v0.5.0-alpha` checklist](ALPHA_RELEASE_CHECKLIST.md).
The first beta is governed separately by the
[Beta release readiness checklist](BETA_RELEASE_CHECKLIST.md); a passing alpha
release does not imply that the beta operational and adoption gates have passed.

The tagged commit must be reachable from `origin/main`. The release verification
job also queries GitHub Actions for successful `CI`, Go vulnerability, license,
container vulnerability, CodeQL, and `Extended security fuzzing` runs whose
commit exactly equals the tagged commit. The first five must be `push` runs on
`main`; the manually dispatched fuzz run must retain exactly twelve non-expired
`fuzz-evidence-*` artifacts. A run for an earlier commit, a pull-request-only
run, or a successful fuzz run whose evidence expired is deliberately
insufficient, and build or publication jobs cannot start when any required
evidence is missing.

After verifying those run identities, the workflow retains a checksummed,
secret-free `release-candidate.json` artifact for 90 days. It binds the tag and
repository to the exact commit plus the six reviewed workflow run IDs and fuzz
artifact count. This manifest records provenance of the gate decision; it does
not replace inspection of hosted logs, generated artifacts, or attestations.

Release notes must be committed as `docs/releases/<tag>.md`. The verification
job checks the exact tag heading and required installation section before any
build begins; beta tags additionally require explicit support, upgrade,
rollback, known-limitation, single-replica, consecutive-upgrade, and
unsupported-mode language. Unreviewed generated-note fallback is prohibited.
Start beta notes from [`BETA_TEMPLATE.md`](releases/BETA_TEMPLATE.md), replace
every placeholder, and keep the file in review with the candidate. The first
alpha notes are
[`docs/releases/v0.5.0-alpha.md`](releases/v0.5.0-alpha.md).
The workflow independently repeats formatting, vet, unit/contract tests, and
the Linux race detector before building artifacts.

Pull-request CI separately runs the full Go test suite on hosted Windows and
macOS runners. The macOS job also cross-builds both supported Darwin
architectures so ordinary changes cannot silently break either release target.

## Artifacts

The release matrix produces statically linked CLI archives for:

- Linux amd64 and arm64;
- macOS amd64 and arm64;
- Windows amd64.

Every binary is built with `-trimpath` and its tag is injected into the version
contract. Release assets include SHA-256 checksums, a CycloneDX module SBOM, and
GitHub artifact provenance. v0 tags are published as prereleases.

Before provenance is generated or any asset is published, the release workflow
runs the repository's cross-platform release verifier. It requires exactly five
supported-platform archives, one populated CycloneDX SBOM, and one checksum
manifest. Every checksum must match, every archive must contain exactly the
versioned root, executable, `README.md`, `SECURITY.md`, and `LICENSE`, and
metadata is rejected when it contains a private-key marker, recognizable hosted
token, signed URL, or user-specific absolute path. Unexpected directories,
files, archive paths, symlinks, and platform assets fail the release.

Maintainers can reproduce the same check after placing the generated assets and
`SHA256SUMS` in one directory:

```bash
go run ./cmd/opscustodian-releasecheck --dist ./dist --tag v0.6.0-beta.1
```

GitHub Actions have root `contents: read` permission, use full commit SHA pins,
and disable checkout credential persistence. Only the final publish job obtains
scoped `contents: write`, `id-token: write`, and `attestations: write` access.
Dependabot tracks Go modules and Actions pins.

## Required gates

Before creating a public tag:

1. manually run the `Extended security fuzzing` workflow for the exact release
   commit and retain the successful run plus all twelve checksummed evidence
   artifacts as release evidence;
2. run `opscustodian doctor --profile release --format json` and retain the
   secret-free result with the release evidence;
3. verify the committed Apache-2.0 `LICENSE` is included in every archive;
4. require the CI workflow and review on the protected `main` branch;
   release automation additionally requires exact-commit successful push runs
   for CI, Go vulnerability, dependency-license, container-vulnerability, and
   CodeQL workflows;
5. run the deferred real PostgreSQL migration/rollback and container tests;
6. run `opa fmt --fail policies/builtin` and `opa test policies/builtin -v`;
7. validate a real OpenTelemetry Collector/backend path;
8. validate real Kubernetes ingestion and readiness behavior;
9. validate GitHub PAT and GitHub App access against public/private test
   repositories, including provider rate limits;
10. verify the release archives, `SHA256SUMS`, SBOM, and provenance from a
disposable consumer environment.

Kubernetes release validation must render and exercise the contract documented
in [`KUBERNETES_DEPLOYMENT.md`](KUBERNETES_DEPLOYMENT.md); static YAML parsing
does not satisfy admission, networking, TLS, disruption, or rollout gates.

The local deterministic suite does not satisfy these environment-backed gates.
The workflow itself remains source-level implementation until it has completed
successfully in GitHub Actions.

The disposable starting point for PostgreSQL, OPA, and Collector validation is
documented in [`INTEGRATION_TESTING.md`](INTEGRATION_TESTING.md). Its current
source contract is tested, but its containers have deliberately not been run
during the source-development phase.
