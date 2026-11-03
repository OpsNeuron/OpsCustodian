# Security testing

## Repository and release hygiene

Pull-request CI and the tag workflow run a tracked-file hygiene verifier before
building. It obtains the exact source manifest from `git ls-files`, rejects
unsafe or duplicate manifest paths, symlinks, unexpected binary content,
oversized text, generated root artifacts, the local presentation draft, and
recognizable private-key, hosted-token, signed-URL, or user-home path patterns.
The verifier reports only the rule and repository-relative path, never matching
content. Intentional Agent BOM and SARIF fixtures under `examples` and
`testdata` remain valid source contracts.

Run the same source check locally with:

```bash
go run ./cmd/opscustodian-repocheck --root .
```

The publication workflow separately runs `opscustodian-releasecheck` after
checksums are generated and before provenance or upload. These deterministic
checks reduce accidental disclosure; they do not replace secret scanning of
hosted logs and exact-candidate workflow artifacts.

Security tests complement, but do not replace, review of trust boundaries and
deployment-specific penetration testing. Repositories, parser input,
configuration documents, policy output, connector responses, and persisted
JSON are treated as untrusted.

## Continuous fuzz smoke tests

CI runs bounded native Go fuzzing against twelve high-value decoding boundaries:

- API credential JSON, including unknown fields and trailing values;
- RepositorySet JSON, including schedule, retry, path, and cardinality rules;
- OPA JSON output, including missing, malformed, and invalid decisions;
- GitHub Actions YAML, including malformed roots and attacker-influenced workflow structures;
- multi-document Kubernetes YAML, including malformed documents and supported asset contracts;
- MCP JSON/YAML configuration, including runtime provenance and credential references;
- agent Markdown frontmatter, including declared tools, skills, models, and MCP references; and
- GitHub Agentic Workflows frontmatter, imports, permissions, tools, network rules, and safe outputs; and
- API pagination input, including oversized, cross-scope, empty-payload, malformed, and duplicate cursor or limit parameters; and
- API query filters, including duplicate, untrimmed, oversized, and control-character values; and
- route-specific API query allowlists, including empty, oversized, encoded, and unknown parameter names; and
- the shared audit-event envelope, including schema, timestamp, severity, naming, JSON encoding, and payload-size constraints.

Each target includes valid and adversarial seeds, limits accepted fuzz input to
the corresponding operational payload ceiling, and asserts that every accepted
result still satisfies its downstream contract. The CI smoke duration is 10
seconds per target with four workers to remain predictable on shared runners.

Run the same gate locally:

```bash
go test ./internal/server -run=^$ -fuzz=^FuzzParseBearerCredentialsJSON$ -fuzztime=10s -parallel=4
go test ./internal/ingestion -run=^$ -fuzz=^FuzzParseRepositorySet$ -fuzztime=10s -parallel=4
go test ./internal/policy -run=^$ -fuzz=^FuzzDecodeOPAResponse$ -fuzztime=10s -parallel=4
go test ./internal/parsers/githubactions -run=^$ -fuzz=^FuzzParseWorkflow$ -fuzztime=10s -parallel=4
go test ./internal/parsers/kubernetes -run=^$ -fuzz=^FuzzParseManifest$ -fuzztime=10s -parallel=4
go test ./internal/parsers/mcp -run=^$ -fuzz=^FuzzParseConfiguration$ -fuzztime=10s -parallel=4
go test ./internal/parsers/agentmarkdown -run=^$ -fuzz=^FuzzParseAgentMarkdown$ -fuzztime=10s -parallel=4
go test ./internal/parsers/ghaw -run=^$ -fuzz=^FuzzParseAgenticWorkflow$ -fuzztime=10s -parallel=4
go test ./internal/server -run=^$ -fuzz=^FuzzRequestPage$ -fuzztime=10s -parallel=4
go test ./internal/server -run=^$ -fuzz=^FuzzRequestBoundedQueryValue$ -fuzztime=10s -parallel=4
go test ./internal/server -run=^$ -fuzz=^FuzzRejectUnknownQueryParameters$ -fuzztime=10s -parallel=4
go test ./internal/audit -run=^$ -fuzz=^FuzzValidateEvent$ -fuzztime=10s -parallel=4
```

For release candidates, manually run the `Extended security fuzzing` workflow.
Its fail-independent matrix gives every reviewed boundary a two-minute campaign
with four workers, without adding twelve long-running jobs to every push. A
successful workflow run is release evidence; the presence of the workflow alone
is not. Every matrix job retains a 30-day evidence artifact containing its full
test log, exact commit and workflow identity, target, duration, outcome, and
SHA-256 checksums. Failed jobs upload the same bounded evidence for diagnosis.
The release workflow verifies that all twelve evidence artifacts still exist
and have not expired before it accepts the matching successful campaign.
Retain any minimized crashing corpus as a reviewed regression fixture. Never
seed fuzzing with production credentials, private repository content, or
customer data.

## Dependency reproducibility gate

CI runs `go mod verify` to authenticate downloaded module contents against
`go.sum`, followed by `go mod tidy -diff` to reject an undeclared or stale
module graph. Release automation separately emits the CycloneDX SBOM and build
provenance.

These checks are integrity and reproducibility controls; they do not determine
whether a vulnerable dependency is reachable from OpsCustodian.

## Go vulnerability gate

Every pull request and push to `main` runs the official Go vulnerability
analyzer against all packages. A scheduled run repeats the scan each Monday so
that a newly published advisory can fail the gate even when the repository has
not changed. The scanner version is pinned to remain compatible with the
minimum Go version in `go.mod`; its vulnerability database is queried live on
each run.

Run the same blocking gate locally:

```bash
bash ./scripts/verify-vulnerabilities.sh
```

From Windows Command Prompt, use the equivalent wrapper:

```bat
scripts\verify-vulnerabilities.cmd
```

The text-mode command exits non-zero when it finds a reachable vulnerability or
cannot complete the scan. CI does not maintain a blanket ignore list. A finding
must be fixed by upgrading, removing, or making the vulnerable call unreachable.
Any temporary exception requires a public issue with an owner, expiry date,
affected surface, and compensating control; the workflow remains failing until
that decision is explicitly implemented and reviewed.

This gate covers vulnerabilities known to the Go vulnerability database and
reachable through analyzed Go call graphs. Dependency-license review, manual
security review, and platform penetration testing remain separate release
gates.

## Container vulnerability gate

Every pull request and push to `main` rebuilds the final Docker image from
digest-pinned builder, certificate, policy-runtime, and minimal runtime images.
The workflow downloads Grype 0.119.0 from its immutable release asset, verifies
the reviewed Linux archive SHA-256 before execution, and fails on every known
high or critical operating-system, binary, or Go-module vulnerability in the
final image. A scheduled run repeats the scan each Monday against a freshly
updated vulnerability database.

The final runtime contains BusyBox, the OpsCustodian executable, the pinned OPA
executable, and the copied CA certificate bundle. Build-only Alpine and Go
packages do not enter the final image. The workflow neither enables
`only-fixed` nor continues after a blocking finding; vulnerabilities without an
upstream fix remain visible and blocking when their severity reaches the gate.
Dependabot reviews the Dockerfile weekly so immutable digest pins can advance
through ordinary pull requests and the same blocking scan.

Reproduce the scan with Docker Desktop or another Docker Engine:

```bash
docker build --pull --tag opscustodian:security-scan .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  anchore/grype@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 \
  docker:opscustodian:security-scan --fail-on high --output table
```

The scanner image digest is the reviewed multi-platform manifest for Grype
0.119.0. The CI workflow independently verifies the released Linux binary
archive because hosted runners should not require access to the local Docker
daemon from another container.

## Dependency license gate

Every pull request and push to `main` checks the complete Go package graph,
including test-only dependencies, with go-licenses 2.0.1. The reviewed policy
allows only Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, and MIT. An unknown or
unlisted license fails the workflow; additions require an explicit policy and
contract-test change rather than a command-line exception.

The same run emits `license-report.csv` and retains it as a fourteen-day CI
artifact. Each row records the library, classified license, and a versioned
license source URL when the scanner can discover one; an `Unknown` URL does not
weaken the license-classification allowlist check. Generate the same report
locally:

```bash
bash ./scripts/verify-licenses.sh license-report.csv
```

From Windows Command Prompt:

```bat
scripts\verify-licenses.cmd license-report.csv
```

The generated root report is ignored by Git. It is evidence for the resolved Go
dependency graph, not legal advice and not a scan of base-image packages,
external policy bundles, deployment manifests, or separately installed tools.

## CodeQL static-analysis gate

Pull requests, pushes to `main`, weekly refreshes, and manual runs execute the
GitHub CodeQL action for both Go source and GitHub Actions workflows. The action
is pinned to the reviewed v4.38.2 commit, uses the `security-extended` query
suite, and uploads SARIF through the repository's code-scanning boundary.

The Go job uses CodeQL's `autobuild` mode. Workflow analysis uses the native
`actions` language with no build step. Both jobs are blocking; the workflow does
not use `continue-on-error`. Its token is restricted to reading repository,
Actions, and package metadata plus the required `security-events: write` scope.

CodeQL findings are static signals rather than proof of exploitability or the
absence of vulnerabilities. Manual review, dependency and image scanning,
runtime integration tests, and deployment-specific penetration testing remain
separate gates.

## Current evidence boundary

The initial local campaigns completed bounded fuzz runs for all twelve targets.
They discovered and retained regression cases for invalid GitHub Actions and
MCP inputs; all reviewed targets now pass without a panic or accepted-contract
violation. Passing Go, final-image
vulnerability, and license runs cover only their analyzed software and data
known at execution time. These results do not prove parser correctness for
every input, resistance to sustained resource exhaustion, legal compliance, or
the security of PostgreSQL, Kubernetes, the host, or deployment-specific
configuration.
