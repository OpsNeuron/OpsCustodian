# Security testing

Security tests complement, but do not replace, review of trust boundaries and
deployment-specific penetration testing. Repositories, parser input,
configuration documents, policy output, connector responses, and persisted
JSON are treated as untrusted.

## Continuous fuzz smoke tests

CI runs bounded native Go fuzzing against three high-value decoding boundaries:

- API credential JSON, including unknown fields and trailing values;
- RepositorySet JSON, including schedule, retry, path, and cardinality rules;
- OPA JSON output, including missing, malformed, and invalid decisions.

Each target includes valid and adversarial seeds, limits accepted fuzz input to
the corresponding operational payload ceiling, and asserts that every accepted
result still satisfies its downstream contract. The CI smoke duration is 10
seconds per target with four workers to remain predictable on shared runners.

Run the same gate locally:

```bash
go test ./internal/server -run=^$ -fuzz=^FuzzParseBearerCredentialsJSON$ -fuzztime=10s -parallel=4
go test ./internal/ingestion -run=^$ -fuzz=^FuzzParseRepositorySet$ -fuzztime=10s -parallel=4
go test ./internal/policy -run=^$ -fuzz=^FuzzDecodeOPAResponse$ -fuzztime=10s -parallel=4
```

For release candidates, increase `-fuzztime` in a disposable environment and
retain any minimized crashing corpus as a reviewed regression fixture. Never
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

## Current evidence boundary

The initial local campaign completed bounded fuzz runs for all three targets
without a panic or accepted-contract violation. Passing Go and final-image
vulnerability runs cover only their analyzed software and advisories known at
execution time. These results do not prove parser correctness for every input,
resistance to sustained resource exhaustion, or the security of PostgreSQL,
Kubernetes, the host, or deployment-specific configuration.
