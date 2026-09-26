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
reachable through analyzed Go call graphs. Dependency-license review, container
and operating-system package scanning, manual security review, and platform
penetration testing remain separate release gates.

## Current evidence boundary

The initial local campaign completed bounded fuzz runs for all three targets
without a panic or accepted-contract violation. A passing Go vulnerability run
covers only the source graph and advisories known at execution time. These
results do not prove parser correctness for every input, resistance to sustained
resource exhaustion, or the security of OPA, PostgreSQL, container, Kubernetes,
or operating-system dependencies.
