# Contributing

OpsCustodian is a pre-v1 project preparing its first public beta. Contributions
should improve the offline first-user journey, accuracy, evidence,
compatibility, and security rather than broadly adding platform names.

Use the repository issue forms for reproducible bugs, sanitized parser
compatibility examples, and first-user feedback. Never attach credentials,
private repository contents, customer data, or unredacted generated reports.

## Priorities

1. Reproducible offline inventory and permission-drift demos.
2. Accurate, evidence-backed normalization and effective access.
3. Safe handling of untrusted input and credential references.
4. Parser compatibility fixtures from real, sanitized configurations.
5. Clear CLI, HTML, SARIF, policy, and remediation explanations.

## Design expectations

- New inferred facts must include source evidence and confidence.
- Parsers must use untrusted-input limits and fixture-based tests.
- Domain models must not accept secret values.
- Platform-specific parsing must remain separate from canonical comparison.
- New dependencies require a concrete use case and maintenance justification.
- Public APIs are introduced conservatively and documented with compatibility expectations.

## Development workflow

Before opening a pull request, run:

```bash
go fmt ./...
go vet ./...
go test ./...
go build ./cmd/opscustodian
```

Use the pull request template, describe any public-contract or support-boundary
impact, and keep generated reports and local evidence out of Git. All
contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

The disposable container-backed suite is intentionally separate; see
[`docs/INTEGRATION_TESTING.md`](docs/INTEGRATION_TESTING.md). Do not describe
static fixtures, fake-backed tests, or an unexecuted harness as live provider or
production validation. Proposed contract changes should include their relevant
architecture or schema rationale.

## Architecture decisions

Decisions with long-term compatibility, security, or extension consequences
should be recorded under `docs/decisions/` before implementation.
