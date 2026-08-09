# Contributing

OpsCustodian is in its foundation phase. Early contributions should strengthen
the product contract rather than broaden the platform list.

## Priorities

1. Deterministic GitHub-first discovery.
2. Accurate, evidence-backed normalization.
3. Semantic permission drift.
4. Safe handling of credential references.
5. Clear CLI and CI explanations.

## Design expectations

- New inferred facts must include source evidence and confidence.
- Parsers must use untrusted-input limits and fixture-based tests.
- Domain models must not accept secret values.
- Platform-specific parsing must remain separate from canonical comparison.
- New dependencies require a concrete use case and maintenance justification.
- Public APIs are introduced conservatively and documented with compatibility expectations.

## Development workflow

The concrete build, lint, and test commands will be added with the Go module in
the implementation phase. Until then, proposed changes should include the
relevant architecture or schema rationale.

## Architecture decisions

Decisions with long-term compatibility, security, or extension consequences
should be recorded under `docs/decisions/` before implementation.
