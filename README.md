# OpsCustodian

OpsCustodian is an evidence-based control plane for AI agents operating in
software delivery and infrastructure environments.

It discovers agentic assets, normalizes their effective access into a
vendor-neutral Agent Bill of Materials (Agent BOM), detects semantic permission
drift, and evaluates organizational policy before risky changes reach
production.

## Product promise

OpsCustodian answers one operational question:

> Which agent, using which identity, can access which tool, credential,
> repository, and environment—and did that access become more dangerous?

Agent BOM inventories typed `assets`: agents, workflows, MCP servers, skills,
and instruction sets. Different ecosystem objects remain distinct while still
participating in one evidence and access graph.

The initial product wedge is GitHub-first permission drift detection:

```text
repository configuration
        -> discovery and evidence
        -> normalized Agent BOM
        -> semantic baseline diff
        -> policy decision and remediation
        -> CLI / CI / SARIF / GitHub Check
```

## CLI experience

```bash
opscustodian scan . --output agentbom.json
opscustodian findings --bom agentbom.json --format terminal --fail-on high
opscustodian diff baseline.json proposed.json
opscustodian check --baseline baseline.json --bom proposed.json --policy ./policies
opscustodian explain --report drift.json <finding-id>
opscustodian report --bom agentbom.json --output opscustodian-report.html
```

For monorepositories, assign assets to explicit component boundaries:

```bash
opscustodian scan --boundary services/payments=payments --output agentbom.json .
```

The first pre-alpha implementation now includes offline artifact discovery,
GitHub Actions and MCP configuration parsing, Agent BOM validation, non-fatal
parser diagnostics, JSON/YAML output, stable finding IDs, semantic `diff`, CI
severity thresholds, finding explanations, and OPA/Rego policy evaluation.
Hosted CI integration remains planned for the next milestones.

## Build prerequisites

- Go 1.23 or newer

```bash
go mod download
go build -o ./bin/opscustodian ./cmd/opscustodian
```

Example:

```bash
./bin/opscustodian scan . --output agentbom.json
./bin/opscustodian diff \
  examples/permission-drift/agentbom.before.json \
  examples/permission-drift/agentbom.after.json
```

For CI, request JSON and fail at a chosen severity threshold:

```bash
./bin/opscustodian diff --format json --fail-on high \
  baseline.json proposed.json > drift.json
```

Exit codes are stable: `0` means successful execution below the configured
threshold, `1` means an operational or input error, and `2` means semantic drift
met the `--fail-on` threshold.

SARIF output is available for GitHub and other compatible consumers:

```bash
./bin/opscustodian diff --format sarif --output opscustodian.sarif \
  --fail-on high baseline.json proposed.json
```

A self-contained, read-only HTML inventory can be generated without starting a
server or loading external resources:

```bash
./bin/opscustodian report --bom agentbom.json --output opscustodian-report.html
```

The report summarizes typed assets, owners, capabilities, credentials,
relationships, and parser diagnostics. Repository-provided values are escaped
before rendering, and the generated document contains no JavaScript.

Malformed supported artifacts are emitted as Agent BOM diagnostics. One bad
workflow does not hide successfully parsed assets elsewhere in the scan.

## Principles

- Evidence before assertion: every inferred capability must point to its source.
- Semantic changes over textual noise: report access changes, not formatting.
- Safe by construction: record secret references, never secret values.
- Vendor-neutral core: normalize platform-specific configuration into a shared model.
- Offline first: repository scans must not require network access.
- Explainable enforcement: every denial must include its reason and remediation.
- Open contracts: the Agent BOM schema and core policy interfaces remain open.

## Project documents

- [Vision](docs/VISION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Agentic asset model](docs/ASSET_MODEL.md)
- [Relationship graph](docs/RELATIONSHIP_GRAPH.md)
- [GitHub Agentic Workflows coverage](docs/GH_AW.md)
- [Current project status](docs/PROJECT_STATUS.md)
- [Ownership resolution](docs/OWNERSHIP.md)
- [Explainable risk model](docs/RISK_MODEL.md)
- [Canonical normalization](docs/NORMALIZATION.md)
- [Local inventory report](docs/LOCAL_REPORT.md)
- [Monorepo boundaries](docs/MONOREPO.md)
- [Parser extension contract](docs/PARSER_EXTENSIONS.md)
- [Kubernetes effective access](docs/KUBERNETES.md)
- [MCP server provenance and pinning](docs/MCP.md)
- [OpenTelemetry-compatible audit events](docs/AUDIT_EVENTS.md)
- [Current-state findings](docs/FINDINGS.md)
- [Public contract tests](docs/CONTRACT_TESTS.md)
- [Compatibility and versioning](docs/COMPATIBILITY.md)
- [Read-only server foundation](docs/SERVER.md)
- [Control-plane OpenAPI 3.1](api/openapi.yaml)
- [PostgreSQL persistence and migrations](docs/DATABASE.md)
- [Stable remediation identifiers](docs/REMEDIATIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Policy enforcement](docs/POLICY.md)
- [GitHub Action integration](docs/GITHUB_ACTION.md)
- [Agent BOM v1alpha1 schema](schemas/agentbom-v1alpha1.schema.json)
- [Policy decision schema](schemas/policy-decision-v1alpha1.schema.json)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Status

Pre-alpha (`v0.1` under active development). File formats and APIs may change
until the first compatibility guarantee is published.

## License

The intended license for the open-source core is Apache-2.0. The complete
license text will be added before the first public release.
