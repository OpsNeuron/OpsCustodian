# Project status and delivery path

This document distinguishes implementation from validation. A capability marked
implemented is present in source code; it is not considered production-ready
until its build, automated tests, fixtures, and integration gates pass.

## Current position

OpsCustodian is between the `v0.2` CI guardrail milestone and the `v0.3` useful
inventory milestone.

### Foundation — implemented, pending repository validation

- Product vision and boundaries.
- Versioned Agent BOM and policy decision schemas.
- Typed agentic assets and evidence contracts.
- Security invariants and architecture decisions.

### v0.1 Core — implemented, pending build and automated tests

- CLI commands for scan, diff, explain, and version.
- Deterministic repository discovery.
- GitHub Actions and MCP parsers.
- Agent BOM validation and non-fatal parser diagnostics.
- Semantic drift, severity thresholds, and stable finding IDs.

### v0.2 CI guardrail — implemented, pending integration validation

- OPA/Rego adapter and starter policies.
- SARIF 2.1 reporter with source locations and fingerprints.
- Docker-based GitHub Action and example workflow.
- Stable process exit contract.

### v0.3 Useful inventory — in progress

- Codex, Claude, Cursor, and repository instruction discovery.
- GitHub Agentic Workflows source parser.
- GitHub Agentic Workflows imports, custom-agent dependencies, resources, and runtime-import discovery.
- Conservative effective composition for resolved local gh-aw shared workflows, including permission and cycle diagnostics.
- gh-aw import-schema validation for required, unknown, type, and enum constraints.
- Caller-first safe-output precedence and cross-import conflict diagnostics.
- Typed assets for agents, workflows, MCP servers, skills, and instructions.
- Evidence-backed relationship graph and relationship drift.
- Canonical action, effect, resource, owner, reference, and scope normalization.
- Explicit effect-escalation and scope-expansion drift findings.
- Self-contained local HTML inventory report. *(implemented, pending browser validation)*

Missing exit items:

- Upstream-schema fixtures and parser compatibility matrix.
- Complete GitHub Agentic Workflows field precedence and advanced JSON Schema constraints.
- CODEOWNERS ownership correlation. *(initial matcher implemented, pending compatibility tests)*
- Risk model based on scope, environment, effect, controls, and confidence. *(initial explainable model and escalation factors implemented, pending calibration)*

## Remaining path to 1.0

### Phase A — Complete v0.3 normalization

Build a stable canonical vocabulary for actions, resources, identities,
credentials, tools, environments, and controls. Finish parser coverage and
ownership resolution without adding server infrastructure.

Exit gate: representative repositories produce explainable, deterministic BOMs
with bounded false positives.

### Phase B — v0.4 effective access

- Kubernetes workload, ServiceAccount, and RBAC parser.
- GitHub App, workflow token, environment, and repository permission enrichment.
- Declared-versus-effective access comparison.
- MCP provenance, version, registry, and pinning analysis.
- OpenTelemetry audit event contract.

Exit gate: at least one repository declaration can be correlated with one real
runtime authorization system without collecting credential values.

### Phase C — v0.5 organization control plane

- Read-only server API.
- PostgreSQL persistence and migrations.
- Multi-repository ingestion and incremental scans.
- Organization relationship graph and historical drift.
- Authentication, authorization, tenant boundaries, and audit retention.

Exit gate: a platform team can query inventory and findings across multiple
repositories with reproducible history and least-privilege connectors.

### Phase D — UI surfaces

- Local static HTML report for portable read-only exploration.
- Backstage plugin for catalog ownership and per-component agentic access.
- Standalone web UI only after server APIs and authorization are stable.
- Inventory, asset detail, access graph, findings, policy exceptions, and audit timeline.

Exit gate: UI contains no policy or risk business logic and renders the same
contracts consumed by CLI and CI.

### Phase E — hardening and test lab

- Dedicated safe, risky, and critical agent fixture repository.
- Unit, golden, integration, fuzz, compatibility, security, and performance tests.
- Live GitHub Action/SARIF validation.
- OPA bundle compatibility and policy regression tests.
- Threat model, dependency review, release signing, SBOM, provenance, and secure defaults.
- Windows, Linux, and macOS release verification.

Exit gate: documented quality targets pass on every supported platform and the
project is safe to recommend as a layered production control.

### Phase F — v1.0 release

- Stable Agent BOM, policy input, decision, relationship, and API contracts.
- Schema migration and compatibility policy.
- Signed release artifacts and reproducible build documentation.
- Operational runbooks, upgrade path, and incident response process.
- Public examples, adoption guide, and contribution roadmap.

## Explicitly deferred

- Running or hosting AI models.
- Replacing OPA, Backstage, GitHub, or Kubernetes.
- General-purpose secret and vulnerability scanning.
- Standalone UI before server and authorization contracts stabilize.
- Production claims before the hardening and test-lab gates pass.
