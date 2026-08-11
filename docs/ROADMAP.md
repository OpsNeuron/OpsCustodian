# Roadmap

The roadmap is outcome-based. Dates will be assigned only after the foundation
is reviewed and implementation capacity is known.

## Foundation — current

- Define mission, users, product boundaries, and differentiator.
- Establish architecture and security invariants.
- Publish the first experimental Agent BOM schema.
- Define repository governance and contribution expectations.
- Record architecture decisions as they become irreversible.
- Define validation, diagnostic, stable finding ID, and exit-code contracts.

Exit condition: implementation can begin without reopening the product's core
scope or data ownership rules.

## v0.1 — Proof of value

- Portable Go CLI and configuration loading.
- Deterministic repository discovery.
- GitHub Actions and MCP configuration parsers.
- Agent BOM JSON/YAML generation with evidence.
- Semantic diff for permissions, credential references, scopes, and controls.
- Terminal and machine-readable reports.
- Non-fatal parser diagnostics and internal Agent BOM validation.
- Stable finding IDs, explanation output, and CI severity thresholds.
- Fixture-based parser and end-to-end tests.

Exit condition: a local demo reliably identifies production permission drift.

## v0.2 — CI guardrail

- OPA/Rego policy adapter and open starter policy pack. *(implemented, pending validation)*
- GitHub Action packaging.
- SARIF and pull-request annotations. *(initial SARIF and Action implemented, pending validation)*
- Stable exit-code contract.
- Git baseline comparison and approval-aware findings.
- Actionable remediation messages.

Exit condition: a pull request containing a dangerous access expansion is
blocked with correct evidence and remediation.

## v0.3 — Useful inventory

- Codex, Claude, and Cursor asset discovery. *(initial Markdown/frontmatter discovery implemented, pending validation)*
- GitHub Agentic Workflows source discovery. *(initial parser implemented, pending upstream-schema validation)*
- GitHub Agentic Workflows import and custom-agent dependency discovery. *(implemented, pending compiler compatibility tests)*
- Optional/unresolved import and parameter-conflict diagnostics. *(implemented, pending compatibility tests)*
- Safe-output import precedence and conflict detection. *(implemented, pending compatibility tests)*
- Network import union and allowed/blocked conflict detection. *(implemented, pending compatibility tests)*
- MCP server first-wins precedence and sanitized configuration conflict detection. *(implemented, pending compatibility tests)*
- Explainable full-path import cycle detection. *(implemented, pending compatibility tests)*
- Backstage ownership correlation. *(implemented, pending catalog compatibility fixtures)*
- CODEOWNERS ownership correlation. *(initial resolver implemented, pending GitHub compatibility suite)*
- Explainable risk scoring. *(initial factor model implemented, pending calibration)*
- Canonical capability and scope normalization. *(initial contract and escalation detection implemented, pending tests)*
- Local relationship graph and HTML report. *(initial self-contained report implemented, pending browser validation)*
- Evidence-backed relationship correlation. *(initial in-BOM graph implemented, pending validation)*
- Monorepo support and configurable boundaries. *(initial CLI boundaries implemented, pending config-file support)*
- Documented and runtime-enforced parser extension contract. *(implemented, pending extension compatibility fixtures)*

Exit condition: a platform team can understand agent ownership and access across
a representative repository without manually assembling an inventory.

## v0.4 — Effective access

- Kubernetes workload and ServiceAccount correlation. *(initial offline parser and runs-as graph implemented, pending validation)*
- Kubernetes RBAC role/binding correlation. *(initial offline parser and graph implemented, pending validation)*
- Effective RBAC grant propagation to identities and workloads. *(implemented offline, pending validation)*
- Kubernetes ServiceAccount token exposure analysis. *(automount precedence implemented, pending validation)*
- Kubernetes RBAC privilege-escalation analysis. *(wildcard and special-verb detection implemented, pending validation)*
- Projected ServiceAccount token analysis. *(mounted audience and expiration analysis implemented, pending validation)*
- Declared-versus-effective Kubernetes access. *(structured inherited-access summaries implemented, pending validation)*
- Provider-neutral effective access paths. *(Kubernetes RBAC path producer and validation contract implemented, pending validation)*
- Local effective-access path explorer. *(self-contained HTML rendering and filters implemented, pending browser validation)*
- Binding-aware Kubernetes RBAC scope. *(resource names and non-resource URL semantics implemented, pending validation)*
- Aggregated Kubernetes ClusterRoles. *(selector matching and fixed-point composition implemented, pending validation)*
- Aggregated ClusterRole cycle analysis. *(canonical bounded cycle paths implemented, pending validation)*
- Effective-access unit tests. *(initial Kubernetes RBAC, token, aggregation, and cycle coverage implemented, pending validation)*
- Kubernetes parser unit tests. *(workload, token, RBAC, aggregation, and error-contract coverage implemented, pending validation)*
- Agent BOM contract tests. *(access-path validation, normalization, deduplication, and evidence retention implemented, pending validation)*
- HTML reporter tests. *(self-contained output, escaping, filter, encoding, and escalation coverage implemented, pending validation)*
- Scanner integration test. *(temporary-repository full-pipeline invariants and deterministic repeat scan implemented, pending validation)*
- Optional GitHub API enrichment.
- Declared-versus-effective access findings.
- OpenTelemetry audit events.
- Provenance and pinning checks for MCP servers.

Exit condition: repository declarations can be compared with at least one real
runtime authorization system.

## v1.0 — Organization ready

- Stable Agent BOM and policy input contracts.
- Multi-repository server mode with PostgreSQL.
- REST API and Backstage integration.
- Signed baselines and governed exceptions.
- Retention, upgrade, migration, and compatibility policies.
- Security review and performance benchmarks.

Exit condition: the project can be operated as a dependable organization-wide
control plane while preserving the offline CLI workflow.

## Explicitly outside the early roadmap

- Proprietary policy language.
- General secret, vulnerability, or prompt-injection scanning.
- Agent runtime, model gateway, or model evaluation platform.
- Broad cloud entitlement management unrelated to agents.
- Managed commercial service before open-source product fit is demonstrated.
