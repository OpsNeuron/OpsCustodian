# Project status and delivery path

This document distinguishes implementation from validation. A capability marked
implemented is present in source code; it is not considered production-ready
until its build, automated tests, fixtures, and integration gates pass.

## Current position

OpsCustodian has completed the offline/core implementation scope of the `v0.4`
effective-access milestone. The milestone remains pending final integration,
upstream compatibility, browser, OPA-runtime, and real-environment validation;
those results must not be represented as production readiness.

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

### v0.3 Useful inventory — core implemented, compatibility validation pending

- Codex, Claude, Cursor, and repository instruction discovery.
- GitHub Agentic Workflows source parser.
- GitHub Agentic Workflows imports, custom-agent dependencies, resources, and runtime-import discovery.
- Conservative effective composition for resolved local gh-aw shared workflows, including permission and cycle diagnostics.
- gh-aw import-schema validation for required, unknown, type, and enum constraints.
- Caller-first safe-output precedence and cross-import conflict diagnostics.
- Deterministic network union with conservative blocked-wins conflict handling.
- First-wins MCP server import precedence with secret-safe shape conflicts.
- Full-path gh-aw import cycle diagnostics evaluated before parameter conflicts.
- Typed assets for agents, workflows, MCP servers, skills, and instructions.
- Evidence-backed relationship graph and relationship drift.
- Canonical action, effect, resource, owner, reference, and scope normalization.
- Explicit effect-escalation and scope-expansion drift findings.
- Self-contained local HTML inventory report. *(implemented, pending browser validation)*
- Repeatable longest-prefix monorepo boundaries surfaced in Agent BOM and HTML.
- Enforced parser registry, provenance, evidence, credential, and stable-ID contracts.
- Offline Backstage Component ownership and component-scope correlation.

Missing exit items:

- Upstream-schema fixtures and parser compatibility matrix.
- Complete GitHub Agentic Workflows field precedence and advanced JSON Schema constraints.
- CODEOWNERS ownership correlation. *(initial matcher implemented, pending compatibility tests)*
- Risk model based on scope, environment, effect, controls, and confidence. *(initial explainable model and escalation factors implemented, pending calibration)*

### v0.4 Effective access — offline/core implemented, integration validation pending

- Offline Kubernetes ServiceAccount and workload discovery.
- Evidence-backed workload `runs-as` identity correlation.
- Offline Kubernetes RBAC role/binding parsing and relationship correlation.
- Evidence-backed effective RBAC grant propagation to identities and workloads.
- Effective ServiceAccount token automount precedence and workload token-use capability.
- Explicit Kubernetes RBAC wildcard, bind, escalate, and impersonate detection.
- Mounted projected ServiceAccount token audience and expiration analysis.
- Structured Kubernetes declared-versus-effective access summaries and dangerous expansion diagnostics.
- Provider-neutral, stable, evidence-backed effective access paths generated from Kubernetes RBAC.
- Self-contained HTML access-path explorer with local origin, effect, and escalation filters.
- Object-level RBAC resource names, non-resource URLs, and binding-aware effective scope.
- Fixed-point Kubernetes aggregated ClusterRole composition with selector and evidence propagation.
- Bounded, deterministic Aggregated ClusterRole cycle-path diagnostics.
- Effective-access unit test foundation for RBAC scope, access paths, token precedence, aggregation, and cycles.
- Kubernetes parser unit tests for stable evidence, token projection, exact RBAC rules, aggregation selectors, and malformed documents.
- Agent BOM access-path validation and capability-normalization regression tests.
- HTML reporter security and regression tests for escaping, local filters, encoding, and escalation classification.
- End-to-end scanner test covering discovery, ownership, boundaries, parsing, effective access, correlation, validation, and determinism.
- Explainable risk-model calibration tests for effects, scope, environment, tokens, confidence, mitigations, drift, and graph changes.
- Semantic-drift regression tests for escalation classification, evidence provenance, stable finding IDs, determinism, and asset/capability/relationship lifecycle changes.
- Policy-contract tests for deterministic finding normalization, strict decision validation, bounded process output, and OPA response decoding without an external runtime dependency.
- CI exit-contract tests for severity thresholds, fail-fast option validation, report persistence on policy exits, and wrapped exit causes.
- SARIF regression tests for deterministic rules, GitHub-compatible levels, source regions, stable fingerprints, tool identity, and explicit empty collections.
- Job-scoped GitHub Actions token-permission resolution with workflow inheritance, job override precedence, explicit disablement, unspecified-default tracking, and evidence-backed parser tests.
- Semantic GitHub Actions OIDC-token issuance, deployment-environment capabilities, production context propagation, and explicit unknown protection state pending API enrichment.
- Deterministic workflow-trigger inventory and conservative privileged trust-boundary exposure for `pull_request_target` and `workflow_run`, integrated into explainable capability risk.
- Initial evidence-backed GitHub Actions source-to-sink analysis for privileged untrusted checkout refs and cross-run artifact consumption, without flagging safe default checkout behavior.
- Direct GitHub Actions script-injection paths from attacker-influenced event expressions to runner shells, with safe environment-variable indirection excluded by construction.
- Evidence-backed runner selection inventory with explicit self-hosted exposure, dynamic/group/custom unknown states, and persistent-compromise risk only when combined with untrusted data flow.
- GitHub Actions dependency graph and integrity classification for external actions, reusable workflows, local actions, container tags/digests, full commit SHAs, and dynamic references.
- Reusable workflow call-boundary inventory with caller permission provenance, explicit versus inherited secret propagation, invocation capabilities, and honest local/external resolution state.
- Local reusable workflow composition with bounded nested permissions, secret propagation, cycle/depth diagnostics, direct call relationships, and provider-neutral delegation access paths.
- Semantic effective-access path drift for additions, permission escalation, delegation/authorization rerouting, and removals with multi-asset evidence locations.
- End-to-end access-path drift fixture covering JSON, terminal, SARIF, stable locations, report persistence, and severity-threshold exit behavior.
- Secret-safe MCP runtime provenance for npm, Python, OCI, local executable, system executable, and remote endpoint sources with pinning and transport risk controls.
- Semantic MCP provenance drift for pin/integrity weakening, TLS downgrade, registry/endpoint changes, source transitions, and repository-boundary escapes without duplicate opaque-control findings.
- End-to-end MCP provenance drift fixture covering pin, digest, transport, repository-boundary, JSON, terminal, SARIF, stable-location, and threshold-exit contracts.
- Versioned OpenTelemetry-compatible JSONL audit-event contract for scan summaries, diagnostics, semantic findings, and diff summaries with secret-safe attribute minimization.
- Opt-in OTLP/HTTP JSON log export with TLS-by-default endpoint validation, environment-only authentication headers, bounded timeout, redirect prevention, and partial-rejection handling.
- Versioned current-state finding contract with cross-asset evidence references and initial Kubernetes declared-versus-effective access expansion findings.
- Current-state finding terminal, JSON, SARIF, HTML, and CI severity-threshold consumers with stable fingerprints and evidence locations.
- Structured Kubernetes findings for RBAC privilege escalation, effective ServiceAccount token exposure, and risky projected token audience/lifetime.
- Vendor-neutral current-state MCP findings for mutable runtime identities, insecure remote transport, and repository-boundary escape.
- Structured GitHub Actions findings for privileged triggers, untrusted executable data flow, self-hosted runner exposure, and mutable dependencies.
- Stable namespace-qualified remediation IDs shared by Agent BOM, terminal, SARIF, HTML, audit events, and future policy/API/UI consumers.
- Built-in OPA severity gate for structured current-state findings with remediation and evidence propagation plus deterministic Rego contract tests.
- Byte-stable golden tests for Agent BOM JSON, findings JSON, findings SARIF, and policy decision JSON public contracts.
- Deterministic Finding deduplication with evidence union, highest-severity preservation, stable signal identity, and explicit snapshot lifecycle semantics.
- Central public-contract version registry, machine-readable CLI version output, and normalization compatibility enforcement with legacy-read support.

### v0.5 Organization control plane — started

- Persistence-neutral `Reader` and `Writer` interfaces for validated repository snapshots.
- Thread-safe in-memory multi-repository history with deterministic repository IDs, latest-snapshot selection, defensive copies, and cancellation support.
- Versioned read-only HTTP handler for health, contract discovery, repository inventory, latest Agent BOM, and cross-repository findings.
- Explicit empty collections, deterministic ordering, validated filters, public-safe errors, and baseline response security headers.
- Opaque keyset pagination, immutable snapshot-history endpoints, safe snapshot identifiers, and an OpenAPI 3.1 route-conformance test.
- Episode-aware Finding lifecycle projection with introduced, persisting, resolved, and reintroduced semantics plus source-derived observation timestamps.
- Embedded PostgreSQL migration catalog and transactional runner with tenant-scoped schema, immutable snapshot/Finding storage, checksums, advisory locking, rollback, and newer-database rejection.
- Driver-neutral transactional PostgreSQL snapshot writer with pre-write Agent BOM validation, tenant/repository provisioning, idempotent re-ingestion, immutable revision-conflict rejection, and Finding projection.
- Tenant-scoped PostgreSQL reader for repository inventory, immutable snapshot history, current findings, and episode-aware lifecycle projections with bounded keyset pagination and persisted-BOM revalidation.

The handler is intentionally not connected to a network listener until
authentication, authorization, request limits, and safe bind defaults are
designed and tested.

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
- Declared-versus-effective access comparison with structured current-state findings.
- MCP provenance, version, registry, and pinning analysis.
- OpenTelemetry audit event contract and guarded OTLP/HTTP export.

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
