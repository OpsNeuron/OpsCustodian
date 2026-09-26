# Project status and delivery path

This document distinguishes implementation from validation. A capability marked
implemented is present in source code; it is not considered production-ready
until its build, automated tests, fixtures, and integration gates pass.
The current public support boundary is maintained in
[Public Alpha Limitations](LIMITATIONS.md).

## Current position

The immediate delivery phase is **public-alpha adoption and evidence-backed
hardening**. The offline onboarding path, tagged release, and initial Docker
Desktop integration gate have passed. The current priority is compatibility,
real-provider evidence, and closing the remaining runtime Kubernetes and
operational gates without expanding the public HA claim.

OpsCustodian has completed the offline/core implementation scope of the `v0.4`
effective-access milestone. Deterministic tests, browser report inspection,
OPA runtime execution, Docker-backed PostgreSQL/Collector integration, and
Kubernetes API admission have passed. Upstream compatibility, live runtime
authorization compatibility beyond the sampled fixture, and workload-level
Kubernetes enforcement remain; these results must not be represented as
production readiness.

The control-plane runtime now separates public liveness (`/healthz`) from
bounded dependency readiness (`/readyz`). Database bootstrap, scheduled
ingestion outcomes, and GitHub App authentication update fixed low-cardinality
component states without exposing repository, credential, path, or error data.

Release automation now defines and has executed SHA-pinned least-privilege CI,
Linux race and Windows compatibility gates, cross-platform tagged builds,
checksums, CycloneDX SBOM, provenance attestation, and dependency updates for
`v0.5.0-alpha`. Passing release automation does not imply that every
real-provider or production-runtime gate has passed.

The published Windows amd64 archive has also passed an independent consumer
check: its digest matched `SHA256SUMS`, the archive contained the binary,
license, README, and security policy, the binary reported `v0.5.0-alpha`, the
CycloneDX 1.6 SBOM was populated, and GitHub returned an in-toto SLSA provenance
statement whose subject matched the downloaded archive digest and tagged
release workflow.

The `doctor` command provides versioned terminal/JSON offline preflight profiles
for server configuration, RepositorySet/GitHub App consistency, OPA/policy
presence, and release licensing. It is deliberately secret-free and does not
claim network or runtime validation.

A disposable, internal-network Compose harness has passed on Docker Desktop
with Linux Engine 28.3.2: PostgreSQL 17.4 bootstrap and forward migrations,
authenticated repository ingestion/readiness, OPA 1.7.1 policy tests,
OTLP/HTTP export to OpenTelemetry Collector 0.123.0, and scoped cleanup were
observed. Supplemental disposable validation passed PostgreSQL
`sslmode=verify-full`, migration rollback/reapplication, policy allow/deny and
fail-closed behavior, Kubernetes server-side admission, single-replica runtime
readiness, and HTTPS access through the Envoy sidecar. The current Docker
Desktop cluster did not enforce the NetworkPolicy and exposed no policy-capable
CNI/controller. A follow-up Kind v1.32.2 and Calico v3.32.1 lab passed both the
labeled allow path and unlabeled deny path before complete cleanup. A later
real-provider gate passed GitHub App token exchange/cache reuse, private
repository ingestion, unchanged-revision handling, and secret-safe invalid
installation rejection. PAT parity, expiry-driven refresh, real rate-limit and
redirect observations, load, HA contention, and failure injection remain open.
The offline effective-access result was also compared with live Kubernetes
authorization for four representative namespaced, cluster-wide, non-resource,
and wildcard-derived capabilities without discrepancy.

Database readiness now performs bounded periodic PostgreSQL probes. A Docker
Compose outage/recovery test observed readiness degradation with uninterrupted
liveness, followed by readiness and authenticated API recovery after PostgreSQL
returned. A bounded 2,000-request authenticated read baseline at concurrency 20
completed with zero errors and healthy readiness; sustained load, capacity,
write contention, and broader dependency failure injection remain open.

A restricted Kubernetes/Kustomize deployment contract now preserves the
loopback server boundary through a TLS 1.3 Envoy sidecar and defines probes,
resources, secret references, network policy, and disruption behavior. Both
variants pass server-side API admission, and the base workload reached Ready
in disposable deployments before cleanup. HTTPS through the sidecar passed,
and NetworkPolicy enforcement passed on the policy-capable Kind/Calico lab.

An opt-in two-replica `ha-experimental` overlay and evidence-oriented
takeover/fencing test plan are statically defined. The single-replica base is
unchanged and no HA runtime claim is made before Docker Desktop validation.
HA development is frozen for the alpha introduction: the overlay is retained
only as experimental future work, while the supported evaluation path remains
the offline CLI and a single control-plane replica.

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
- Versioned, bounded, scope-isolated policy evaluation API with explicit
  allow/deny output and fail-closed evaluator behavior; process-level OPA wiring
  remains pending.
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
- Versioned HTTP API for health, contract discovery, repository inventory, latest Agent BOM, cross-repository findings, and bounded snapshot ingestion.
- Explicit empty collections, deterministic ordering, validated filters, public-safe errors, and baseline response security headers.
- Opaque keyset pagination, immutable snapshot-history endpoints, safe snapshot identifiers, and an OpenAPI 3.1 route-conformance test.
- Episode-aware Finding lifecycle projection with introduced, persisting, resolved, and reintroduced semantics plus source-derived observation timestamps.
- Embedded PostgreSQL migration catalog and transactional runner with tenant-scoped schema, immutable snapshot/Finding storage, checksums, advisory locking, rollback, and newer-database rejection.
- Tenant-scoped PostgreSQL scheduler lease schema and adapter with server-time TTLs, atomic takeover, monotonic fencing tokens preserved across release, stale-holder-safe renewal/release, and deterministic driver-neutral tests; real contention tests remain pending.
- Lease-coordinated ingestion runtime with cryptographic per-process holder identity, healthy standby cycles, renewal during active batches, cancellation after lease loss, and transactionally fenced snapshot writes that lock and verify the active lease generation before mutation; real PostgreSQL contention tests remain pending.
- Bounded scheduler coordination configuration and secret-free operational visibility with `leader`, `standby`, and `lease-lost` roles shared by readiness and ingestion audit summaries without exposing holder identities or fencing tokens.
- Persistent scheduler leadership retained and renewed across batch intervals, with bounded standby acquisition retries and deterministic proof that multiple cycles use one lease generation rather than releasing ownership after every scan.
- Driver-neutral transactional PostgreSQL snapshot writer with pre-write Agent BOM validation, tenant/repository provisioning, idempotent re-ingestion, immutable revision-conflict rejection, and Finding projection.
- Tenant-scoped PostgreSQL reader for repository inventory, immutable snapshot history, current findings, and episode-aware lifecycle projections with bounded keyset pagination and persisted-BOM revalidation.
- Environment-only control-plane database configuration with bounded connection-pool and lifecycle defaults, shared organization-ID validation, and a secret-free operational projection.
- Driver-neutral database bootstrap with bounded ping and migration contexts, deterministic lifecycle ordering, optional migration, fail-closed cleanup, and idempotent shutdown.
- Pinned pgx v5 PostgreSQL `database/sql` driver registration with lazy-handle construction and Go 1.25 minimum runtime alignment.
- Fail-closed PostgreSQL transport validation requiring certificate and hostname verification across primary and failover hosts, with an explicit observable development-only insecure override and secret-safe errors.
- Loopback-only HTTP runtime contract with bounded request lifecycle/header limits and deterministic graceful-shutdown orchestration over an injected listener.
- Constant-time opaque Bearer authentication for all control-plane API routes, public health isolation, strict header parsing, secret-free authenticator state, and OpenAPI security declaration.
- Environment-to-digest API-token configuration and fail-closed server composition that cannot construct the operational HTTP server without authentication and a Store reader.
- Deterministic control-plane process orchestration across PostgreSQL bootstrap, authenticated server construction, listener acquisition, serving, and ordered resource cleanup with joined failure preservation.
- Experimental `serve` CLI with environment-only configuration, secret-free no-I/O config inspection, interrupt/termination context cancellation, and default pgx/TCP process dependencies.
- Versioned secret-minimized HTTP request audit events, synchronized JSONL stderr sink, and fail-closed process wiring with server-generated correlation IDs, canonical routes, authentication outcomes, status, and latency.
- Authenticated fail-closed policy-evaluation API backed by a locally executed, timeout-bounded OPA runtime with secret-safe configuration and a pinned container executable.
- Minimized policy request audit summaries containing only bounded outcomes and deny/warn counts, with policy input, decision text, rules, evidence, remediation, and evaluator errors excluded.
- Explicit scope-based API authorization with granular contracts, inventory, and findings read permissions plus a `control-plane:read` umbrella, separate `401`/`403` semantics, fail-closed environment validation, OpenAPI declarations, and authorization audit outcomes.
- Repository-scoped credential grants enforced before in-memory and PostgreSQL collection pagination, direct snapshot reads, finding/lifecycle queries, and snapshot writes, while omitted grants retain the documented organization-wide compatibility behavior.
- Repository-authorized historical semantic drift API comparing two immutable stored snapshots, with versioned OpenAPI coverage and no repository rescan or client-supplied comparison payload.
- Bounded organization-graph API exposing the latest assets, relationships, and effective-access paths per authorized repository with repository-keyset pagination.
- Integrity-preserving organization-graph filters for repository, asset type, owner, component, capability action, and relationship type with filter-bound opaque cursors.
- Tenant-scoped PostgreSQL audit retention with secret-minimized event validation, fail-closed dual sinks, repository-aware filtering, dedicated `audit:read` authorization, and a paginated query API.
- Bounded audit lifecycle enforcement with configurable 24-hour-to-10-year retention, startup and periodic pruning, tenant-isolated delete batches, safe operational projection, and fail-closed process coordination.
- Bounded snapshot lifecycle enforcement with server-time age calculation, a configurable per-repository history floor, latest-snapshot preservation, tenant-isolated delete batches, and fail-closed process coordination.
- Docker-backed snapshot-retention evidence covering real PostgreSQL deletion, batch limiting, latest-history preservation, and dependent-Finding cascade cleanup.
- Docker-backed logical backup and restore across independent PostgreSQL volumes with migration, tenant, content-fingerprint, and authenticated restored-API verification.
- Stable validated credential identity propagated from digest-only Bearer authentication into secret-minimized audit events and safe operational configuration, establishing the contract for multi-token rotation and future OIDC subjects.
- Bounded multi-credential registry with independent identity scopes, duplicate-ID/token rejection, all-digest authentication checks, mutually exclusive legacy configuration, and secret-free operational projection.
- Deterministic credential lifecycle enforcement with disablement, RFC3339 activation/expiration windows, bounded zero-downtime rotation overlap, and indistinguishable public rejection responses.
- Atomic in-process credential reload registry with immutable per-request security snapshots, last-known-good preservation after invalid reloads, and synchronized authentication/authorization publication.
- Hardened credential-file reload boundary with bounded reads, strict JSON, symlink/non-regular rejection, Unix owner-only permission enforcement, file identity verification, and last-known-good preservation.
- Cancellable bounded credential-file polling trigger with immediate load, retry-after-failure behavior, deterministic runtime tests, and structured result observation for future audit/metrics wiring.
- Operational `serve` integration for credential-file hot reload with absolute-path configuration, secret-safe config projection, minimized reload audit events, coordinated cancellation, and fail-closed audit persistence.
- Scope-isolated multi-repository snapshot ingestion with strict 10 MiB Agent BOM decoding, pre-write contract validation, deterministic identifiers, typed immutable conflicts, bounded success responses, and OpenAPI coverage.
- Secret-minimized snapshot-ingestion audit outcomes with validated deterministic identifiers, bounded inventory counts, and rejection-path protection against untrusted metadata propagation.
- Persistence-neutral multi-repository ingestion orchestration with bounded concurrency, conditional known-revision fetches, deterministic result ordering, source-integrity enforcement, and per-repository failure isolation.
- Repository-scoped ingestion timeouts and explicitly classified transient retry handling with bounded exponential backoff, permanent-error fail-fast behavior, and attempt observability.
- Non-overlapping ingestion scheduler with immediate startup execution, completion-based cadence, bounded cryptographic jitter, immutable configuration snapshots, structured observations, and fail-closed observer handling.
- Validated connector registry and secret-free repository configuration with a deterministic local-checkout connector that reuses the production parser pipeline and enforces source/revision identity.
- Versioned strict RepositorySet JSON contract and bounded race-resistant file loader with startup validation for scheduling, retry policy, duplicate identity, boundaries, paths, and connector support.
- Optional fail-closed `serve` wiring for RepositorySet loading, local connector orchestration, non-overlapping scheduling, bounded ingestion audit summaries, and coordinated HTTP/database cancellation.
- Hardened GitHub revision-discovery client with strict repository/ref identity, secret-reference-only authentication, redirect prevention, bounded HTTPS requests/responses, immutable SHA validation, and transient rate-limit/server classification.
- Bounded GitHub ZIP materialization with isolated temporary workspaces, single-root enforcement, Zip Slip/symlink/special-file/duplicate rejection, compressed/extracted/entry ceilings, cancellation, fixed permissions, and idempotent cleanup.
- Two-stage GitHub archive acquisition with immutable-SHA requests, allowlisted HTTPS redirect targets, single-redirect enforcement, Authorization stripping, signed-URL error minimization, direct-response support, and transient failure classification.
- Operational GitHub App authentication with strict installation references, expiry-aware cache refresh, per-installation request coalescing, cancellation, RSA-2048+ validation, bounded RS256 JWTs, hardened token exchange, safe private-key files, secret-free config projection, explicit PAT/App routing, and fail-before-database RepositorySet wiring; real-provider exchange, cache reuse, private ingestion, unchanged-revision, and invalid-installation rejection have passed, while expiry-driven refresh remains pending.
- Secret-minimized GitHub authentication audit events for cache and provider outcomes, including bounded rate-limit/status/duration signals and fail-closed observer propagation.
- End-to-end GitHub connector composition across immutable revision resolution, unchanged short-circuiting, archive acquisition/materialization, production parser scanning, deterministic BOM metadata, and mandatory cleanup propagation.
- RepositorySet and process integration for GitHub repositories with connector-specific schema validation, allowlisted `OPSCUSTODIAN_GITHUB_TOKEN_*` environment references, arbitrary-environment exfiltration prevention, and shared local/GitHub orchestration.

The server can now be started explicitly, but remains restricted to loopback
and is not production-ready. Fine-grained authorization and rotation contracts
exist, while real PostgreSQL TLS/migration behavior has been validated in one
disposable environment. Provider parity, Kubernetes runtime enforcement, HA
contention, load, recovery, and final platform/security gates remain incomplete.

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
- Authentication, authorization, tenant boundaries, audit retention, and snapshot retention.

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
