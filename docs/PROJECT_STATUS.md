# Project status and delivery path

This document distinguishes implementation from validation. A capability marked
implemented is present in source code; it is not considered production-ready
until its build, automated tests, fixtures, and integration gates pass.
The current public support boundary is maintained in the
[Beta support matrix](BETA_SUPPORT_MATRIX.md), with residual pre-v1 and
experimental constraints explained in [Limitations](LIMITATIONS.md).

## Current position

The immediate delivery phase is **public-beta adoption and post-release
evidence closure**. The [`v0.6.0-beta.1`](https://github.com/OpsNeuron/OpsCustodian/releases/tag/v0.6.0-beta.1)
prerelease has been published with cross-platform archives, checksums, a
CycloneDX SBOM, and build provenance after exact-commit hosted CI, CodeQL,
container, dependency, license, and twelve-artifact extended-fuzz gates passed.
The support promise remains deliberately restricted to the offline CLI
platforms and single-replica control-plane reference listed in the beta matrix.
The reviewed mixed fixture produces 11 intentional, evidence-backed Findings
and is regression-locked against silent identity, severity, source,
remediation, or evidence-count drift. The current priorities are independent
artifact consumption, remaining real-provider failure-mode evidence,
operator-runbook review, and external-adopter feedback; Kubernetes and HA do
not silently expand the beta scope.

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

Release automation has executed SHA-pinned least-privilege CI, Linux race,
Windows, and macOS compatibility gates plus cross-platform tagged builds,
checksums, CycloneDX SBOM generation, and provenance attestation for
`v0.6.0-beta.1`. Passing release automation does not imply that every
real-provider or production-runtime gate has passed.

Release publication now also fails closed through a cross-platform Go verifier
before provenance and upload. It checks the exact supported asset set,
SHA-256 manifest, archive paths and contents, populated CycloneDX shape, and
obvious private-key, hosted-token, signed-URL, or user-path leakage. The
published beta passed this deterministic control; an independent disposable
consumer verification of its archives and provenance remains open.

Tag verification now binds hosted candidate evidence to the exact tagged
commit. Successful `main` push runs are required for CI, Go vulnerability,
dependency-license, container-vulnerability, and CodeQL workflows, together
with the twelve-artifact extended-fuzz run. The workflow retains a checksummed,
secret-free manifest of the repository, tag, commit, run IDs, and fuzz artifact
count for 90 days; earlier-commit or pull-request-only success cannot satisfy
the gate. The published `v0.6.0-beta.1` tag satisfied this exact-commit gate.

Tag publication no longer falls back to generated release notes. An exact
`docs/releases/<tag>.md` file must pass the release-note verifier before the
build starts; beta notes must name the support matrix, threat model,
consecutive-upgrade/restore path, known limitations, single-replica boundary,
and unsupported modes without unresolved placeholders. The final beta tag and
its reviewed note file are now published. The complete `v0.6.0-beta.1` notes
passed that verifier on the exact tagged commit.

Pull-request and tag workflows now also scan the exact `git ls-files` source
manifest with a secret-safe hygiene verifier. It rejects generated root output,
the local presentation draft, unsafe tracked paths, unexpected binary content,
and recognizable private-key, hosted-token, signed-URL, or user-home patterns
without echoing matched content. Hosted logs and generated workflow artifacts
still require inspection on the exact candidate.

The operator-runbook gate now has one fail-closed rehearsal entry point. It
requires a clean committed worktree, creates a detached local clone, and runs
source validation, the offline Quick Start, base integration, logical
backup/restore, consecutive upgrade, and active database-outage recovery before
confirming project-scoped Docker cleanup. The harness is implemented and
contract-tested; its exact-candidate run remains an open beta evidence item.

The published Windows amd64 archive has also passed an independent consumer
check: its digest matched `SHA256SUMS`, the archive contained the binary,
license, README, and security policy, the binary reported `v0.5.0-alpha`, the
CycloneDX 1.6 SBOM was populated, and GitHub returned an in-toto SLSA provenance
statement whose subject matched the downloaded archive digest and tagged
release workflow. The macOS compatibility gate has now passed on a hosted
runner for the exact public-beta commit.

The custom CodeQL workflow is active for Go and GitHub Actions. Both analyses
successfully uploaded results for the exact public-beta commit and satisfied
the release evidence gate. Future changes must keep the advanced workflow
active and must not enable a conflicting default CodeQL configuration.

The `doctor` command provides versioned terminal/JSON offline preflight profiles
for server configuration, RepositorySet/GitHub App consistency, OPA/policy
presence, release licensing, and Beta evidence-file readiness. It is deliberately
secret-free and does not claim network, hosted-workflow, or runtime validation.
The reviewed [Beta release readiness checklist](BETA_RELEASE_CHECKLIST.md)
separates already retained evidence from the remaining hosted, provider,
security, performance, and external-adoption gates.
On a clean checkout, Beta preflight intentionally remains not-ready until the
operator supplies server configuration and a local OPA executable; this keeps
missing runtime prerequisites visible instead of treating repository files as
proof of deployment readiness.

A disposable, internal-network Compose harness was re-run on 2026-10-08 on
Docker Desktop 4.44.1 with Linux Engine 28.3.2. It passed PostgreSQL 17.4
bootstrap and forward migrations,
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
installation rejection. Deterministic expiry-aware refresh, cache coalescing,
and fail-closed token validation are covered by the local ingestion suite. PAT
parity, provider-observed expiry-driven refresh, real rate-limit and
redirect observations, load, HA contention, and failure injection remain open.
The same run passed the isolated PostgreSQL backup/restore and schema upgrade
compatibility profiles, including restored API reads, preserved history,
idempotent restart, and fail-closed future-version rejection. The offline
effective-access result was also compared with live Kubernetes
authorization for four representative namespaced, cluster-wide, non-resource,
and wildcard-derived capabilities without discrepancy.

On 2026-11-01 the upgrade profile was extended and re-run from the immutable
`v0.5.0-alpha` schema-2 binary through current schema 4. Snapshot history and
content digest were preserved; legacy audit identity was backfilled; a pending
durable-spool event was replayed, acknowledged, and persisted exactly once
across restart; both older-schema and unknown-future version skew failed
closed; and all disposable containers and volumes were removed.

Database readiness now performs bounded periodic PostgreSQL probes. A Docker
Compose outage/recovery test observed readiness degradation with uninterrupted
liveness, followed by readiness and authenticated API recovery after PostgreSQL
returned. On 2026-11-02 an audited-request outage additionally proved
fail-closed process termination, private durable event retention, exactly-once
startup replay and acknowledgement, and duplicate-free restart. A bounded
2,000-request authenticated read baseline at concurrency 20
completed with zero errors and healthy readiness. On 2026-11-02 a separate
30-second smoke completed 4,150 reads and 1,036 writes under ten concurrent
workers with zero request/readiness errors and no snapshot or audit-identity
integrity violation. A separate controlled run accepted 32 concurrent identical
snapshot writes, rejected 32 concurrent content conflicts, retained one
canonical immutable snapshot, and preserved exact audit identity. Broader
dependency failure injection remains open. A
rate-limited 60-second latency/resource profile also completed 6,000 reads and
600 writes without error at 110 requests per second, with read p99 71.853 ms,
write p99 93.289 ms, and intact snapshot/audit/spool checks; this validates the
measurement harness rather than closing the sustained beta gate.
The default five-minute profile then completed 25,200 reads, 3,000 writes, and
301 readiness checks without error at 94 completed requests per second. Read
p99 was 278.343 ms, write p99 was 296.639 ms, persistence/audit/spool checks
remained intact, and sampled PostgreSQL CPU peaked at 114.56% on the Docker
Desktop allocation.
The fixed 30-minute `beta-reference-v1` profile subsequently completed 145,425
reads, 17,991 writes, and 1,800 readiness checks without error on a 16-CPU,
33,534,070,784-byte Docker Desktop allocation. Read p99 was 340.654 ms, write
p99 was 374.199 ms, persistence/audit/spool checks remained intact, and sampled
PostgreSQL CPU peaked at 114.43%. The observed aggregate completion rate of
90.787 requests per second remained below the configured 110-request ceiling,
so sustained correctness is closed and the capacity experiment below defines
the first measured boundary.
The fixed capacity ramp then validated 107.2 requests per second for two
minutes at 97.455% target attainment and found the first boundary at the
220-request configured ceiling, where only 93.317 requests per second and
42.417% attainment were observed without request, readiness, or integrity
failure. A low-pressure recovery profile returned to 99.697% attainment with
clean state. The measured single-host envelope is now published; a true
CPU/memory saturation point and production SLO remain intentionally undefined.
An active-load PostgreSQL outage then produced the expected read, write, and
readiness failures and stopped the process fail-closed. Eleven private audit
events replayed exactly once after recovery; a subsequent profile completed
399 reads and 39 writes without error, preserved all snapshot/audit/spool
invariants, and remained duplicate-free after another restart. A controlled
200 ms snapshot-write delay subsequently raised write p50 from 11.292 ms to
212.085 ms without read, write, or readiness errors and returned to 10.553 ms
after removal; every phase preserved exact snapshot, audit, and spool
invariants. A separate two-connection application-pool test directly observed
both slots occupied, a 9,779 ms authenticated-read wait, degraded database
readiness, and recovery without restart; the subsequent 196-read/19-write
profile passed without error or integrity violation. PostgreSQL server-level
connection limits, large wait queues, packet loss, storage saturation, and
broader partial-dependency injection remain open.
A controlled read-only transition then rejected an authenticated snapshot with
`500`, retained no partial snapshot, durably spooled one failed-ingestion audit
event, and stopped fail-closed. Restoring read-write mode replayed the event
exactly once; a 200-read/20-write recovery profile and another restart remained
free of persistence, audit, or spool violations. Replica routing, promotion,
and managed-database failover remain open.
A separately privileged PostgreSQL runtime role was then reduced to a
server-enforced zero connection limit. The resulting authenticated read
returned `500` with `SQLSTATE 53300`, its audit event survived fail-closed
shutdown, and restoring the limit replayed it exactly once. A subsequent
199-read/19-write profile and second restart passed without request, readiness,
persistence, audit, or spool violation. Global `max_connections`, reserved
slots, large connection queues, and managed proxies remain open.
Repeatable source benchmarks now cover constant-time authentication at the full
100-credential boundary, atomic credential reload, and bounded audit-envelope
validation. A manual hosted workflow retains raw benchmark and environment
evidence. The fixed sustained reference profile and progressive capacity ramp
now pass, and their allocation-specific envelope is published without implying
a production SLO.

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
- Semantic GitHub Actions OIDC-token issuance, deployment-environment capabilities, production context propagation, evidence-backed job scoping, and explicit unknown protection state are implemented offline; live provider protection-state enrichment remains pending.
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
- Reviewed first-beta contract freeze covering public JSON, API, ingestion, preflight, SARIF, and database migration boundaries, with complete CLI/API contract discovery.

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
- Driver-neutral transactional PostgreSQL snapshot writer with pre-write Agent BOM validation, tenant/repository provisioning, contention-safe idempotent re-ingestion without immutable-row updates, immutable revision-conflict rejection, and Finding projection; bounded 32-worker identical/conflicting contention passed against PostgreSQL on 2026-11-02.
- Tenant-scoped PostgreSQL reader for repository inventory, immutable snapshot history, current findings, and episode-aware lifecycle projections with bounded keyset pagination and persisted-BOM revalidation.
- Environment-only control-plane database configuration with bounded connection-pool and lifecycle defaults, shared organization-ID validation, and a secret-free operational projection.
- Driver-neutral database bootstrap with bounded ping and migration contexts, deterministic lifecycle ordering, optional migration, fail-closed cleanup, and idempotent shutdown.
- Pinned pgx v5 PostgreSQL `database/sql` driver registration with lazy-handle construction and Go 1.26.10 minimum runtime alignment.
- Fail-closed PostgreSQL transport validation requiring certificate and hostname verification across primary and failover hosts, with an explicit observable development-only insecure override and secret-safe errors.
- Loopback-only HTTP runtime contract with bounded request lifecycle/header limits and deterministic graceful-shutdown orchestration over an injected listener.
- Constant-time opaque Bearer authentication for all control-plane API routes, public health isolation, RFC 6750 token-alphabet enforcement, strict header parsing, secret-free authenticator state, and OpenAPI security declaration.
- Environment-to-digest API-token configuration and fail-closed server composition that cannot construct the operational HTTP server without authentication and a Store reader.
- Deterministic control-plane process orchestration across PostgreSQL bootstrap, authenticated server construction, listener acquisition, serving, and ordered resource cleanup with joined failure preservation.
- Experimental `serve` CLI with environment-only configuration, secret-free no-I/O config inspection, interrupt/termination context cancellation, and default pgx/TCP process dependencies.
- Versioned secret-minimized HTTP request audit events, shared bounded envelope validation before delivery, synchronized JSONL stderr and PostgreSQL fan-out that attempts every destination, and fail-closed process wiring with server-generated correlation IDs, canonical routes, authentication outcomes, status, and latency.
- Bounded PostgreSQL audit retry with deterministic tenant-scoped event idempotency, capped exponential backoff, cancellation-aware shutdown, and an optional private bounded file spool replayed before serving; real single-event database-outage crash/recovery passed on 2026-11-02, while sustained and scale evidence remain open.
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
- Docker-backed upgrade from the immutable `v0.5.0-alpha` binary and schema version 2 to the current schema, preserving snapshot history and proving idempotent restart plus fail-closed downgrade/future-version handling.
- Bounded native fuzzing for credential JSON, RepositorySet JSON, OPA decision output, GitHub Actions, Kubernetes, MCP configuration, agent Markdown, GitHub Agentic Workflows, API pagination, query filters, route-specific query allowlists, and the shared audit envelope, with CI module-integrity and module-graph drift gates.
- Stable validated credential identity propagated from digest-only Bearer authentication into secret-minimized audit events and safe operational configuration, establishing the contract for multi-token rotation and future OIDC subjects.
- Bounded multi-credential registry with independent identity scopes, duplicate-ID/token rejection, all-digest authentication checks, mutually exclusive legacy configuration, and canonical secret-free operational projection.
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
- Operational GitHub App authentication with strict installation references, expiry-aware cache refresh, per-installation request coalescing, cancellation, RSA-2048+ validation, bounded RS256 JWTs, hardened token exchange, safe private-key files, secret-free config projection, explicit PAT/App routing, and fail-before-database RepositorySet wiring; deterministic expiry refresh and coalescing tests pass, as do real-provider exchange, cache reuse, private ingestion, unchanged-revision, and invalid-installation rejection, while provider-observed expiry-driven refresh remains pending.
- Secret-minimized GitHub authentication audit events for cache and provider outcomes, including bounded rate-limit/status/duration signals and fail-closed observer propagation.
- End-to-end GitHub connector composition across immutable revision resolution, unchanged short-circuiting, archive acquisition/materialization, production parser scanning, deterministic BOM metadata, and mandatory cleanup propagation.
- RepositorySet and process integration for GitHub repositories with connector-specific schema validation, allowlisted `OPSCUSTODIAN_GITHUB_TOKEN_*` environment references, arbitrary-environment exfiltration prevention, and shared local/GitHub orchestration.

The server can now be started explicitly, but remains restricted to loopback
and is not production-ready. Fine-grained authorization and rotation contracts
exist, while real PostgreSQL TLS/migration behavior and a fixed 30-minute
single-host reference profile have been validated in one disposable
environment. Provider parity, Kubernetes runtime enforcement, HA lease
contention, broader saturation behavior, recovery breadth, and final
platform/security gates remain incomplete.

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
