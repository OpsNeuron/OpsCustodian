# Roadmap

The roadmap is outcome-based. Dates will be assigned only after the foundation
is reviewed and implementation capacity is known.

## Current delivery focus — alpha adoption

Before expanding organization-server or HA scope, OpsCustodian prioritizes a
short, reproducible first-user journey: build one binary, scan an offline demo,
open one self-contained report, and observe one explainable critical drift.
Documentation, representative fixtures, release packaging, and final
integration evidence take precedence over new distributed-system features.

The two-replica deployment remains an explicitly experimental artifact. The
default deployment stays single-replica until product adoption demonstrates a
need for HA and the Docker Desktop failure-injection plan has been executed.

## Release maturity gates

Release maturity is evidence-based rather than date-based. A version number or
elapsed development time alone does not promote the project to the next stage.

### Alpha — validate the product and contracts

The public alpha is suitable for evaluation, offline repository scans, CI
experiments, and feedback. Consumers must pin the executable and generated data
contracts because compatible additions and explicitly versioned breaking
changes may still occur.

Alpha continues until all of the following are true:

- independent users have completed the documented Quick Start and reported
  actionable installation, inventory, drift, or policy feedback;
- representative repositories exercise GitHub Actions, MCP, agent Markdown,
  Kubernetes, ownership, and policy paths with bounded false positives;
- public Agent BOM, finding, policy, and API contracts have a documented
  migration path and no known imminent redesign;
- real GitHub, OPA, PostgreSQL, OpenTelemetry, and Kubernetes compatibility
  gates pass on the supported configurations; and
- no known critical or high-severity defect compromises evidence integrity,
  tenant isolation, credential handling, or fail-closed enforcement.

### Beta — stabilize operations and upgrades

The first beta may be cut only after the alpha gate passes. Beta freezes the
core semantic contracts except for versioned migrations and focuses on upgrade,
rollback, performance, recovery, and multi-repository operational evidence.
Beta does not imply production HA unless the separate HA test plan passes.
The executable evidence gate for the first beta is maintained in the
[Beta release readiness checklist](BETA_RELEASE_CHECKLIST.md).

Beta exits when:

- at least two consecutive releases preserve compatibility or provide tested
  migrations;
- fresh installation, upgrade, rollback, backup, restore, and failure-recovery
  paths pass in the supported environment matrix;
- security review, fuzzing, dependency review, and published performance
  envelopes have no unresolved release blocker; and
- external adopters have operated the supported deployment and its runbooks
  without an unresolved data-integrity or access-control failure.

### Stable — organization-ready support promise

`v1.0.0` begins the documented compatibility and support window. It requires
the organization-control-plane, hardening, migration, operational-runbook, and
release-signing gates below. Experimental features remain explicitly excluded
from the stable support promise until they pass their own exit gates.

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

- OPA/Rego policy adapter and open starter policy pack. *(implemented with current-state finding gates, deterministic Rego tests, authenticated server runtime wiring, and Docker-backed validation)*
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

- Offline GitHub Actions current-state findings. *(privileged triggers, untrusted data flow, self-hosted runners, mutable dependencies, OIDC issuance, deployment environments, and unknown protection state implemented)*
- Stable remediation vocabulary. *(namespace-qualified remediation IDs and catalog implemented; auto-fix intentionally deferred)*

- Kubernetes workload and ServiceAccount correlation. *(initial offline parser and runs-as graph implemented, pending validation)*
- Kubernetes RBAC role/binding correlation. *(initial offline parser and graph implemented, pending validation)*
- Effective RBAC grant propagation to identities and workloads. *(implemented offline, pending validation)*
- Kubernetes ServiceAccount token exposure analysis. *(automount precedence and structured findings implemented, pending final environment validation)*
- Kubernetes RBAC privilege-escalation analysis. *(wildcard/special-verb detection and structured findings implemented, pending final environment validation)*
- Projected ServiceAccount token analysis. *(mounted audience, expiration, and structured risk findings implemented, pending final environment validation)*
- Declared-versus-effective Kubernetes access. *(structured inherited-access summaries implemented, pending validation)*
- Provider-neutral effective access paths. *(Kubernetes RBAC path producer and validation contract implemented, pending validation)*
- Local effective-access path explorer. *(self-contained HTML rendering and filters implemented, pending browser validation)*
- Binding-aware Kubernetes RBAC scope. *(resource names and non-resource URL semantics implemented, pending validation)*
- Aggregated Kubernetes ClusterRoles. *(selector matching and fixed-point composition implemented, pending validation)*
- Aggregated ClusterRole cycle analysis. *(canonical bounded cycle paths implemented, pending validation)*
- Effective-access unit tests. *(initial Kubernetes RBAC, token, aggregation, and cycle coverage implemented, pending validation)*
- Kubernetes parser unit tests. *(workload, token, RBAC, aggregation, and error-contract coverage implemented, pending validation)*
- Agent BOM contract tests. *(access-path validation, normalization, deduplication, and evidence retention implemented, pending validation)*
- Current-state Finding identity and lifecycle semantics. *(stable IDs and deterministic deduplication implemented; persistent observation history belongs to the server phase)*
- HTML reporter tests. *(self-contained output, escaping, filter, encoding, and escalation coverage implemented, pending validation)*
- Scanner integration test. *(temporary-repository full-pipeline invariants and deterministic repeat scan implemented, pending validation)*
- Risk calibration tests. *(capability, escalation, credential, control, relationship, and asset scoring implemented, pending validation)*
- Optional GitHub API enrichment. *(revision discovery, credential resolution, controlled archive acquisition, hardened scanning, RepositorySet/process integration, operational PAT/GitHub App authentication, deterministic expiry-refresh/coalescing coverage, and selected real-provider validation implemented; PAT parity, provider-observed expiry refresh, rate-limit, redirect, and broader compatibility validation remain pending)*
- Local GitHub reusable-workflow composition and delegation access paths. *(implemented offline with permission ceilings, secret propagation, and bounded cycle analysis)*
- Declared-versus-effective access findings. *(versioned contract, initial Kubernetes producer, terminal/JSON/SARIF/HTML consumers, and CI threshold implemented)*
- OpenTelemetry audit events. *(versioned offline JSONL event envelope, CLI conversion, and guarded OTLP/HTTP JSON exporter implemented)*
- Provenance and pinning checks for MCP servers. *(offline classification, semantic drift, and structured current-state findings implemented)*

Exit condition: repository declarations can be compared with at least one real
runtime authorization system.

## v0.5 — Organization control plane

- Persistence-neutral snapshot reader/writer boundary. *(initial interface and memory implementation complete)*
- Versioned repository, finding, and snapshot ingestion API. *(authenticated loopback runtime and tested handlers implemented)*
- Keyset pagination, repository snapshot history, and OpenAPI contract. *(implemented in the read-only handler)*
- Cross-snapshot Finding lifecycle projection and filtering. *(episode-aware in-memory and PostgreSQL query implementations complete; real database validation pending)*
- Historical semantic drift API. *(repository-authorized comparison of immutable stored snapshots implemented with OpenAPI, unit, and PostgreSQL-backed integration coverage)*
- Organization relationship graph API. *(latest repository subgraphs, authorization filtering, bounded pagination, OpenAPI, and PostgreSQL-backed integration coverage implemented)*
- Organization graph query filters. *(exact repository and graph-content matching with complete-subgraph results and filter-bound cursors implemented)*
- Persistent audit history. *(tenant-scoped PostgreSQL retention, fail-closed process wiring, repository authorization, bounded filters, pagination, and OpenAPI query contract implemented)*
- Audit retention policy. *(bounded configurable lifetime, startup/periodic tenant-scoped pruning, safe config visibility, and fail-closed runtime coordination implemented)*
- Snapshot retention policy. *(server-time age, per-repository minimum history, latest-snapshot preservation, bounded tenant-scoped deletion, and fail-closed runtime coordination implemented)*
- PostgreSQL logical backup and restore. *(documented custom-format procedure and isolated Docker source/destination verification re-run successfully on 2026-10-08; physical backup, PITR, scale, and RPO/RTO remain open)*
- Database upgrade compatibility. *(`v0.5.0-alpha` schema 2 through schema 4 was re-verified on 2026-11-01 with snapshot preservation, legacy audit identity backfill, durable spool replay/removal, idempotent restart, and fail-closed version-skew checks; mixed-version, skip-version, and scale gates remain open)*
- Security fuzz gates. *(credential, ingestion, policy, GitHub Actions, Kubernetes, MCP, agent Markdown, GitHub Agentic Workflows, API pagination, query-filter, route-allowlist, and audit-envelope boundaries plus module-integrity checks implemented; manual two-minute-per-boundary release-candidate workflow implemented, while a passing hosted campaign remains required)*
- Reachable Go vulnerability gate. *(pinned scanner, pull-request and main-branch enforcement, weekly advisory refresh, and local reproduction implemented)*
- Final container vulnerability gate. *(digest-pinned base images, checksum-verified Grype 0.119.0, high/critical pull-request enforcement, weekly database refresh, and Docker reproduction implemented)*
- Go dependency-license gate. *(explicit permissive allowlist, test dependency coverage, pinned go-licenses 2.0.1, pull-request enforcement, and retained CSV evidence implemented; non-Go and legal review remain open)*
- CodeQL static-analysis gate. *(SHA-pinned v4 analysis for Go and GitHub Actions with security-extended queries, least-privilege SARIF upload, scheduled refresh, and contract enforcement implemented; organization-level advanced-setup enablement and a passing hosted upload remain pending)*
- PostgreSQL persistence and migrations. *(initial tenant-aware schema and guarded embedded migration runner implemented; Docker-backed PostgreSQL validation passed on 2026-10-08)*
- PostgreSQL snapshot reader/writer. *(tenant-scoped, transactional, and driver-neutral implementations complete; Docker-backed persistence and authorized API reads passed on 2026-10-08)*
- Bounded environment-based database and tenant configuration. *(implemented without activating a driver or network listener)*
- Database bootstrap and lifecycle orchestration. *(driver-neutral ordering and cleanup implemented; Docker-backed startup, readiness, restart, and cleanup validation passed on 2026-10-08)*
- Official pgx PostgreSQL driver wiring. *(pinned and registered; live connection and compatibility matrix deferred to final integration)*
- PostgreSQL transport-security guard. *(verified TLS enforced across effective pgx primary/fallback configuration; certificate-chain integration deferred)*
- Multi-repository ingestion and historical Finding lifecycle. *(endpoint, immutable persistence, orchestration/scheduler, connector registry, local and GitHub connectors, RepositorySet loader, process wiring, and audit summary implemented; real-provider validation pending)*
- Authentication, authorization, tenant isolation, pagination, and audit middleware.
- Safe loopback-first server command and operational configuration. *(experimental authenticated `serve` and secret-free `--print-config` implemented)*
- Secure HTTP runtime primitives. *(loopback validation, bounded server configuration, and graceful shutdown implemented; CLI listener remains gated on authentication design)*
- Initial API authentication boundary. *(opaque Bearer digest verification and OpenAPI contract implemented; rotation and OIDC pending)*
- Initial API authorization boundary. *(granular read scopes, isolated `snapshots:write`, explicit `control-plane:admin`, fail-closed environment configuration, repository-scoped credential grants, `403` response, OpenAPI declarations, and audit outcome implemented)*
- Stable credential identity. *(validated non-secret token identity and audit propagation implemented)*
- Multi-credential rotation registry. *(bounded environment registry, independent identity grants, ambiguity rejection, and safe projection implemented; external secret-provider reload pending)*
- Credential lifecycle policy. *(disablement, activation, expiration, overlap semantics, and deterministic clock-backed tests implemented; external reload triggers pending)*
- Atomic credential reload core. *(validated snapshot publication, in-flight request pinning, and last-known-good rollback semantics implemented; automatic watcher and external secret-provider integrations pending)*
- Credential file source. *(bounded strict parsing, file-type and Unix permission checks, identity verification, and safe reload implemented)*
- Credential reload trigger. *(bounded cancellable polling, immediate load, recovery after invalid updates, and result observation implemented)*
- Operational credential reload wiring. *(environment configuration, process lifecycle, minimized audit events, and fail-closed audit handling implemented; real secret rotation validation deferred)*
- Authenticated control-plane composition. *(environment token derivation and mandatory authenticated handler wiring implemented)*
- Control-plane process lifecycle. *(startup/resource ownership, signal-aware CLI wiring, and failure cleanup implemented; live integration pending)*
- Request audit pipeline. *(shared bounded OTel-compatible envelope validation, deterministic event identity, synchronized JSONL stderr plus tenant-scoped PostgreSQL persistence, all-destination fan-out, bounded retry, optional durable file-spool recovery, fail-closed process shutdown, bounded outcomes, and retention implemented; external backend delivery remains open)*

Exit condition: a platform team can query reproducible inventory and Finding
history across multiple repositories through an authenticated control plane.

## v1.0 — Organization ready

- Stable Agent BOM and policy input contracts.
- Golden compatibility tests for Agent BOM, finding, SARIF, and policy decision output. *(implemented)*
- Central contract registry and compatibility rules. *(implemented for v1alpha1; stable-version support windows remain pre-1.0 work)*
- Multi-repository server mode with PostgreSQL.
- REST API and Backstage integration.
- Signed baselines and governed exceptions.
- Retention, upgrade, migration, and compatibility policies.
- Security review and performance benchmarks. *(bounded read-only, mixed
  read/write, and 32-worker immutable snapshot-contention Docker evidence
  implemented; a rate-limited latency/resource probe is reproducible and a
  default five-minute Docker profile passed, while sustained
  reference-environment load, saturation, and capacity envelopes remain open;
  hard PostgreSQL failure under active load and clean replay/recovery passed,
  while slow and partial dependency failures remain open)*
- Hardened release pipeline. *(SHA-pinned least-privilege CI, Linux race plus Windows and macOS compatibility jobs, cross-platform archives, checksums, CycloneDX SBOM, provenance, main-line tag validation, exact-commit extended-fuzz evidence enforcement, and Apache-2.0 license implemented; tagged workflow and independent Windows consumer verification passed, while the new evidence gates and hosted macOS path require hosted validation)*

Exit condition: the project can be operated as a dependable organization-wide
control plane while preserving the offline CLI workflow.

## Explicitly outside the early roadmap

- Proprietary policy language.
- General secret, vulnerability, or prompt-injection scanning.
- Agent runtime, model gateway, or model evaluation platform.
- Broad cloud entitlement management unrelated to agents.
- Managed commercial service before open-source product fit is demonstrated.
