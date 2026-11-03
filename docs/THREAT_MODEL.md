# First-beta threat model

This document records the focused security review for the first OpsCustodian
beta boundary. The review was last updated on 2026-11-03 and covers tenant
isolation, credential lifecycle, policy failure modes, repository ingestion,
and audit integrity. It is a design and source review backed by the repository's
deterministic and disposable-environment tests; it is not a penetration test or
a claim that every deployment is secure.

The supported deployment assumptions are defined in the
[Beta support matrix](BETA_SUPPORT_MATRIX.md). In particular, the control plane
is a single Linux amd64 process bound to literal loopback, backed by the exact
PostgreSQL reference, and exposed remotely only through an operator-managed TLS
boundary. Kubernetes, HA, OIDC, public direct HTTP exposure, and arbitrary
provider integrations are outside this review's supported deployment claim.

## Protected assets

- API bearer values, GitHub credentials, private keys, and database secrets;
- repository content and the generated Agent BOM, Finding, and graph history;
- organization and repository authorization boundaries;
- policy inputs, decisions, and reviewed policy material;
- audit identity, ordering, retention, and durable pending events;
- service availability and the ability to fail closed without silent data loss.

## Trust boundaries and data flow

1. An operator supplies process configuration, credential files, policy files,
   and database trust material. A host administrator is trusted; an attacker
   with host, process, or database-superuser control is outside the beta model.
2. An API client crosses the loopback/TLS boundary, authenticates with one
   bounded bearer credential, and is authorized by scope and optional exact
   repository grants before reaching a handler.
3. Repository configuration and provider responses are untrusted. The
   ingestion scheduler applies concurrency and timeout bounds, materializes
   provider archives in an isolated temporary directory, scans them, and writes
   immutable snapshots within the configured organization.
4. Policy input crosses a process boundary to the reviewed local OPA binary.
   The decision is accepted only when it matches the bounded response contract.
5. Every handled request crosses the audit boundary. Secret-minimized events
   are validated, persisted within the organization, and optionally staged in
   a private bounded spool before acknowledgement.

## Security invariants

- Client input cannot choose the effective organization. One configured
  organization identity is bound into the server and every PostgreSQL query,
  write, retention operation, and audit query is scoped by it.
- Authentication failure is public-safe. Bearer values are length/character
  bounded, stored as SHA-256 digests for matching, compared across the complete
  active credential set in constant time, and never used as audit identity.
- Authorization is deny-by-default for an unknown route scope. Snapshot writes
  and policy evaluation require dedicated scopes; repository-restricted
  identities cannot read or write a repository outside their exact grants.
- Credential reload is atomic. A complete validated authentication and
  authorization snapshot replaces the prior snapshot together; invalid input
  preserves the last-known-good state and emits only a bounded outcome.
- Policy evaluation fails closed. Missing evaluators, execution failure,
  timeout, oversized input/output, and invalid decisions cannot become an
  allow decision.
- Ingestion cannot trust archive paths or file types. Compressed size,
  extracted size, entry count, repository count, per-file size, concurrency,
  retries, and repository duration are bounded; traversal, duplicate paths,
  symlinks, special files, redirects, and unsafe cleanup are rejected.
- Audit delivery cannot silently degrade. Events are schema/size bounded and
  secret-minimized; configured sink failure reaches the process failure path.
  PostgreSQL uniqueness is scoped by organization and event identity, while
  the private bounded spool supports crash-safe replay and acknowledgement.

## Threat review

| Threat | Existing controls | Residual beta risk and disposition |
| --- | --- | --- |
| Cross-organization read or write | Organization is process configuration rather than request input; store queries, retention, leases, snapshots, findings, and audit records bind `organization_id`; repository grants narrow a credential further | A database superuser can bypass application isolation, and a future unscoped SQL query could regress the invariant. Database administration is trusted; query isolation remains contract-tested and must be reviewed with every new store method |
| Credential guessing, replay, or leakage | Minimum/maximum bearer bounds, digest-only matching, constant-time comparison, generic rejection, unique IDs/digests, lifecycle windows, safe config projection, owner-only non-symlink credential files on Unix, and secret-free audit fields | Static bearer credentials remain replayable if stolen; the host environment and process memory contain secret material; OIDC and external secret-provider rotation are unsupported. Operators must use short-lived rotation windows, filesystem permissions, TLS, and separate credentials/scopes |
| Authorization bypass or confused deputy | Dedicated write/policy/audit scopes, exact repository grants, one authentication snapshot per request, route-specific checks, and public-safe `401`/`403` responses | There is no end-user identity federation or delegated user session. The beta is a service-credential control plane and must not be exposed as a multi-user identity provider |
| Policy bypass, tampering, or unsafe evaluator output | Dedicated evaluation scope, bounded strict input, process timeout/cancellation, private temporary input file, bounded output, validated decision schema, and `503` on unavailable/failed/invalid evaluation | Policy bundles and the OPA binary are trusted local operator inputs and are not signed or remotely attested. File replacement by a host administrator is outside the model; policy changes require reviewed deployment provenance |
| Malicious repository or provider response | Strict RepositorySet parsing, HTTPS and redirect restrictions, bounded responses, immutable revision validation, bounded ZIP extraction, traversal/symlink/special-file rejection, cancellation, scanner limits, and isolated cleanup | Parser defects and algorithmic complexity are still possible. Fuzzing and size limits reduce exposure but do not replace a parser audit; real-provider expiry, redirect, cancellation, and rate-limit evidence remains a release-candidate gate |
| Audit suppression, duplication, leakage, or tampering | Required sink/failure handler, bounded allowlisted attributes, tenant-scoped uniqueness, transactional persistence, retry classification, private spool with fsync/atomic publication, replay, and fail-closed process coordination | Audit storage is not cryptographically append-only or WORM. A database/host administrator can alter history, and storage exhaustion can stop the service. Operators must restrict database roles, monitor spool/database capacity, and export to an independently controlled backend where required |
| Resource exhaustion and availability loss | Loopback-only listener, request/response limits, pagination, bounded credentials/grants, ingestion concurrency/timeouts/retries, audit bounds, database timeouts, readiness degradation, and measured load/recovery behavior | The API has no built-in per-client rate limiter and the supported topology has one replica. TLS proxy rate limiting, host resource controls, and monitoring are operator responsibilities; availability is not a beta SLO |
| Dependency or supply-chain compromise | Pinned CI actions and container digests, checksums, SBOM/provenance, module-integrity, vulnerability, license, container, CodeQL, and fuzz workflows | Scanner databases and hosted services are point-in-time evidence; CodeQL upload enablement and exact-candidate hosted gates must still pass. A green scan is not proof of absence of vulnerabilities |

## Review outcome

The focused review did not identify a confirmed critical or high-severity defect
inside the declared first-beta boundary. It did identify material residual
risks that are accepted only because the beta promise is narrow: static bearer
replay, operator-controlled policy integrity, non-cryptographic audit history,
no built-in request rate limiter, and single-replica availability.

Those residuals must not be hidden by release messaging. A change that adds
remote direct exposure, multi-organization request routing, OIDC, a new hosted
provider, multi-replica operation, or a general-purpose server image changes
the trust model and requires this review to be repeated before support is
claimed.

## Required release evidence

The threat model is necessary but not sufficient for release. The exact
candidate must still satisfy [Security testing](SECURITY_TESTING.md), the
[Beta release checklist](BETA_RELEASE_CHECKLIST.md), hosted platform gates,
provider failure-mode evidence, artifact inspection, and the independent-user
Quick Start review. Newly discovered high or critical defects reopen this
review and block the beta candidate.
