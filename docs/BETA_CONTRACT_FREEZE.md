# First-beta contract freeze

This document is the reviewed inventory and change policy for machine-readable
OpsCustodian interfaces in the first beta. It freezes meaning, identity, and
compatibility expectations; it does not turn every experimental runtime into a
supported deployment. Operational support remains defined by the
[Beta support matrix](BETA_SUPPORT_MATRIX.md).

The executable source of truth is `internal/contracts.BuildInfo`. Operators and
integrations can query the same registry with:

```bash
opscustodian version --format json
```

## Frozen contract inventory

| Interface | Version | Authoritative artifacts | Beta rule |
| --- | --- | --- | --- |
| Agent BOM | `opscustodian.dev/v1alpha1` | `schemas/agentbom-v1alpha1.schema.json`, model validation, JSON golden | Existing field types, meanings, evidence identity, and required fields are frozen |
| Normalization semantics | `v1alpha1` | normalization code, drift/risk tests | Any change that can alter canonical identity, Finding identity, scope, or effect requires a new normalization version |
| Findings envelope | `opscustodian.dev/findings/v1alpha1` | JSON/SARIF goldens and finding documentation | Finding/remediation identity and severity meaning are frozen |
| Policy input | `opscustodian.dev/policy-input/v1alpha1` | server validation, OPA fixtures, OpenAPI | Request shape is strict; incompatible or newly required input needs a new version |
| Policy decision schema | `v1alpha1` | `schemas/policy-decision-v1alpha1.schema.json`, policy validation, JSON golden | `deny`/`warn` and message meaning are frozen; the payload intentionally has no embedded `apiVersion` and is versioned by this registry/schema |
| Audit event | `opscustodian.dev/audit-event/v1alpha1` | audit validator, OTLP mapping, JSONL tests | Event identity, bounded attributes, secret-minimization, and retry/idempotency meaning are frozen |
| Control-plane HTTP API | `opscustodian.dev/control-plane/v1alpha1` | `api/openapi.yaml`, handler and OpenAPI tests | Existing route methods, authorization requirements, pagination binding, response fields, and error meaning are frozen |
| RepositorySet | `opscustodian.dev/ingestion/v1alpha1` | `schemas/repository-set-v1alpha1.schema.json`, strict loader/fuzz tests | Configuration input is strict; incompatible or newly required fields need a new version |
| Preflight report | `opscustodian.dev/preflight/v1alpha1` | `doctor` terminal/JSON tests and documentation | Check IDs, required status meaning, readiness aggregation, and secret-free output are frozen |
| SARIF | `2.1.0` | SARIF golden and schema URI | Valid SARIF 2.1.0, stable fingerprints, locations, and rule identity are frozen |

Human terminal formatting and HTML visual styling are not byte-stable API
contracts, but they must remain safe, self-contained where documented, and
semantically consistent with the machine-readable result. CLI exit codes,
command names, and required flags remain compatibility surfaces even though
they are not data schemas.

## Database contract

The first beta database catalog contains migrations 1 through 4:

1. `control_plane`;
2. `scheduler_leases`;
3. `audit_history`;
4. `audit_idempotency`.

Published migration names, versions, SQL, and checksums are immutable. Schema
changes require a new forward migration, transactional application, updated
upgrade/restore evidence, and release notes. Deleting ledger rows, editing a
published migration, in-place downgrade, mixed-version rollout, and
skip-version upgrade are not supported.

## Compatible changes during beta

A change is compatible only when all existing valid inputs retain their
meaning, existing clients can consume the result under their documented reader
rules, stable identifiers do not change, and deterministic/golden tests remain
valid. Examples include a new optional response field proven safe for tolerant
readers, a new diagnostic code, or a new parser that produces existing model
types without changing normalization.

Strict request/configuration decoders do not tolerate unknown fields. Adding a
new required field, changing a field type or meaning, removing or renaming a
field, reusing a remediation ID, changing pagination cursor scope, weakening an
authorization requirement, or changing identity/normalization semantics is
breaking and requires a new contract or normalization version.

## Required change procedure

Every intentional contract change must include, in one reviewed change:

1. a compatibility classification and affected interface list;
2. a new version when the change is breaking under the rules above;
3. updated schema or OpenAPI artifacts and centralized registry values;
4. deterministic validator, parser, authorization, migration, and golden tests;
5. migration and rollback guidance where persisted or operator input changes;
6. release notes naming the compatibility effect and supported source version;
7. updated support matrix, threat model, and runbook evidence when the trust or
   deployment boundary changes.

Golden files have no automatic update switch. A reviewer must inspect the exact
machine-readable diff rather than accepting regenerated output blindly.

## Explicitly not frozen as supported beta runtime

The experimental HA overlay, Kubernetes distribution, OIDC, GitHub PAT,
non-GitHub providers, general-purpose server container, physical backup/PITR,
and direct non-loopback HTTP exposure are not supported by this freeze. Their
source may evolve, but they cannot alter a frozen supported contract or be
advertised as beta-supported without completing their own compatibility,
security, migration, and environment-backed evidence gates.

## Review outcome

The review found no known imminent redesign inside the declared supported
first-beta interfaces. The registry omission for RepositorySet, preflight, and
the policy-decision schema revision was corrected additively before the freeze.
Future changes are governed by this document and the public contract tests.
