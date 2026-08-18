# Read-only control-plane server

The v0.5 server foundation separates HTTP APIs from persistence. The HTTP layer
depends only on a `store.Reader`; the initial thread-safe memory store implements
the same boundary intended for PostgreSQL.

## Current read-only API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Process health |
| `GET` | `/api/v1/contracts` | Build and supported contract discovery |
| `GET` | `/api/v1/repositories` | Deterministic repository summaries |
| `GET` | `/api/v1/repositories/{repositoryId}/bom` | Latest repository snapshot |
| `GET` | `/api/v1/repositories/{repositoryId}/snapshots` | Repository snapshot history |
| `GET` | `/api/v1/repositories/{repositoryId}/snapshots/{snapshotId}/bom` | One immutable snapshot |
| `GET` | `/api/v1/findings` | Findings across latest repository snapshots |
| `GET` | `/api/v1/finding-lifecycles` | Current lifecycle episode for each Finding |

The findings endpoint accepts exact `repositoryId` and `severity` filters.
Collection endpoints use keyset pagination with `limit` (default 50, maximum
200) and an opaque versioned `cursor`. All API envelopes use
`opscustodian.dev/control-plane/v1alpha1`. Collection responses emit explicit
empty arrays. Repository and snapshot IDs are deterministic hash-derived
identifiers rather than raw filesystem paths or revisions.

Finding lifecycle queries accept `repositoryId`, `severity`, and `status`
filters. `introduced` means the Finding first appears in its current episode,
`persisting` means it remains across consecutive ingested snapshots, and
`resolved` means a later snapshot no longer contains it. Reintroduction starts
a new episode. Observation timestamps are copied only from snapshot
`generatedAt`; missing source timestamps remain absent.

The OpenAPI 3.1 source of truth is [`api/openapi.yaml`](../api/openapi.yaml).
A Go conformance test ensures every implemented read-only route remains
documented under the same API contract version.

## Persistence boundary

The store distinguishes read and write capabilities:

- `Reader` lists repositories, retrieves the latest snapshot, and queries
  findings.
- `Writer` ingests a validated Agent BOM snapshot.

HTTP handlers receive only `Reader`. There are no mutation endpoints. The
memory implementation keeps multiple revisions, makes defensive copies, honors
request cancellation, and can be replaced without changing the API layer.

## Security status

The handler sets `no-store`, `nosniff`, frame denial, and a restrictive Content
Security Policy. It returns bounded public error messages rather than internal
store errors.

Authentication, authorization, tenant isolation, request-body/server limits,
and audit middleware are not implemented yet. Consequently this handler is not
connected to a CLI listener and must not be exposed to a network. A future
`serve` command will default to loopback and will not support non-loopback binds
until the authentication boundary is explicit.
