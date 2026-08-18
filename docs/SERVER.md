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
| `GET` | `/api/v1/findings` | Findings across latest repository snapshots |

The findings endpoint accepts exact `repositoryId` and `severity` filters. All
API envelopes use `opscustodian.dev/control-plane/v1alpha1`. Collection
responses emit explicit empty arrays, and repository IDs are deterministic
hash-derived identifiers rather than raw filesystem paths.

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

Authentication, authorization, tenant isolation, pagination, request limits,
and audit middleware are not implemented yet. Consequently this handler is not
connected to a CLI listener and must not be exposed to a network. A future
`serve` command will default to loopback and will not support non-loopback binds
until the authentication boundary is explicit.
