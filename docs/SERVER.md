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

The authenticated constructor protects every `/api/*` route with an opaque
Bearer token while leaving only `/healthz` public. Tokens must contain 32 to
4096 bytes without whitespace, are immediately reduced to a SHA-256 digest,
and are checked using constant-time comparison. Missing, ambiguous, duplicated,
or invalid authorization headers receive a versioned public-safe `401` response.
The raw token is neither retained by the authenticator nor serializable.

Authentication and authorization are separate middleware boundaries. Every
current `/api/*` operation requires an explicit read scope. `contracts:read`,
`inventory:read`, and `findings:read` constrain access by API family, while
`control-plane:read` grants all current read operations. An authenticated token
without the required permission receives a public-safe `403`.
Per-repository roles, token rotation, and OIDC identity are not implemented yet.
The unauthenticated constructor remains available only for isolated tests and
must not be connected to a listener. The runtime still cannot bind outside
loopback.

`OPSCUSTODIAN_API_TOKEN` is required by control-plane configuration and must
contain 32 to 4096 non-whitespace bytes. It is read from the process environment
and immediately converted into the authenticator's digest-only representation.
`OPSCUSTODIAN_API_SCOPES` is also required and accepts a comma-separated set of
the documented scopes. Unknown scopes fail configuration rather than granting
future permissions accidentally. The safe configuration projection reports
authentication state and the non-secret authorization scope list.

The production composition constructor validates the complete configuration,
requires a Store `Reader`, installs the authenticated API handler, and only then
constructs the bounded HTTP server. This keeps the unauthenticated test
constructor outside the operational wiring path.

## HTTP runtime guardrails

The server runtime accepts only literal IPv4 or IPv6 loopback addresses;
wildcard, external, and hostname binds fail validation even though initial
authentication now exists. Non-loopback operation remains gated on
authorization, transport, proxy-trust, and audit design.
The constructor configures bounded header-read, request-read, response-write,
idle, and header-size limits. Serving uses an injected listener and performs a
timeout-bounded graceful shutdown when its context is cancelled.

| Variable | Default | Constraint |
| --- | --- | --- |
| `OPSCUSTODIAN_HTTP_LISTEN_ADDRESS` | `127.0.0.1:8080` | literal loopback IP and port 1–65535 |
| `OPSCUSTODIAN_HTTP_READ_HEADER_TIMEOUT` | `5s` | positive, at most 5 minutes |
| `OPSCUSTODIAN_HTTP_READ_TIMEOUT` | `15s` | bounded and not shorter than header timeout |
| `OPSCUSTODIAN_HTTP_WRITE_TIMEOUT` | `30s` | positive, at most 5 minutes |
| `OPSCUSTODIAN_HTTP_IDLE_TIMEOUT` | `60s` | positive, at most 5 minutes |
| `OPSCUSTODIAN_HTTP_MAX_HEADER_BYTES` | `65536` | 8192 to 1048576 bytes |

Unit tests verify both loopback families, rejection of exposure-prone binds,
timeout/header bounds, cancellation, shutdown, and error propagation without
opening a real socket.

## Process lifecycle

The control-plane process orchestrator now owns startup and cleanup order:

1. validate configuration and bootstrap PostgreSQL;
2. construct the authenticated HTTP server;
3. acquire the loopback listener;
4. serve until the caller's context is cancelled or serving fails;
5. close the listener; and
6. close the database exactly once.

Listener and serving functions are injected for deterministic tests. Failures
before listener creation cannot leak a database handle, failures while serving
still close both resources, and simultaneous serve/close failures are retained
as a joined error. Default dependencies register pgx and real TCP behavior but
do not perform I/O until the process runner is explicitly invoked. The CLI
converts OS interrupt and termination signals into process-context cancellation.

## CLI command

`opscustodian serve` loads the complete environment configuration, constructs
the default pgx/TCP dependencies, and runs the authenticated process lifecycle.
The CLI root context is cancelled on interrupt or termination signals, which
initiates graceful HTTP shutdown followed by database close.

`opscustodian serve --print-config` performs full validation and prints only
the safe configuration projection. It does not construct dependencies, connect
to PostgreSQL, or open a listener. Database DSNs, passwords, API tokens, and
token digests are never included in its output.

The regular `serve` path now opens a real loopback listener and requires a real
PostgreSQL connection. It remains experimental until the deferred database,
signal, platform, and security integration suite is complete.

## Request audit middleware

The authenticated API has a request-audit middleware contract that emits the
shared OpenTelemetry-compatible OpsCustodian audit envelope. It records a
server-generated request ID, canonical route pattern, status, duration,
organization, method, authentication result, and authorization result. Raw URL/query values, headers,
tokens, bodies, and remote addresses are excluded by construction.

Public health, rejected authentication, successful API requests, and API errors
are distinguished without exposing credential material. The middleware requires
an explicit sink. The `serve` composition installs a thread-safe JSONL sink on
standard error. A sink write failure triggers process cancellation, graceful
HTTP shutdown, listener cleanup, and database close; the server does not
continue in an unaudited state. Long-term retention and rotation still belong
to the service supervisor or a future durable exporter.
