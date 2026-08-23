# Control-plane server

The v0.5 server foundation separates HTTP APIs from persistence. The HTTP layer
depends on a `store.Reader` for queries and an optional `store.Writer` for
snapshot ingestion. The thread-safe memory store and PostgreSQL implement both.

## Current API

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
| `POST` | `/api/v1/snapshots` | Validate and persist an immutable Agent BOM snapshot |

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
A Go conformance test ensures every implemented route remains
documented under the same API contract version.

Snapshot ingestion requires `Content-Type: application/json`, accepts exactly
one strict Agent BOM JSON document, and limits request bodies to 10 MiB. Contract
violations return `422`; reusing a repository revision with different immutable
content returns `409`. Successful writes return only deterministic repository
and snapshot IDs plus bounded summary counts, not the submitted BOM.

## Persistence boundary

The store distinguishes read and write capabilities:

- `Reader` lists repositories, retrieves the latest snapshot, and queries
  findings.
- `Writer` ingests a validated Agent BOM snapshot.

Read handlers depend only on `Reader`; snapshot ingestion is enabled only when
the supplied store also implements `Writer`. The memory implementation keeps
multiple immutable revisions, makes defensive copies, honors request
cancellation, and can be replaced without changing the API layer.

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
current `/api/*` operation requires an explicit scope. `contracts:read`,
`inventory:read`, and `findings:read` constrain access by API family, while
`control-plane:read` grants all current read operations. Snapshot ingestion
requires `snapshots:write`; it is deliberately not implied by
`control-plane:read`. `control-plane:admin` explicitly grants all operations. An authenticated token
without the required permission receives a public-safe `403`.
Per-repository roles, token rotation, and OIDC identity are not implemented yet.
The unauthenticated constructor remains available only for isolated tests and
must not be connected to a listener. The runtime still cannot bind outside
loopback.

`OPSCUSTODIAN_API_TOKEN` is required by control-plane configuration and must
contain 32 to 4096 non-whitespace bytes. It is read from the process environment
and immediately converted into the authenticator's digest-only representation.
`OPSCUSTODIAN_API_TOKEN_ID` is a required non-secret stable identifier containing
3 to 63 lowercase letters, digits, or hyphens. Successful requests carry this
identity into audit records without exposing the token or its digest.
In single-token mode, `OPSCUSTODIAN_API_SCOPES` is also required and accepts a comma-separated set of
the documented scopes. Unknown scopes fail configuration rather than granting
future permissions accidentally. The safe configuration projection reports
authentication state, credential ID, and the non-secret authorization scope list.

For rotation and distinct service identities, `OPSCUSTODIAN_API_CREDENTIALS`
accepts a JSON array of `{id, token, scopes}` objects. It supports 1 to 100
credentials, rejects duplicate IDs and duplicate token digests, and assigns
scopes independently per identity. Registry mode is mutually exclusive with
the three single-token variables. Authentication examines every configured
digest before deciding the match, and safe configuration exposes only IDs.
Each registry entry may set `disabled`, `notBefore`, and `expiresAt`.
Timestamps must be RFC3339 and expiration must follow activation. The validity
window is start-inclusive and expiration-exclusive, enabling a bounded overlap
where old and new rotation credentials are both accepted. Disabled, future,
expired, unknown, and malformed credentials all receive the same public-safe
`401` response.

Credential configuration is held by an in-process atomic registry. A validated
reload publishes authentication digests and authorization grants together;
invalid reloads leave the last good snapshot active. Each request pins one
snapshot during authentication, so a concurrent rotation cannot combine an old
identity with new grants. Environment configuration creates this registry at
startup. Filesystem watching and external secret-provider adapters remain
future operational integrations.

The filesystem adapter `ReloadCredentialFile` provides the hardened boundary
for those integrations. It accepts only regular non-symlink files, limits input
to 1 MiB, rejects unknown JSON fields and trailing values, and on Unix requires
owner-only permissions. It verifies that the inspected and opened file refer to
the same object before parsing. A read, parse, permission, or validation failure
does not replace the active registry snapshot. Automatic polling or signal
wiring is intentionally not enabled yet.

The cancellable polling trigger `WatchCredentialFile` performs an immediate
load and retries at a bounded interval from 1 second to 1 hour. Every attempt
produces a structured result callback suitable for audit and metrics. A failed
attempt is observable but does not terminate the watcher or replace the active
snapshot; later corrected files can recover automatically. Context cancellation
stops polling cleanly.

`serve` now activates this watcher when
`OPSCUSTODIAN_API_CREDENTIAL_FILE` contains an absolute path. Bootstrap
credentials still come from the environment, preserving a last-known-good
identity set before the first file attempt. The optional
`OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL` defaults to 30 seconds and is
bounded from 1 second to 1 hour. Safe configuration exposes only whether a file
is configured and its interval, never its path. Each attempt emits a minimized
credential reload audit event; an audit sink failure remains process-fatal.

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
| `OPSCUSTODIAN_REPOSITORY_SET_FILE` | unset | clean absolute path to a strict versioned RepositorySet JSON file |
| `OPSCUSTODIAN_GITHUB_APP_ID` | unset | positive integer; requires the private-key file setting |
| `OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE` | unset | clean absolute path; requires the App ID setting |

Unit tests verify both loopback families, rejection of exposure-prone binds,
timeout/header bounds, cancellation, shutdown, and error propagation without
opening a real socket.

## Process lifecycle

The control-plane process orchestrator now owns startup and cleanup order:

1. validate configuration and process dependencies;
2. load and validate the optional RepositorySet before external I/O;
3. initialize required GitHub credential providers from bounded runtime references;
4. bootstrap PostgreSQL and optionally apply migrations;
5. construct the authenticated HTTP server;
6. acquire the loopback listener;
7. run HTTP, optional credential reload, and optional ingestion scheduling under one cancellation scope;
8. stop on serving, watcher, scheduler, or audit failure;
9. close the listener and database exactly once.

Scheduled ingestion emits one bounded audit summary containing outcome,
duration, and status counts. Repository paths, connector errors, BOM content,
and credentials are excluded. An ingestion audit failure stops the scheduler
and process rather than continuing unaudited.

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

Snapshot-ingestion request events add a bounded result (`persisted`, `conflict`,
`rejected`, `failed`, or `unavailable`). Only after contract validation may an
event include deterministic repository/snapshot IDs and revision; successful
writes also include asset and Finding counts. Rejected untrusted metadata is
never copied from the request into audit attributes.

Public health, rejected authentication, successful API requests, and API errors
are distinguished without exposing credential material. The middleware requires
an explicit sink. The `serve` composition installs a thread-safe JSONL sink on
standard error. A sink write failure triggers process cancellation, graceful
HTTP shutdown, listener cleanup, and database close; the server does not
continue in an unaudited state. Long-term retention and rotation still belong
to the service supervisor or a future durable exporter.
