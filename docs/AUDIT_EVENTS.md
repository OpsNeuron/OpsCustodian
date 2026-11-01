# OpenTelemetry-compatible audit events

OpsCustodian converts scan and semantic-drift results into versioned JSON Lines
events without making network connections. The initial contract is:

```text
opscustodian.dev/audit-event/v1alpha1
```

The envelope follows the OpenTelemetry LogRecord event model with `timestamp`,
`eventName`, `severityNumber`, a string display `body`, `resource`,
`instrumentationScope`, and flat `attributes`. It is intentionally not an OTLP
wire representation. A Collector file receiver, custom adapter, or future
exporter can map the envelope to OTLP.

The shared runtime validator rejects empty or control-character field names,
nested objects and arrays, non-finite numbers, missing resource/scope identity,
and envelopes larger than 64 KiB. Multi-destination delivery gives every sink
an isolated copy so a backend cannot mutate the event observed by another.

## Event names

- `opscustodian.scan.completed`: one inventory summary per BOM.
- `opscustodian.diagnostic.reported`: one structured parser/composition
  diagnostic occurrence.
- `opscustodian.finding.detected`: one minimized current-state security finding.
- `opscustodian.drift.detected`: one event per semantic finding.
- `opscustodian.diff.completed`: one severity-count summary per drift report.
- `opscustodian.http.request.completed`: one minimized control-plane request
  observation emitted by the server audit middleware.
- `opscustodian.credential.reload.completed`: one secret-free success or failure
  outcome for an operational credential-file reload attempt.
- `opscustodian.github.authentication.completed`: one bounded GitHub App cache
  or token-exchange outcome.

Event names contain no asset IDs, revisions, finding IDs, or other dynamic
values. Those values are flat `opscustodian.*` attributes so backends can
filter and aggregate without high-cardinality event names.

## CLI

```bash
opscustodian events --bom agentbom.json --output scan-events.jsonl
opscustodian events --drift drift.json --output drift-events.jsonl
```

Exactly one input is required. BOM `generatedAt` is used as the scan event
timestamp when present; drift conversion uses the conversion time. An observed
timestamp is not invented because that belongs to the SDK, receiver, or
Collector that observes the event.

## Data minimization

Events include counts, identifiers, severity, risk score, factor names, and the
primary evidence location. They deliberately exclude diagnostic messages,
finding before/after values, finding reasons, and risk-factor explanations.
This prevents audit export from becoming a second channel for configuration or
credential-bearing text. Secret values remain prohibited throughout the Agent
BOM and audit contracts.

Control-plane request events contain only a server-generated request ID,
organization ID, HTTP method, canonical ServeMux route pattern, response status,
bounded duration, authentication result (`public`, `authenticated`, or
`rejected`), and authorization result (`public`, `authorized`, `denied`, or
`unknown`). Successful authentication also records the configured non-secret
credential ID; rejected and public requests use no client-provided identity.
They never record raw URLs, query strings, cursors, client-supplied
request IDs, Authorization headers, tokens, remote addresses, or request/response
bodies. A random 128-bit request ID is returned as `X-Request-ID` for local
correlation.

Policy-evaluation requests add only a bounded outcome (`allowed`, `denied`,
`rejected`, `unavailable`, `failed`, or `invalid`). Successful evaluations also
record non-negative deny and warning counts. Policy input, BOM content, decision
messages, rule names, evidence, remediation text, and evaluator errors are never
copied into the request audit event.

The request middleware requires an explicit sink and uses the same
`opscustodian.dev/audit-event/v1alpha1` envelope as scan and drift events.
`serve` installs a synchronized JSONL sink on standard error and a tenant-scoped
PostgreSQL sink. Writes are serialized across concurrent requests and each JSONL
event occupies exactly one line. Fan-out attempts every configured destination
once, even when an earlier destination fails. A shared preflight contract rejects
invalid schema versions, timestamps, severity values, event names, non-JSON
attributes, and payloads larger than 64 KiB before any destination observes them.

Audit storage is fail-closed: if serialization or persistence fails, all sink
errors are joined and the failure is
reported to the process orchestrator, which cancels serving, performs graceful
HTTP shutdown, and closes PostgreSQL. OpsCustodian will not silently continue
serving unaudited requests. PostgreSQL audit history uses the configured bounded
retention policy.

The audit package provides a retry wrapper for destinations that can classify
their own failures as transient. It requires explicit attempt and backoff
bounds, stops on permanent errors, honors context cancellation, and clones the
event before every attempt. `serve` enables it only for PostgreSQL failures that
are safe to repeat before commit, including connection acquisition,
serialization, deadlock, and temporary availability failures. Commit failures
are never retried because the database outcome may be ambiguous and a second
write could duplicate the event. JSONL failures also remain fail-fast. Durable
buffering across process restarts, JSONL rotation, and delivery to other
backends remain responsibilities of the service supervisor or a future bounded
audit exporter.

Credential reload events contain only organization ID and the outcome
`succeeded` or `failed`. File paths, parser errors, credential IDs, scopes,
tokens, and digests are excluded so a malformed secret file cannot become an
audit-data exfiltration channel.

GitHub authentication events contain only organization ID, a bounded operation
and result, transient classification, non-negative duration, and the HTTP status
when an exchange reached the provider. Installation IDs, repository identity,
refs, JWTs, tokens, private-key paths, response bodies, and backend error text
are excluded. Cache hits and refreshes are observable without making credential
material or dynamic identifiers part of telemetry. Observer failure is
fail-closed and is forwarded to the process audit-failure channel.

## OTLP/HTTP export

Network export is disabled unless `--otlp-endpoint` is provided. The endpoint
is the complete signal-specific logs URL and is used as-is:

```bash
opscustodian events --drift drift.json --output drift-events.jsonl \
  --otlp-endpoint https://collector.example.com/v1/logs
```

The exporter sends the official OTLP JSON `ExportLogsServiceRequest` shape with
`Content-Type: application/json`. It performs one bounded request (10 seconds
by default, maximum 1 minute), never follows redirects, and does not retry.
Durable retry and buffering belong in the Collector or job orchestrator.

Authentication headers are read from `OTEL_EXPORTER_OTLP_LOGS_HEADERS`, falling
back to `OTEL_EXPORTER_OTLP_HEADERS`, using the standard comma-separated
`key=value` syntax. Keeping values in environment variables prevents them from
appearing in command arguments. Userinfo, query strings, fragments, `Host`,
`Content-Length`, and connection-control headers are rejected.

Plain HTTP is rejected by default. For a local development Collector only, it
must be explicitly enabled:

```bash
opscustodian events --bom agentbom.json --output scan-events.jsonl \
  --otlp-endpoint http://127.0.0.1:4318/v1/logs --allow-insecure-otlp
```
