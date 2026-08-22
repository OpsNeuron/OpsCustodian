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

The request middleware requires an explicit sink and uses the same
`opscustodian.dev/audit-event/v1alpha1` envelope as scan and drift events.
`serve` installs a synchronized JSONL sink on standard error so container and
service supervisors can collect it independently from API responses. Writes are
serialized across concurrent requests and each event occupies exactly one line.

Audit storage is fail-closed: if serialization or output fails, the failure is
reported to the process orchestrator, which cancels serving, performs graceful
HTTP shutdown, and closes PostgreSQL. OpsCustodian will not silently continue
serving unaudited requests. Durable buffering, rotation, retention, and backend
delivery remain responsibilities of the service supervisor or a future bounded
audit exporter.

Credential reload events contain only organization ID and the outcome
`succeeded` or `failed`. File paths, parser errors, credential IDs, scopes,
tokens, and digests are excluded so a malformed secret file cannot become an
audit-data exfiltration channel.

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
