# Security policy

## Project status

OpsCustodian is pre-alpha and is not yet suitable as a sole production security
control. Findings should be reviewed by a human until a stable release and its
threat model are published.

## Sensitive-data guarantees

OpsCustodian is designed to collect credential references, not credential
values. Secret values must never be included in an Agent BOM, finding, fixture,
normal log, or telemetry event.

If you discover a path by which secret values can be emitted or retained, treat
it as a security vulnerability and do not open a public issue containing the
value or reproduction data.

## Reporting vulnerabilities

A private reporting channel will be configured before the first public release.
Until then, repository maintainers should be contacted privately. Do not include
real credentials, customer data, private repository content, or exploit payloads
in public reports.

## Threat-model scope

The implementation will treat repositories, configuration files, parser input,
policy bundles, and external connector responses as untrusted. The initial
threat model will cover path traversal, symlink escape, resource exhaustion,
malformed serialization, secret leakage, policy tampering, baseline tampering,
and unsafe terminal/SARIF rendering.
