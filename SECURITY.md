# Security policy

## Project status

OpsCustodian is alpha software and is not suitable as a sole production
security control. Findings should be reviewed by a human until a stable release
and its threat model are published.

## Sensitive-data guarantees

OpsCustodian is designed to collect credential references, not credential
values. Secret values must never be included in an Agent BOM, finding, fixture,
normal log, or telemetry event.

If you discover a path by which secret values can be emitted or retained, treat
it as a security vulnerability and do not open a public issue containing the
value or reproduction data.

## Reporting vulnerabilities

Use the repository's GitHub **Security > Advisories > Report a vulnerability**
flow for private reports. Repository administrators must enable GitHub private
vulnerability reporting before making the repository public. If that flow is
not available, do not open a public issue containing vulnerability details;
contact the maintainers through a previously established private channel.

Do not include real credentials, customer data, private repository content, or
unnecessary exploit payloads in any report.

## Threat-model scope

The implementation will treat repositories, configuration files, parser input,
policy bundles, and external connector responses as untrusted. The initial
threat model will cover path traversal, symlink escape, resource exhaustion,
malformed serialization, secret leakage, policy tampering, baseline tampering,
and unsafe terminal/SARIF rendering.
