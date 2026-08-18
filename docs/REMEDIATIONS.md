# Remediation identifiers

Every current-state finding contains a stable `remediationId` and human-readable
`remediation` guidance. Automation, policy, APIs, and UI should match the ID;
the text may improve without changing the contract.

IDs use lowercase `namespace.action-name` form. They identify the intended
outcome rather than a vendor command, because the exact patch depends on the
repository and organizational policy.

## Kubernetes

| ID | Intended outcome |
| --- | --- |
| `kubernetes.reduce-rbac-privileges` | Remove privilege-management verbs or wildcard grants. |
| `kubernetes.reduce-effective-access` | Narrow the complete identity, binding, role, and token access chain. |
| `kubernetes.disable-token-automount` | Prevent unnecessary default ServiceAccount token mounting. |
| `kubernetes.harden-projected-token` | Use a specific audience and short token lifetime. |

## MCP

| ID | Intended outcome |
| --- | --- |
| `mcp.pin-runtime` | Select an immutable or explicitly governed runtime identity. |
| `mcp.require-tls` | Use authenticated TLS for remote MCP transport. |
| `mcp.enforce-repository-boundary` | Keep local execution inside the governed revision. |

## GitHub Actions

| ID | Intended outcome |
| --- | --- |
| `github-actions.restrict-privileged-trigger` | Reduce or isolate privileged trigger boundaries. |
| `github-actions.remove-untrusted-data-flow` | Prevent attacker-controlled data from reaching executable sinks. |
| `github-actions.isolate-self-hosted-runner` | Use ephemeral isolation and trusted trigger constraints. |
| `github-actions.pin-dependency` | Pin actions/workflows to commit SHAs and images to digests. |

The current contract deliberately does not emit auto-fix patches. A future
remediation engine must verify evidence locations, preserve source formatting,
show a diff, and require explicit approval before changing repository content.
