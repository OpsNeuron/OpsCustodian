# Current-state findings

OpsCustodian distinguishes three result types:

- `diagnostics` describe parser, resolution, or composition health.
- `findings` describe security-relevant state in one Agent BOM.
- semantic drift `changes` compare a baseline BOM with a proposed BOM.

Findings are versioned as part of the Agent BOM `v1alpha1` contract. Every
finding has a stable ID, type, severity, subject asset, human-readable reason,
stable `remediationId`, human-readable remediation, structured attributes, and at least one evidence
reference. Evidence references contain both `assetId` and `evidenceId` because
evidence IDs are local to an asset and an effective access chain can cross a
workload, identity, binding, and role.

Consumers must key automation on `remediationId`, not remediation prose. IDs
use lowercase `namespace.action-name` form and are cataloged in
[`REMEDIATIONS.md`](REMEDIATIONS.md).

## Kubernetes effective-access expansion

`kubernetes-effective-access-expansion` is emitted when a workload or identity
inherits dangerous access that it did not declare directly. The finding records
counts, inherited actions, maximum effect, wildcard state, escalation signals,
and grant sources without copying manifest values or credentials.

The existing `KUBERNETES_EFFECTIVE_ACCESS_EXPANSION` diagnostic remains during
the experimental compatibility period. Policy engines should prefer the
structured finding for enforcement and use diagnostics to monitor scan health.

## Kubernetes credential and escalation findings

- `kubernetes-rbac-privilege-escalation` identifies roles containing wildcard,
  bind, escalate, impersonate, or equivalent privilege-management capability.
- `kubernetes-service-account-token-exposure` identifies workloads receiving an
  effective automounted token. Implicit Kubernetes-default automount is rated
  higher than an explicit workload or ServiceAccount choice.
- `kubernetes-projected-token-risk` identifies mounted projected tokens using
  the default audience or an expiration longer than one hour.

These findings contain only references and normalized settings. Token values,
environment values, and arbitrary manifest content never enter the contract.

## MCP provenance findings

- `mcp-runtime-unpinned` identifies mutable package/image references or system
  executables whose installed identity cannot be verified offline.
- `mcp-insecure-transport` identifies non-TLS remote MCP endpoints.
- `mcp-repository-boundary-escape` identifies executable paths outside the
  governed repository revision.

Remote endpoints are not mislabeled as package pinning failures. Their TLS and
host identity are modeled separately, and all attributes use the sanitized MCP
provenance contract.

## GitHub Actions findings

- `github-actions-privileged-trigger`
- `github-actions-untrusted-data-flow`
- `github-actions-self-hosted-runner-exposure`
- `github-actions-mutable-dependency`

These findings preserve job, trigger, source, sink, runner classification, and
dependency pin type while excluding parser explanations, workflow expression
values, secret values, and arbitrary step content. Unknown GitHub-hosted state
is retained as inventory rather than promoted to a false-positive finding.

Current-state findings also produce minimized
`opscustodian.finding.detected` audit events. Finding reasons, remediation text,
and arbitrary structured attributes are deliberately not copied into audit
events.

## CLI and CI enforcement

The same persisted Agent BOM can be rendered without rescanning:

```bash
opscustodian findings --bom agentbom.json --format terminal
opscustodian findings --bom agentbom.json --format json --output findings.json
opscustodian findings --bom agentbom.json --format sarif --output findings.sarif
```

`--fail-on info|low|medium|high|critical` writes the selected report first and
then exits with code `2` when a finding meets the threshold. This makes the
result suitable for CI and GitHub code scanning while preserving the report on
policy failure. SARIF locations are resolved through the finding's cross-asset
evidence references rather than inferred from message text.

The built-in OPA starter pack denies `critical` current-state findings and
warns for `high` findings while preserving their `remediationId` and evidence
references in the policy decision.
