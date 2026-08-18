# Current-state findings

OpsCustodian distinguishes three result types:

- `diagnostics` describe parser, resolution, or composition health.
- `findings` describe security-relevant state in one Agent BOM.
- semantic drift `changes` compare a baseline BOM with a proposed BOM.

Findings are versioned as part of the Agent BOM `v1alpha1` contract. Every
finding has a stable ID, type, severity, subject asset, human-readable reason,
optional remediation, structured attributes, and at least one evidence
reference. Evidence references contain both `assetId` and `evidenceId` because
evidence IDs are local to an asset and an effective access chain can cross a
workload, identity, binding, and role.

## Kubernetes effective-access expansion

`kubernetes-effective-access-expansion` is emitted when a workload or identity
inherits dangerous access that it did not declare directly. The finding records
counts, inherited actions, maximum effect, wildcard state, escalation signals,
and grant sources without copying manifest values or credentials.

The existing `KUBERNETES_EFFECTIVE_ACCESS_EXPANSION` diagnostic remains during
the experimental compatibility period. Policy engines should prefer the
structured finding for enforcement and use diagnostics to monitor scan health.

Current-state findings also produce minimized
`opscustodian.finding.detected` audit events. Finding reasons, remediation text,
and arbitrary structured attributes are deliberately not copied into audit
events.
