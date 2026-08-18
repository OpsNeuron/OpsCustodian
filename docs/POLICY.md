# Policy enforcement

OpsCustodian delegates policy evaluation to Open Policy Agent (OPA). It does not
define a proprietary policy language. Policies are ordinary Rego and receive a
versioned JSON input document.

## Check an Agent BOM

```bash
opscustodian check --bom agentbom.json --policy policies/builtin
```

For drift-aware policy, add an approved baseline:

```bash
opscustodian check \
  --baseline baseline.json \
  --bom proposed.json \
  --policy policies/builtin
```

OPA must be available on `PATH`, or selected explicitly with `--opa`. The
default query is `data.opscustodian.decision`. A different package can be used
with `--query` when it returns the same decision contract.

## Policy input

```json
{
  "apiVersion": "opscustodian.dev/policy-input/v1alpha1",
  "bom": {},
  "drift": {}
}
```

`drift` is omitted when no baseline is supplied.

## Decision contract

```json
{
  "deny": [{
    "rule": "production-destructive-access-requires-approval",
    "title": "Destructive production access has no human approval",
    "message": "Agent can delete a production resource without approval.",
    "severity": "critical",
    "agentId": "github-actions:.github/workflows/remediator.yml",
    "remediationId": "github-actions.restrict-privileged-trigger",
    "remediation": "Add a humanApproval control.",
    "evidenceIds": ["gha-1234"]
  }],
  "warn": []
}
```

`rule`, `title`, and `message` are required. Severity must be `info`, `low`,
`medium`, `high`, or `critical`. `remediationId`, when present, must use the same
namespace-qualified contract as Agent BOM findings. OpsCustodian generates a
stable policy finding ID when the policy does not provide one.

## Exit behavior

- No denial: exit `0`, including when warnings exist.
- One or more denials: exit `2` after writing the complete decision.
- Invalid input, policy, OPA output, timeout, or execution error: exit `1`.

## Security behavior

- OPA execution is bounded by `--timeout` (10 seconds by default).
- Captured OPA stdout and stderr are bounded to prevent unbounded memory use.
- Policy input uses a mode `0600` temporary file removed after evaluation.
- Agent BOM forbids credential values; only references enter policy input.
- Policy bundles are executable authorization logic and must be reviewed and
  versioned like source code.

## Starter policies

The starter pack:

- denies every structured current-state finding with `critical` severity;
- warns for structured current-state findings with `high` severity;
- carries the finding's `remediationId`, remediation, and evidence references
  into the policy decision;
- detects destructive production access without approval;
- denies newly-added credential references containing `PROD`; and
- warns for agents without an owner.

Medium and lower current-state findings remain inventory by default. The pack
is intentionally conservative and must be reviewed before production use.
Its deterministic Rego contract tests live beside the policy and run with:

```bash
opa test policies/builtin -v
```
