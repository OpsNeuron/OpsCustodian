# Policy enforcement

OpsCustodian delegates policy evaluation to Open Policy Agent (OPA). It does not
define a proprietary policy language. Policies are ordinary Rego and receive a
versioned JSON input document.

The organization API defines `POST /api/v1/policy/evaluate` as a
provider-neutral enforcement boundary. It accepts the same versioned policy
input used by the CLI and returns an explicit `allowed` boolean with the full
normalized deny/warn decision. Requests are bounded, strict, non-persisting,
and protected by the dedicated `policy:evaluate` scope. The endpoint fails
closed when its evaluator is unavailable or invalid. Process-level OPA wiring
is enabled only when `OPSCUSTODIAN_POLICY_PATH` is configured. Without that
setting, the endpoint deliberately returns `503` rather than bypassing policy.

The server executes OPA as a bounded local subprocess. Configure a reviewed
absolute policy path, optionally select the executable and query, and keep the
dedicated scope on only the clients that need policy evaluation:

```bash
OPSCUSTODIAN_API_SCOPES=policy:evaluate
OPSCUSTODIAN_POLICY_PATH=/etc/opscustodian/policies
OPSCUSTODIAN_OPA_BINARY=opa
OPSCUSTODIAN_POLICY_QUERY=data.opscustodian.decision
OPSCUSTODIAN_POLICY_TIMEOUT=5s
```

The supplied container image includes the pinned OPA executable. Policy files
are not embedded; operators mount their reviewed bundle read-only and select it
with `OPSCUSTODIAN_POLICY_PATH`.

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
- Server-side OPA execution is bounded by `OPSCUSTODIAN_POLICY_TIMEOUT` (5 seconds by default and at most 30 seconds).
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
