# Product vision

## Mission

Make non-human operational access visible, reviewable, and governable before it
causes production impact.

AI agents are becoming operational principals. They can open pull requests,
invoke MCP tools, deploy workloads, query production systems, and remediate
incidents. Their authority is currently distributed across workflow files,
agent instructions, MCP configuration, identity bindings, secret references,
and infrastructure policy. Existing tools inspect individual fragments; teams
lack a consistent view of the resulting authority.

OpsCustodian turns those fragments into an evidence-backed access model and
detects when that model becomes riskier.

## Primary users

- Platform engineers introducing agentic automation safely.
- DevSecOps and cloud security teams reviewing non-human access.
- SRE teams operating remediation and incident-response agents.
- Repository and CI administrators enforcing organization-wide controls.

## Initial use case

A pull request modifies an agent or its runtime configuration. OpsCustodian:

1. Discovers affected agentic assets.
2. Extracts identities, credential references, tools, resources, and controls.
3. Produces a normalized Agent BOM with source evidence.
4. Compares it to the approved Git baseline.
5. Classifies access expansion and evaluates policy.
6. Returns an actionable decision in local CLI and CI.

Example decision:

```text
BLOCKED: agent "incident-remediator" gained production delete access

Added capability: kubernetes.namespaces.delete
Credential:       PROD_KUBECONFIG (reference only)
Evidence:         .github/workflows/remediator.yml:38
Policy:           production-delete-requires-security-approval
Remediation:      restrict the resource scope or add the required approval
```

## Differentiation

OpsCustodian is not a generic secret scanner, prompt-injection detector, agent
runtime, or replacement for OPA. Its defensible core is:

- Cross-format discovery of agentic operational assets.
- Vendor-neutral normalization of effective access.
- Evidence and confidence attached to every inferred relationship.
- Semantic drift detection between approved and proposed states.
- Correlation across agent, identity, credential, tool, resource, environment,
  owner, and control.
- Explainable policy outcomes and concrete remediation.

## Product boundaries

The early releases will not build:

- A proprietary policy language.
- A general-purpose secret or vulnerability scanner.
- An agent execution runtime or LLM gateway.
- A large SaaS dashboard before the CLI proves value.
- Superficial support for many platforms at the expense of reliable evidence.

## Success criteria for the first public milestone

- Installation to first useful result takes less than five minutes.
- Scans are deterministic and work without network access.
- Every finding contains evidence and an explanation.
- Secret values can never enter the Agent BOM or normal logs.
- A realistic demo catches a dangerous permission expansion in a pull request.
- Windows, Linux, and macOS use the same portable executable and behavior.
- The normalized schema is useful to tools other than the OpsCustodian CLI.

## Long-term direction

OpsCustodian can evolve from repository guardrail to organization-wide control
plane by correlating declared configuration with runtime identity, Kubernetes
RBAC, cloud permissions, execution telemetry, cost, and audit history. The open
Agent BOM remains the interoperability boundary throughout that evolution.
