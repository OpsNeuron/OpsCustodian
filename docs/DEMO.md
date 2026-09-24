# Two-minute demo

This is a presenter script for introducing OpsCustodian without explaining the
organization server, HA, or every parser. Run it from the repository root.

The repository also includes a short, silent terminal-to-report teaser at
[`docs/images/opscustodian-demo.gif`](images/opscustodian-demo.gif). It contains
no local filesystem path, credential, or generated Agent BOM content and can be
embedded in the repository or release description.

## 0:00 — The problem

> AI agents and automated workflows are becoming DevOps operators. Their
> permissions are scattered across workflow files, MCP configuration, secrets,
> Kubernetes identities, and imported instructions. OpsCustodian answers who
> can do what, through which identity, and whether that access became riskier.

## 0:25 — Build an evidence-backed inventory

Windows Command Prompt:

```bat
go build -o .\bin\opscustodian.exe .\cmd\opscustodian
.\bin\opscustodian.exe scan --output .\agentbom.demo.json .\examples\scan-input
.\bin\opscustodian.exe report --bom .\agentbom.demo.json --output .\opscustodian-demo.html
```

Open `opscustodian-demo.html` and show:

1. discovered agents, workflows, MCP servers, and Kubernetes identities;
2. credentials and capabilities without exposed secret values;
3. relationships and effective-access paths;
4. diagnostics that preserve uncertainty instead of hiding unsupported input.

## 1:05 — Detect meaningful drift

```bat
.\bin\opscustodian.exe diff .\examples\scope-expansion\agentbom.before.json .\examples\scope-expansion\agentbom.after.json
```

Point to the result:

```text
CRITICAL kubernetes.deployments.update
Before: kubernetes:production/apps/payments (write)
After:  kubernetes:production/* (admin)
Reason: capability effect increased; scope introduced wildcard access
```

> This is not a text diff. OpsCustodian recognized that one workload with write
> access became every production workload with admin access, kept the evidence,
> and assigned a stable finding identity that CI can enforce.

## 1:40 — The product boundary

> The first-use path is one offline binary. It does not host a model, run an
> agent, retrieve secrets, or require a control-plane server. Teams can start
> locally, add the GitHub Action and OPA policies, and adopt the organization
> server later when they need history across repositories.

## Close

> OpsCustodian is the evidence and policy layer between agentic automation and
> production access.

Do not claim production readiness, real-provider parity, or HA support during
the alpha demo. Those claims remain gated by the documented integration lab.
