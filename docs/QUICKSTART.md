# Quick Start

This guide demonstrates OpsCustodian locally without an AI model, database,
cluster, token, or network connection. It uses deliberately risky fixtures so
the first report contains useful evidence.

## What OpsCustodian does

Think of an AI agent as an automated operator, an MCP server as its toolbox,
and a credential as a key. OpsCustodian reads repository declarations and
builds an evidence-backed map of which operator can use which toolbox and key.
It then identifies dangerous current access and meaningful access changes.

OpsCustodian analyzes configuration. It does not execute the agents, connect to
their tools, read secret values, or modify the scanned repository.

## Prerequisite

- Go 1.25 or newer

Run all commands from the repository root.

## Windows Command Prompt

```bat
go build -o .\bin\opscustodian.exe .\cmd\opscustodian
.\bin\opscustodian.exe scan --output .\agentbom.demo.json .\examples\scan-input
.\bin\opscustodian.exe report --bom .\agentbom.demo.json --output .\opscustodian-demo.html
.\bin\opscustodian.exe diff .\examples\scope-expansion\agentbom.before.json .\examples\scope-expansion\agentbom.after.json
```

## Linux and macOS

```bash
go build -o ./bin/opscustodian ./cmd/opscustodian
./bin/opscustodian scan --output ./agentbom.demo.json ./examples/scan-input
./bin/opscustodian report --bom ./agentbom.demo.json --output ./opscustodian-demo.html
./bin/opscustodian diff \
  ./examples/scope-expansion/agentbom.before.json \
  ./examples/scope-expansion/agentbom.after.json
```

## What to inspect

Open `opscustodian-demo.html` in a browser. The report is one local HTML file;
it contains no external scripts or network resources.

Look for:

- agentic assets discovered from GitHub Actions, agent Markdown, MCP, and
  Kubernetes configuration;
- ownership, credentials, declared capabilities, and correlated relationships;
- effective access paths that show how permissions reach a workload or agent;
- diagnostics that explain ambiguous or dangerous configuration.

The final `diff` command should print a critical `capability-escalated` finding.
Its evidence shows a production deployment permission changing from:

```text
kubernetes:production/apps/payments (write)
```

to:

```text
kubernetes:production/* (admin)
```

This is the core value proposition: OpsCustodian compares the meaning of agent
access rather than reporting a noisy text diff.

## Scan your own repository

The scan is offline and read-only:

```bat
.\bin\opscustodian.exe scan --output .\agentbom.json D:\path\to\repository
.\bin\opscustodian.exe report --bom .\agentbom.json --output .\opscustodian-report.html
```

On Linux or macOS, use the equivalent `./bin/opscustodian` paths. Review parser
diagnostics before treating a missing asset as proof that no access exists.

## What is intentionally not part of this first run

The organization server, PostgreSQL persistence, OPA runtime, OpenTelemetry
Collector, GitHub provider access, Kubernetes runtime comparison, and
multi-replica HA validation belong to the final integration lab. They are not
required to understand or evaluate the offline product.

## Next steps

- Add the [GitHub Action](GITHUB_ACTION.md) as a pull-request guardrail.
- Read the [Agent BOM model](ASSET_MODEL.md).
- Review [policy enforcement](POLICY.md) and the [risk model](RISK_MODEL.md).
- Check the honest implementation and validation boundary in
  [project status](PROJECT_STATUS.md).
