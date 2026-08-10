# Architecture

## System context

```text
Git repositories / CI / MCP / Kubernetes / cloud metadata
                           |
                    Discovery engine
                           |
                   Parsers + evidence
                           |
                 Normalization pipeline
                           |
                    Agent BOM + graph
                           |
             +-------------+-------------+
             |             |             |
        Drift engine   Policy engine   Risk engine
             |             |             |
             +-------------+-------------+
                           |
              CLI / JSON / SARIF / CI checks
                           |
                  Audit and telemetry
```

## Architectural invariants

1. Discovery locates artifacts; parsers interpret them.
2. Platform-specific values do not leak into core comparison logic without a
   normalized representation.
3. Every derived fact carries evidence, parser identity, and confidence.
4. Collection never requires access to secret values.
5. Risk scoring prioritizes findings but never replaces policy decisions.
6. Local and CI execution use the same analysis pipeline.
7. Network enrichment is optional and must be explicitly distinguishable from
   offline evidence.
8. Outputs are deterministic after volatile metadata is excluded.

## Core domain model

The first model consists of:

- `Asset`: a typed agent, workflow, MCP server, skill, or instruction set.
- `Agent`: a non-human actor represented as one asset type.
- `Runtime`: the environment in which it executes.
- `Identity`: the principal used to authenticate.
- `CredentialReference`: the name and type of a credential, never its value.
- `Tool`: an interface the agent can invoke.
- `Capability`: an action/effect over a resource.
- `Resource`: repository, environment, cluster, namespace, service, or other target.
- `Control`: approval, network, cost, sandbox, or execution constraint.
- `Evidence`: source location and inference metadata.
- `Finding`: a drift or policy outcome with remediation.

Stable IDs must be reproducible from source identity rather than random values.

## Components

### Discovery engine

Walks configured roots, applies ignore rules, identifies supported artifacts,
and emits content-addressed artifact descriptors. It owns traversal safety,
symlink behavior, file-size limits, and deterministic ordering.

### Parsers

Each parser is independently testable and declares supported artifacts. The
first planned parsers are GitHub Actions and common MCP configuration. Later
parsers cover Codex, Claude, Cursor, Kubernetes RBAC, and Backstage metadata.

Conceptual contract:

```go
type Parser interface {
    Name() string
    Supports(Artifact) bool
    Parse(context.Context, Artifact) (ParseResult, error)
}
```

Parser errors are data-quality signals. A malformed supported artifact must not
silently disappear from the report.

Parser failures are isolated per artifact. They produce structured diagnostics
in the Agent BOM while other supported artifacts continue through the pipeline.
Discovery or filesystem integrity failures remain fatal because the scan cannot
claim to represent the requested root reliably.

### Normalization pipeline

Converts raw parser observations to canonical actions and resource identifiers.
Normalization rules are versioned. Raw observations remain attached as evidence
so users can audit mappings and future releases can re-evaluate them.

The effective-access pass runs after canonicalization and before relationship
correlation. Its gh-aw adapter composes the security-relevant subset of resolved
local imports while keeping validation-only GitHub permissions non-inheritable.
Imported facts retain source evidence; unresolved imports remain graph edges.
Composition order is explicit output data so precedence decisions can be
explained without reproducing parser traversal internally.
Configuration conflict fingerprints must be structurally useful without
serializing secret values or sensitive command arguments into portable output.

### Evidence graph

Represents relationships among agents, identities, credentials, tools,
capabilities, resources, environments, owners, and controls. The Agent BOM is
the portable serialized view; later server releases may persist the graph.

The first correlation pass resolves explicit owner, tool, MCP server, credential,
and skill dependency declarations. Resolved asset targets use stable IDs;
unresolved declarations remain visible as typed references.

An optional boundary pass classifies source paths into monorepo components using
deterministic longest-prefix matching. Classification is orthogonal to discovery
and ownership: it never hides assets or rewrites evidence paths.

### Drift engine

Compares canonical models, not source text. Initial change classes include:

- Agent, tool, credential reference, identity, or capability added.
- Read-to-write or write-to-delete escalation.
- Resource or repository scope expansion.
- Access to a more sensitive environment.
- Approval, sandbox, owner, pin, or network restriction removed.
- Provenance or runtime changed.

Every change receives a reproducible finding ID derived from semantic identity,
not report ordering. This makes suppression, explanation, and CI annotations
stable across repeated scans.

### Risk engine

Assigns transparent, configurable priority based on impact, scope, environment,
and evidence confidence. The result must expose its contributing factors.

### Policy adapter

Uses OPA/Rego initially. OpsCustodian supplies a stable policy input document
and consumes deny, warn, and remediation results. Policy evaluation remains
separate from discovery and parsing.

The first adapter invokes the OPA CLI as an isolated process. This avoids
embedding the full OPA dependency graph in the portable core while the policy
contracts mature. Execution has a timeout, bounded output capture, a protected
temporary input file, and a validated decision shape. An embedded adapter can
be added behind the same contract if deployment evidence requires it.

### Reporters

The initial reporters are terminal, JSON, YAML, SARIF, and a self-contained
read-only HTML inventory. Reporters must not change analysis results and must
apply centralized redaction rules. The HTML surface has no JavaScript or remote
resources and escapes repository-derived values during rendering.

## Process exit contract

- `0`: successful execution with no finding at the configured failure threshold.
- `1`: invalid input, configuration, serialization, or operational failure.
- `2`: analysis succeeded and semantic drift met `--fail-on`.

Future policy denials will reuse exit code `2`; callers should distinguish drift
and policy outcomes through the structured report rather than additional exit
codes.

## Planned repository layout

```text
cmd/opscustodian/       CLI entry point
internal/discovery/     deterministic artifact discovery
internal/parsers/       first-party format parsers
internal/model/         canonical domain types
internal/normalize/     versioned normalization rules
internal/evidence/      provenance and confidence handling
internal/graph/         domain correlation
internal/drift/         semantic comparison
internal/risk/          explainable prioritization
internal/policy/        OPA adapter and policy input
internal/report/        output formats and redaction
internal/config/        configuration loading
pkg/sdk/                intentionally public integration contracts
schemas/                versioned interchange schemas
policies/builtin/       open default policy pack
examples/               runnable safe and unsafe scenarios
testdata/               parser and end-to-end fixtures
docs/                   product and engineering documentation
action/                 GitHub Action packaging
```

Public Go packages will be introduced only when a real external integration
requires them. Most implementation stays under `internal` while APIs mature.

## Security and privacy

- Secret values are prohibited from domain models and normal logs.
- File content is processed locally by default.
- Optional network connectors must be opt-in and use least privilege.
- Evidence output applies path and value redaction consistently.
- Artifact parsing must assume untrusted input and enforce resource limits.
- Baselines and policy exceptions will support integrity protection before 1.0.

## Compatibility strategy

The schema uses an explicit `apiVersion`. Until beta, breaking changes may occur
between alpha versions. Each stable version will define migration rules and a
support window. Parser behavior and normalization-rule versions are included in
generation metadata to make results reproducible.

## Deferred decisions

- Exact OPA integration mode: embedded library versus external binary.
- Plugin isolation protocol: subprocess JSON versus WASM.
- Graph persistence model for server mode.
- Signed-baseline format and trust model.
- Effective-access enrichment contracts for GitHub, Kubernetes, and cloud APIs.

These decisions are deliberately deferred until the offline GitHub-first path
has real fixtures and performance data.
