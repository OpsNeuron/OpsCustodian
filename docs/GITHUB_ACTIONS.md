# GitHub Actions effective access

OpsCustodian resolves repository-local GitHub Actions declarations without
inventing repository or organization settings that are not present in the
checkout.

## Token permission precedence

Each job receives a job-scoped capability set:

1. A job-level `permissions` declaration replaces the workflow declaration.
2. A job without `permissions` inherits the workflow declaration.
3. An explicit empty mapping or an all-`none` mapping disables token
   permissions for that job.
4. When neither level declares permissions, OpsCustodian records
   `githubTokenPermissionsUnspecified` and does not guess the repository's
   configurable default.

The `github-actions-job` scope keeps identical permissions on different jobs
separate and preserves the evidence for both the job and the declaration that
determined its effective permissions.

## OIDC federation

GitHub defines `id-token: write` as permission to request an OIDC JWT. It does
not grant write access to repository content. OpsCustodian therefore emits:

```text
action:   github.oidc_token.issue
resource: github:oidc-token
effect:   execute
```

The capability is security-sensitive because a cloud or infrastructure trust
policy may exchange that token for external credentials. The repository alone
does not reveal the external trust policy, audience, or resulting cloud role;
those facts require a later provider enrichment connector.

## Deployment environments

A job that references a GitHub environment emits a
`github.environment.deploy` capability scoped to that job. The accompanying
`githubDeploymentEnvironment` control records the name, optional URL, and a
`protectionStatus` of `unknown`.

The status is intentionally unknown because required reviewers, wait timers,
branch restrictions, environment secrets, and custom protection rules live in
GitHub repository configuration rather than workflow YAML. A future GitHub API
enricher can replace this unknown state with evidence-backed configuration.

## Trigger trust boundaries

OpsCustodian inventories all workflow events in the `githubWorkflowTriggers`
control. It additionally records `githubPrivilegedTriggerExposure` for events
whose GitHub execution context can bridge low-trust input into a privileged
workflow:

- `pull_request_target` runs from the base-repository context. The trigger is
  not itself proof that untrusted code is executed, but checking out or
  evaluating pull-request-controlled content can expose secrets, write tokens,
  or privileged caches.
- `workflow_run` can access secrets and write tokens even when its triggering
  workflow could not. Artifacts, caches, and other outputs from a low-trust
  predecessor therefore require explicit validation.

The parser deliberately reports exposure rather than vulnerability. A later
data-flow stage can correlate checkout refs, artifact consumption, expression
use, runner trust, and effective credentials to establish an exploitable path.

## Initial untrusted data-flow analysis

The first data-flow stage emits `githubUntrustedDataFlow` only for explicit,
high-confidence source-to-sink patterns:

- a privileged `pull_request_target` job passes a pull-request head ref or SHA
  to `actions/checkout`;
- a privileged `workflow_run` job checks out the triggering run's head ref or
  SHA;
- a `workflow_run` job passes `github.event.workflow_run.id` to
  `actions/download-artifact`, moving predecessor-controlled artifacts into the
  privileged runner workspace.

A default checkout of the base branch and a same-run artifact download are not
flagged. This avoids turning the presence of a standard action into a finding
without a demonstrated low-trust source. Each path owns stable step evidence
and is combined with the workflow's effective write, secret, environment, and
OIDC context by the risk engine.

## Direct script injection

OpsCustodian also traces known attacker-influenced GitHub contexts when they
are interpolated directly inside a `run:` script. Initial sources include pull
request titles, bodies and head refs; issue titles and bodies; comment,
discussion and review bodies; and `github.head_ref`. The sink records the
declared shell or the platform default shell.

This stage requires the source to occur inside a GitHub expression in the
`run:` value. It does not flag the safer pattern where an expression is first
assigned to a step or job environment variable and the script references the
quoted shell variable. That distinction follows GitHub's recommendation to
keep untrusted expression expansion out of generated scripts.

## Runner trust

Every statically declared `runs-on` value is recorded in
`githubRunnerSelections` with job evidence. Classification is deliberately
bounded:

- a standard `ubuntu-*`, `windows-*`, or `macos-*` label is classified as
  `github-hosted`;
- an explicit `self-hosted` label is classified as `self-hosted` and emits
  `githubSelfHostedRunnerExposure`;
- expression-selected labels, custom labels, and runner groups remain
  `unknown` and emit `githubRunnerSelectionUnknown`.

Custom labels cannot prove a GitHub-hosted runner because self-hosted runners
can omit the default label, including some Actions Runner Controller setups.
Runner groups may contain either larger GitHub-hosted runners or self-hosted
runners. Resolving those cases requires repository, organization, or enterprise
API enrichment.

The risk engine treats explicit self-hosting as an additional persistence and
isolation concern. When an untrusted data flow reaches that runner, a separate
factor records the possibility that compromise survives beyond the current
job; it does not claim persistence is proven.

## Dependency integrity

Step actions and job-level reusable workflows are added to the asset dependency
graph and summarized in `githubDependencyIntegrity`. OpsCustodian distinguishes:

- `full-commit-sha`: an external action or reusable workflow pinned to a full
  40-character commit SHA;
- `container-digest`: a container action pinned to a SHA-256 digest;
- `same-commit`: a local action or reusable workflow loaded from the caller's
  checked-out revision;
- `tag-or-branch`, `container-tag`, and `unversioned`: mutable external code;
- `dynamic`: an expression-selected reference that cannot be resolved offline.

Mutable and unresolved external dependencies emit
`githubMutableDependencyExposure`. This is a supply-chain exposure, not proof
that the dependency is compromised. The risk engine combines it with effective
write permissions, OIDC, secrets, privileged triggers, data flow, deployment
environment, and runner trust.

Only a full commit SHA is treated as an immutable GitHub action pin. A version
tag remains operationally useful, but its target can be moved or deleted. The
same integrity model applies to external reusable workflows.

## Reusable workflow call boundaries

Job-level reusable workflow calls emit an invocation capability and a
`githubReusableWorkflowCalls` control. Each call records whether it is local or
external, its pin, its effective caller permission source, and one of three
secret modes:

- `none`: no caller secrets are delegated;
- `explicit`: only named secret inputs are mapped, while source secret values
  remain reference-only credentials;
- `inherit`: all organization, repository, and environment secrets visible to
  the caller may be passed to the directly called workflow.

After parsing, OpsCustodian resolves same-revision local calls to workflow
assets and emits `calls-workflow` relationships. The
`githubReusableWorkflowComposition` control records every nested hop, its call
path, caller permission ceiling, and effective secret mode. Nested token
permissions are intersected with the preceding caller ceiling, so composition
never models a called workflow as increasing `GITHUB_TOKEN` access.

Each resolved effective permission also produces a provider-neutral access path
whose `origin` is the caller and whose `delegation` steps are the reusable
workflows in call order. These paths use the same Agent BOM contract, HTML
explorer, validation, and policy surfaces as Kubernetes effective-access paths.
Semantic diff classifies newly reachable paths, permission escalation, changed
delegation routes, and removed paths separately. Findings retain stable IDs and
source locations from every evidence-bearing asset in the path for SARIF and CI.
The derived composition control is excluded from generic `control-changed`
comparison to avoid duplicating those semantic findings with opaque value diffs.

The offline composer reports `GITHUB_REUSABLE_WORKFLOW_UNRESOLVED`,
`GITHUB_REUSABLE_WORKFLOW_CYCLE`, and
`GITHUB_REUSABLE_WORKFLOW_DEPTH_LIMIT`. External reusable workflows remain
explicit unresolved trust boundaries; OpsCustodian does not fetch remote code
or infer its permissions.

## Current-state findings

The offline effective-access stage converts evidence-backed controls into four
structured findings:

- `github-actions-privileged-trigger` for privileged trigger boundaries;
- `github-actions-untrusted-data-flow` when attacker-influenced event data
  reaches a runner shell, workspace, or privileged artifact flow;
- `github-actions-self-hosted-runner-exposure` for explicit self-hosted jobs;
- `github-actions-mutable-dependency` for external code not pinned to a full
  commit SHA or container SHA-256 digest.

Direct runner-shell injection is `critical`. Self-hosted execution becomes
`critical` when the workflow also contains an untrusted data flow because state
can survive beyond one job. A privileged trigger alone is `medium`: it is a
trust boundary requiring review, not proof of exploitation.

Unknown runner groups, dynamic runner expressions, environment protection, and
repository-default token permissions remain explicit unknown state. They are
not promoted to definitive findings until optional GitHub API enrichment can
provide evidence.

`secrets: inherit` emits `githubReusableWorkflowSecretInheritance` and a broad
secret-set reference, never secret values. Secrets do not automatically flow to
the next nested workflow; every direct call must explicitly pass or inherit
them again.

Local calls remain `local-candidate` until the repository composition stage
resolves the referenced workflow asset. External calls remain
`external-unresolved`: the caller-side permissions and secret delegation are
known, but the callee implementation, its nested dependencies, and the actual
repository access policy require source or GitHub API enrichment.
