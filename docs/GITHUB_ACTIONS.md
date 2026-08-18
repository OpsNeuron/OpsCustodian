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
