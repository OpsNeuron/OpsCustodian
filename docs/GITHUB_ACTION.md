# GitHub Action integration

The initial GitHub Action compares an approved Agent BOM with a fresh scan of a
pull request checkout. It emits SARIF 2.1.0 with stable fingerprints and source
locations so GitHub code scanning can display findings beside repository code.

## Establish a baseline

Generate and review the baseline on a trusted revision:

```bash
opscustodian scan --output .opscustodian/baseline.agentbom.json .
```

Commit the reviewed baseline. Baseline changes should require the same owners
who approve agentic access. Do not regenerate and accept it automatically in the
pull-request job, because that would compare the proposed state with itself.

## Workflow

Copy `examples/github-actions/opscustodian.yml` into
`.github/workflows/opscustodian.yml` and pin the action to a released immutable
tag or commit SHA. The `@v0` reference in the example is illustrative until the
first release exists.

The action:

1. Reads the committed baseline.
2. Scans the checked-out proposed repository state.
3. Produces a proposed Agent BOM under `.opscustodian/`.
4. Performs semantic drift analysis.
5. Writes a SARIF report.
6. Exits `2` when findings meet `fail-on`.

The workflow uses `if: always()` for SARIF upload so the report is still
published when OpsCustodian intentionally fails the guard step.

## Inputs

- `baseline-bom` (required): approved Agent BOM path.
- `proposed-bom`: optional existing proposed Agent BOM; skips scanning when set.
- `scan-path`: scan root, default `.`.
- `fail-on`: `info`, `low`, `medium`, `high`, or `critical`; default `high`.
- `sarif-output`: output path; default `opscustodian.sarif`.
- `max-file-size`: discovery limit in bytes; default 2 MiB.

## Outputs

- `sarif`: generated SARIF path.
- `proposed-bom`: Agent BOM used for comparison.

## Security considerations

- Treat the baseline as security-sensitive configuration and protect it with
  CODEOWNERS and branch rules.
- Pin production workflows to an immutable release commit rather than a moving tag.
- The action requests only `contents: read` and `security-events: write` in the
  example workflow.
- GitHub may restrict SARIF uploads from untrusted fork pull requests. Choose a
  workflow model appropriate for the repository's contributor threat model;
  never grant fork-controlled code write-capable credentials.
- The Action currently performs repository-local discovery only. Organization
  and runtime connectors will use separate least-privilege credentials later.

## Current status

The Action and SARIF renderer are pre-alpha and pending build, schema, and live
GitHub validation. Do not make this check the sole production merge control yet.
