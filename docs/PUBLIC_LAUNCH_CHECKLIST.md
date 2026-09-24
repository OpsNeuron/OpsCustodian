# Public repository and social launch checklist

OpsCustodian can be introduced as an **open-source alpha** before organization
server, provider, Kubernetes, or HA hardening is complete. Public wording must
keep the offline evidence workflow separate from production-runtime claims.

## Blockers before making the repository public

- [x] Apache-2.0 license is committed.
- [x] README explains the product, boundaries, Quick Start, and concrete value.
- [x] SECURITY and CONTRIBUTING define safe reporting and contribution rules.
- [x] Deterministic Go checks and the disposable PostgreSQL/OPA/OTLP integration
  harness have passed locally.
- [x] Remove generated root Agent BOM and HTML artifacts from Git tracking while
  retaining the deliberate `examples/**` and `internal/**/testdata/**` fixtures.
- [x] Push the current clean commit and observe Linux, race, and Windows CI pass.
- [x] Enable GitHub private vulnerability reporting before changing visibility.
- [x] Review the public tree and history for real secrets, private repository
  data, personal paths, and internal organization references. A secret-safe
  scan of 221 revisions found no private-key/token patterns or local filesystem
  paths. One author email remains as ordinary historical Git metadata;
  repository-local identity uses the GitHub noreply address for future commits.
- [x] Configure repository description, topics, website/documentation link, and
  default branch protection. The homepage links to the tagged
  `v0.5.0-alpha` Quick Start.

## Blockers before the first social announcement

- [x] Complete all public-repository blockers above.
- [ ] Merge the final hardening branch into `main` and observe required Linux,
  race, and Windows CI checks on the resulting pull request. The public `main`
  branch must display the current README, demo GIF, and limitations before the
  first social announcement.
- [x] Capture current, synthetic screenshots of the self-contained HTML report.
- [x] Run the Windows Quick Start from a fresh, depth-one clone of tag
  `v0.5.0-alpha` at commit `20e32b56f4e46802f32002d9d259e62640f355fd`.
  The source build, scan, self-contained HTML report, and semantic diff passed;
  the expected critical `capability-escalated` finding scored `100/100`
  (verified with Go 1.26.5 on 2026-08-29).
- [x] Decide whether the announcement links to `main` or a tested
  `v0.5.0-alpha` prerelease. Prefer the prerelease when CI and release assets
  have completed successfully. The announcement links to the tested prerelease.
- [x] Prepare one concise problem statement, screenshots, one critical-drift
  example, alpha limitations, and one feedback request in the
  [public alpha launch kit](LAUNCH_KIT.md).
- [x] Verify the repository, `v0.5.0-alpha` release, tagged Quick Start, and
  synthetic report images without authentication. Confirm the issue chooser
  and private vulnerability form resolve to GitHub's expected sign-in flow for
  unauthenticated visitors (verified 2026-08-29).

## Not blockers for the public alpha

- PostgreSQL rollback, TLS matrix, retention, and performance hardening.
- Real GitHub PAT/App compatibility and provider rate-limit testing.
- Live Kubernetes authorization comparison and failure injection.
- Multi-replica leader election and HA claims.
- Standalone UI, Backstage plugin, or managed service.

These remain roadmap and release-hardening gates. Any capability without real
environment evidence must remain labeled experimental or unverified.

## Repository metadata

Suggested description:

> Evidence-based control plane for AI agents, MCP servers and automated DevOps workflows—inventory effective access, detect permission drift, and enforce policy.

Suggested topics:

```text
agentic-devops ai-agents devops security mcp kubernetes github-actions
policy-as-code opa sbom governance go
```

## Launch readiness decision

The repository is public and its original publication blockers are complete.
Social promotion should wait until the final hardening branch is merged into
`main` and its required CI checks pass, because the updated README, demo GIF,
limitations, and environment evidence materially affect first impressions.
