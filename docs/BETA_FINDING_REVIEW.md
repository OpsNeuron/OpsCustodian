# First-beta representative Finding review

This review bounds false-positive behavior on the deliberately mixed
GitHub Actions, MCP, and Kubernetes repository in `examples/scan-input`. It is
a deterministic product review, not an external-adopter usability result and
not a claim about an arbitrary production repository.

## Review method

The repository was scanned with the same parser registry and effective-access
composition used by the CLI. Every Finding was traced from its stable identity
to its source asset, evidence references, reason, and remediation. The reviewed
set is stored in
`internal/contracts/testdata/beta-finding-review.json`; a contract test fails if
a Finding is added, removed, re-identified, re-severed, moved to another source,
loses evidence, or changes remediation without an explicit review.

Run the review regression with:

```bash
go test ./internal/contracts -run TestBetaRepresentativeFindingReviewRemainsStable -v
```

## Reviewed result

The fixture produces 11 Findings: five critical, three high, and three medium.
All 11 correspond to conditions intentionally present in the fixture; no
reviewed Finding was classified as a false positive.

| Finding family | Count | Reviewed source | Intentional condition |
| --- | ---: | --- | --- |
| GitHub Actions mutable dependency | 2 | `privileged-review.yml`, `remediator.yml` | External execution references are deliberately mutable |
| GitHub Actions privileged trigger | 1 | `privileged-review.yml` | A lower-trust event reaches a privileged workflow context |
| GitHub Actions untrusted data flow | 1 | `privileged-review.yml` | Event-controlled data reaches an executable sink |
| GitHub Actions self-hosted runner | 1 | `privileged-review.yml` | The job deliberately selects persistent self-hosted labels |
| MCP runtime pinning | 1 | `.mcp.json` | The runtime identity is intentionally unversioned and lacks integrity evidence |
| Kubernetes RBAC escalation | 1 | `k8s/runtime.yaml` | The role deliberately includes bind, escalate, impersonate, and wildcard authority |
| Kubernetes effective-access expansion | 2 | `k8s/runtime.yaml` | RBAC inheritance intentionally exceeds declared workload and identity access |
| Kubernetes token automount | 1 | `k8s/runtime.yaml` | The workload deliberately receives an automatically mounted token |
| Kubernetes projected-token risk | 1 | `k8s/runtime.yaml` | The projected token lifetime is intentionally long |

The test locks evidence counts as well as Finding identity. It does not freeze
human-facing prose byte for byte, but a reason or remediation change still
requires normal contract and documentation review.

## Boundary and remaining exit evidence

This closes the representative in-repository false-positive review for the
first-beta parser set. The alpha exit gate remains open until a person who did
not implement the feature completes the documented Quick Start from a clean
checkout and reports whether the output is understandable and actionable.
Future parser families or normalization changes require expanding this fixture
or adding another reviewed representative repository; silently accepting a
new Finding is not allowed.
