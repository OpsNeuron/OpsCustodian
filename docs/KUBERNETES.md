# Kubernetes effective access

Kubernetes support begins the `v0.4` effective-access milestone. The first
offline pass discovers manifests in directories named `k8s`, `kubernetes`,
`manifests`, `deploy`, or `deployments`.

## Current coverage

- Multi-document YAML.
- `ServiceAccount` as an `identity` asset.
- `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, and `Job` as `workload` assets.
- Namespace-qualified stable IDs.
- Explicit or default `serviceAccountName` identity references.
- Resolved or unresolved `runs-as` graph relationships.
- Evidence-backed workload execution and service-account authentication capabilities.

The parser does not contact a cluster and never reads token values. Repository
manifests remain declared state until optional live enrichment is introduced.

## Current limitations

- CronJobs and generated Helm/Kustomize output are not yet interpreted.
- RBAC Role, ClusterRole, RoleBinding, and ClusterRoleBinding are the next step.
- Image provenance, admission policy, projected tokens, automount settings, and
  live ServiceAccount identity are not correlated yet.
- Candidate-directory coverage is deliberately bounded to avoid treating every
  repository YAML file as Kubernetes input.
