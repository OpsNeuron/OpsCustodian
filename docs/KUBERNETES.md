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
- `Role` and `ClusterRole` as `authorization-role` assets.
- `RoleBinding` and `ClusterRoleBinding` as `authorization-binding` assets.
- Canonical RBAC capabilities expanded from API groups, resources, and verbs.
- Resolved or unresolved `binds-subject` and `grants-role` relationships.

RBAC effects normalize common verbs as follows: `get/list/watch` are read,
`create/update/patch` are write, deletion verbs are delete, and
`bind/escalate/impersonate/*` are admin. Unknown verbs remain execute so they are
visible without being silently downgraded.

## Effective grants

Resolved bindings copy Role/ClusterRole capabilities onto each referenced
ServiceAccount and then onto workloads using that ServiceAccount. Effective
capabilities carry evidence from both the role and binding. Each recipient also
gets an `effectiveRBACGrant` control naming the source role and binding.

This makes a role-rule change visible as semantic capability drift on the
identity and workload that can actually exercise it. Duplicate capabilities are
collapsed by normalization while evidence from multiple grants is retained.
Missing roles, binding subjects, and workload ServiceAccounts produce
`KUBERNETES_RBAC_ROLE_UNRESOLVED`, `_SUBJECT_UNRESOLVED`, or
`KUBERNETES_SERVICE_ACCOUNT_UNRESOLVED` diagnostics.

## ServiceAccount token exposure

`automountServiceAccountToken` is captured on ServiceAccount and workload
PodSpecs. Effective precedence is workload value, then ServiceAccount value,
then the Kubernetes default (`true`). Every resolved workload receives an
`effectiveServiceAccountToken` control with `enabled` and `source`.

When enabled, the workload receives a
`kubernetes.service_account_token.use` capability targeting its namespace-
qualified ServiceAccount. This capability participates in drift and adds an
explicit risk factor. A workload-level value can intentionally override a
ServiceAccount-level default, and the effective source remains auditable.

The parser does not contact a cluster and never reads token values. Repository
manifests remain declared state until optional live enrichment is introduced.

## Current limitations

- CronJobs and generated Helm/Kustomize output are not yet interpreted.
- Aggregated capabilities are declared-state effective access; admission policy
  and live cluster authorization may still reduce or expand runtime access.
- Projected token audiences/expiration, image provenance, admission policy, and
  live ServiceAccount identity are not correlated yet.
- Candidate-directory coverage is deliberately bounded to avoid treating every
  repository YAML file as Kubernetes input.
