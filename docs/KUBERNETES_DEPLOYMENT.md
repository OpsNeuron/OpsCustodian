# Kubernetes deployment contract

The Kustomize base under `deploy/kubernetes/base` is a source-level deployment
contract for the organization control plane. It has not yet been applied to a
real cluster.

OpsCustodian intentionally remains bound to loopback. An Envoy sidecar accepts
TLS 1.3 on port 8443 and forwards only within the Pod to
`127.0.0.1:8080`. The ClusterIP Service exposes the sidecar on port 443; it does
not bypass the application authentication and authorization middleware.

The base enforces the Restricted Pod Security profile, non-root UID/GID 65532,
default seccomp, dropped capabilities, read-only root filesystems, bounded
temporary volumes, resource requests/limits, disabled ServiceAccount token
mounting, and disabled service-link environment injection. Exec probes are
required because kubelet HTTP probes target the Pod IP while OpsCustodian
listens only on loopback.

## Required replacements

Before rendering, replace:

- `REPLACE_VERSION` with an immutable release tag or, preferably, image digest;
- `REPLACE_ORGANIZATION_ID` with a valid organization identifier;
- `REPLACE_ORGANIZATION_DISPLAY_NAME` with the display name.

Create `opscustodian-secrets` and `opscustodian-tls` through the organization's
secret manager, External Secrets operator, Sealed Secrets, or another approved
mechanism. `secret.example.yaml` contains placeholders and is deliberately not
referenced by Kustomize. Never commit a rendered Secret.

The database DSN must use `sslmode=verify-full` and trusted CA material in
production. The TLS Secret protects the client-to-sidecar hop. Certificate
issuance, rotation, trust distribution, and ingress/gateway configuration remain
cluster-specific overlays.

## Network boundaries

Ingress is permitted only from namespaces labeled:

```text
opscustodian.dev/client-access=allowed
```

Egress permits cluster DNS plus TCP 443 and 5432. Because standard Kubernetes
NetworkPolicy cannot express GitHub or database DNS names, the base uses broad
IPv4 destinations on those two ports. Production overlays must narrow egress
with CNI FQDN policy, explicit database CIDRs, private endpoints, or an egress
gateway. IPv6 and cluster-specific DNS labels also require an overlay.

## Availability boundary

The base deliberately runs one replica. Multiple replicas would run multiple
ingestion schedulers because leader election or distributed job leasing is not
implemented. Do not scale above one until that coordination contract exists.
The PodDisruptionBudget uses `minAvailable: 1`; this improves voluntary-disruption
safety but can block node drains. Rolling updates use one surge Pod and no
unavailable Pod, so database migration compatibility must remain backward-safe.

## Render-only validation

Rendering does not contact a cluster:

```bash
kubectl kustomize deploy/kubernetes/base
```

Final validation must add server-side dry-run, Pod Security admission,
NetworkPolicy connectivity, certificate rotation, PostgreSQL TLS, probe,
rollout, disruption, resource, and rollback tests in a disposable cluster.
