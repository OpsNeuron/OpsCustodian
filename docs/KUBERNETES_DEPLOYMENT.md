# Kubernetes deployment contract

The Kustomize base under `deploy/kubernetes/base` is a deployment contract for
the organization control plane. On 2026-09-23 it passed server-side admission
and a disposable single-replica runtime deployment on Docker Desktop
Kubernetes. The Pod became Ready and an allowed namespace reached `/healthz`
through the Envoy TLS sidecar before all temporary resources were removed.

The Docker Desktop built-in cluster exposed no policy-enforcing CNI/controller,
and an unlabeled namespace also reached the Service there. A follow-up isolated
Kind v1.32.2 cluster with Calico v3.32.1 proved the intended policy behavior:
the labeled client received the HTTPS health response and the unlabeled client
timed out and failed. Both clusters and all supporting resources were removed
after validation.

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

The base deliberately runs one replica. Runtime lease coordination and
transactional snapshot fencing now prevent stale scheduler generations from
committing after takeover. Do not scale above one until this behavior passes
real PostgreSQL contention and failure-injection tests in the final integration
lab; the static contract alone is not a production HA claim.
The PodDisruptionBudget uses `minAvailable: 1`; this improves voluntary-disruption
safety but can block node drains. Rolling updates use one surge Pod and no
unavailable Pod, so database migration compatibility must remain backward-safe.

An opt-in `deploy/kubernetes/overlays/ha-experimental` profile renders two
replicas with preferred node anti-affinity, topology spreading, bounded rollout
timing, a 45-second lease, and 15-second renewal. It exists to drive the final
Docker Desktop/Kubernetes failure-injection plan in `docs/HA_TEST_PLAN.md`; do
not treat its presence as validation or apply it to production.

## Render-only validation

Rendering does not contact a cluster:

```bash
kubectl kustomize deploy/kubernetes/base
kubectl kustomize deploy/kubernetes/overlays/ha-experimental
```

Final validation must still add certificate rotation, trust-distribution,
disruption, resource-pressure, and rollout rollback tests in a disposable
cluster. Server-side admission, restricted workload readiness, probes,
NetworkPolicy connectivity, and PostgreSQL transport/migration behavior have
passed in the documented disposable environments.
