# Beta support matrix

This document defines the deliberately narrow support promise for the first
OpsCustodian beta. A feature that exists in source or has one experimental test
is not beta-supported unless it is listed as supported here. Every supported
claim remains conditional on the exact release-candidate gates in the
[beta checklist](BETA_RELEASE_CHECKLIST.md) passing.

## Support window

Before 1.0, only the latest published beta release receives compatibility and
security fixes. The first beta supports an upgrade from the immutable
`v0.5.0-alpha` release. Later beta releases support only the immediately
preceding published beta unless their release notes and retained upgrade
evidence explicitly add another source version.

Skipping an intervening control-plane release is not supported. Operators must
upgrade through each consecutive supported release and take a verified backup
before every schema-changing step. Offline CLI artifacts do not require a
database migration, but their Agent BOM and finding contracts still follow
[Compatibility and versioning](COMPATIBILITY.md).

There is no supported skip-version path in the first-beta contract.

## Offline CLI

| Platform | Architecture | Beta status | Boundary |
| --- | --- | --- | --- |
| Linux | amd64 | Supported | Release archive and source build |
| Linux | arm64 | Supported | Release archive; hosted execution must pass for the candidate |
| macOS | amd64 | Supported | Release archive and hosted native tests |
| macOS | arm64 | Supported | Release archive and hosted cross-build/native compatibility gate |
| Windows | amd64 | Supported | Release archive and hosted native tests |
| Windows | arm64 | Not supported | No release artifact or retained runtime evidence |

The supported source-build baseline is Go 1.26.10. The reviewed container build
currently uses Go 1.27.3. Other Go major/minor lines are not compatibility
claims merely because the source happens to compile with them.

The supported offline surface includes repository discovery, Agent BOM
generation, findings, semantic diff, policy checks, and local HTML/SARIF/JSON
reporting. These commands do not require PostgreSQL, Kubernetes, a provider
credential, or an AI model.

## Single-replica control plane

| Component | Beta status | Supported reference | Boundary |
| --- | --- | --- | --- |
| Server OS | Supported | Linux amd64 | Native binary; literal loopback listener only |
| Replicas | Supported | Exactly one | Multi-replica and HA are experimental |
| PostgreSQL | Supported | 17.4 | Other major/minor versions require new retained evidence |
| Database transport | Supported | TLS with certificate and hostname verification | Insecure mode is development-only |
| OPA | Supported | 1.21.3 static | Reviewed local policy or bundle; fail closed when unavailable |
| OpenTelemetry Collector | Validated integration | 0.123.0 | External backend compatibility is not a general support claim |
| General-purpose OCI server image | Not supported | None | The published container contract is the GitHub Action image |

The API supports static environment Bearer credentials and the versioned
multi-credential registry with explicit scopes and optional repository grants.
OIDC authentication is not implemented and is not part of the first beta.
Filesystem credential reload exists, but external secret-provider adapters and
provider-driven rotation remain outside the support promise.

The measured single-host performance envelope is documented in
[Performance evidence](PERFORMANCE.md). It is specific to the declared Docker
Desktop allocation and is not an availability SLO or a universal capacity
guarantee.

## Repository providers

| Connector or credential | Beta status | Boundary |
| --- | --- | --- |
| Local repository connector | Supported | Clean absolute local directory; read-only scan materialization |
| GitHub App installation authentication | Supported with limitations | Installation exchange, cache reuse, private ingestion, unchanged revision, and invalid installation are validated |
| GitHub PAT | Not supported | Public/private parity and fresh real-provider evidence are incomplete |
| GitLab or other hosted providers | Not supported | No operational connector contract |

GitHub App expiry-driven provider refresh, redirect, cancellation, and rate
limit observations remain release-candidate evidence items. Until those pass,
the feature must not be described as resilient to every provider failure mode.

## Kubernetes and availability

No Kubernetes version is in the first-beta support matrix. The single-replica
Kustomize base is an evaluation contract, not a supported distribution. It has
passed admission/readiness on Docker Desktop and network-policy behavior on
Kind v1.32.2 with Calico v3.32.1, but certificate rotation, disruption,
resource pressure, rollout rollback, and a generally published server image
remain incomplete.

The two-replica overlay, scheduler leader selection, lease takeover, rolling
mixed-version operation, failover, disaster recovery, and multi-region
deployment are experimental or not supported. Their presence in source does
not expand the beta promise.

## Upgrade, backup, and rollback

The supported first-beta database upgrade is the tested consecutive path from
`v0.5.0-alpha` schema version 2 through the first-beta migration set. Startup
applies forward migrations transactionally under an advisory lock and rejects
unknown, missing, or modified migration records.

The supported backup is a complete custom-format logical dump made with
PostgreSQL 17 client tools and verified by restoring into a new empty database.
Application rollback after a schema change requires restoring the verified
pre-upgrade backup and starting the older binary against that restored
database. In-place schema downgrade, deleted migration-ledger rows,
mixed-version rolling upgrade, physical backup, PITR, and skip-version upgrade
are not supported.

## Explicitly outside the first beta

- production high availability or a multi-replica support promise;
- non-loopback direct HTTP exposure;
- OIDC authentication;
- GitHub PAT and non-GitHub hosted providers;
- Kubernetes as a supported runtime distribution;
- PostgreSQL versions other than the exact 17.4 reference;
- general-purpose server container publication;
- skip-version or mixed-version upgrades;
- physical backup, point-in-time recovery, or a production RPO/RTO;
- universal throughput, latency, tenant-count, or availability guarantees.
