# OpsCustodian <tag>

Summarize the evidence-backed change from `<previous-release>` without making
production-readiness or high-availability claims.

## Supported beta contract

Describe the supported offline CLI platforms and the narrow single-replica
control-plane reference. Link to
[Beta support matrix](../BETA_SUPPORT_MATRIX.md) and
[First-beta threat model](../THREAT_MODEL.md). State which provider,
authentication, Kubernetes, and HA modes are not supported.

## Upgrade and rollback

Name the exact supported source release and state that only a consecutive
upgrade is supported. Summarize the verified backup, migration, validation, and
restore-based rollback procedure. Link to [Upgrades](../UPGRADES.md) and
[Backup and restore](../BACKUP_RESTORE.md).

## Included changes

List user-visible capabilities and fixes that are present in this exact tag.
Separate implementation from environment-backed validation.

## Known limitations

List release-specific limitations in addition to the support matrix. Keep the
single-replica and non-HA boundary explicit and do not imply that configuration
analysis is a live authorization decision.

## Installation and verification

List the supported archives and require verification of `SHA256SUMS`, the
CycloneDX SBOM, and build provenance before running `opscustodian version`.

## Feedback wanted

Request sanitized evidence and prohibit credentials, private keys, signed URLs,
private repository content, and customer data in public issues.
