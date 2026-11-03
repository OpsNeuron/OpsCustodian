# Compatibility and versioning

OpsCustodian versions data contracts independently from the executable. Use
machine-readable build information to discover the contracts supported by a
binary:

```bash
opscustodian version --format json
```

The registry currently reports Agent BOM, normalization, findings, policy
input, audit-event, control-plane API, and SARIF versions from one source of
truth.

## Agent BOM reader rules

- `apiVersion` and `kind` must exactly match a supported contract.
- The offline scanner always emits an explicit supported
  `metadata.normalizationVersion`.
- An empty normalization version remains readable for legacy pre-versioned
  v1alpha1 documents.
- A non-empty unknown normalization version is rejected. Comparing BOMs built
  with unknown normalization semantics could otherwise create false drift.
- Runtime readers tolerate unknown additive JSON/YAML fields within v1alpha1 so
  an older CLI can consume a document enriched by a newer compatible producer.
  The published schema remains strict for producers and conformance testing.

## Change rules

- New optional fields and new enum-like values may be added during alpha.
- Removing or changing the meaning or type of a field requires a new contract
  version and migration guidance.
- `remediationId` values are stable automation keys and are never reused for a
  different outcome.
- Finding IDs remain stable while their semantic identity and normalization
  version are unchanged.
- A change to normalization or Finding identity rules increments the
  normalization version even when the Agent BOM envelope is unchanged.

Before the first stable release, alpha consumers should pin the OpsCustodian
binary and validate golden artifacts during upgrades. Stable releases will
publish an explicit support window and migration policy.

Beta releases freeze the core semantic contracts except for changes delivered
through a new contract version with tested migration guidance. See the
[release maturity gates](ROADMAP.md#release-maturity-gates) for the evidence
required to enter beta and stable stages. The platform, dependency, provider,
and upgrade boundaries for the first beta are defined in the
[Beta support matrix](BETA_SUPPORT_MATRIX.md). The exact machine-readable
interface inventory and change procedure are maintained in the
[First-beta contract freeze](BETA_CONTRACT_FREEZE.md).
