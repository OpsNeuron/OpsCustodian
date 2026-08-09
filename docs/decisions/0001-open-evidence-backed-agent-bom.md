# ADR 0001: Open, evidence-backed Agent BOM

- Status: Accepted
- Date: 2026-08-09

## Context

Agent configuration is distributed across vendor-specific files and runtime
systems. Semantic drift and policy cannot be reliable if the core model is tied
to one vendor, loses its source provenance, or captures sensitive values.

## Decision

OpsCustodian will use a versioned, vendor-neutral Agent Bill of Materials as its
primary interchange contract.

- Every inferred relationship must be traceable to evidence.
- Confidence is explicit when a fact is inferred rather than declared.
- Credential references are modeled; credential values are forbidden.
- Vendor-specific observations are normalized to canonical capabilities while
  their raw provenance remains available.
- The schema is part of the open-source core and is not a commercial boundary.
- Semantic diff and policy evaluation consume the normalized model rather than
  reparsing source artifacts independently.

## Consequences

Parsers require more discipline than flat pattern matching, but findings become
explainable and comparable across platforms. Schema evolution must be versioned,
and normalization changes must be identifiable for reproducibility. Other tools
can consume Agent BOM documents without depending on the OpsCustodian CLI.

## Revisit conditions

Revisit this decision only if real integrations demonstrate that the Agent BOM
cannot represent evidence or effective access without unsafe data capture or
vendor-specific coupling.
