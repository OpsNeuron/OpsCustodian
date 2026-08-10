# Canonical normalization

OpsCustodian compares effective access rather than source-file spelling. Before
validation, graph correlation, and drift analysis, every Agent BOM is passed
through the same deterministic normalization layer. This applies both to newly
scanned repositories and to previously saved baselines.

## Current contract

- Actions are lowercase dot-separated identifiers; hyphens inside segments are
  converted to underscores.
- Effects and environments are lowercase.
- Resource path separators use `/`.
- Owners, references, credentials, and evidence IDs are deduplicated and sorted.
- Import reference identity includes locator, optionality, and canonical JSON
  parameters so conflicting parameterized imports are not collapsed.
- Import references sort by their explicit declaration order before their
  canonical reference key.
- Capabilities are sorted by action, resource, effect, and environment.
- A canonical `scope` is inferred from the resource when a parser does not
  provide one.

Supported scope kinds are `repository`, `organization`, `kubernetes`,
`network`, `workspace`, `mcp-server`, and `unknown`. Scope retains ordered path
segments and whether the declaration contains a wildcard.

## Semantic escalation

For the same normalized action, drift is reported as `capability-escalated`
instead of an unrelated removal plus addition when:

- the effect becomes stronger (`observe < read < execute < write < delete < admin`), or
- the scope gains a wildcard, or moves from a child path to one of its parents.

Escalation findings include the old and new value, an explicit reason, source
evidence, and separate risk factors for effect escalation and scope expansion.

## Compatibility status

This is a pre-alpha contract. Prefix-based scope comparison is intentionally
conservative and does not yet model provider-specific resource hierarchies,
set-based repository lists, exclusions, or runtime authorization. Those require
fixture calibration and connector-specific effective-access work before a
compatibility guarantee can be published.
