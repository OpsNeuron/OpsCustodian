# Relationship graph

OpsCustodian correlates typed assets with the operational objects they use. The
graph is serialized directly in Agent BOM under `relationships`, allowing CLI,
policy, SARIF, Backstage, and future UI clients to consume the same evidence.

## Relationship shape

```json
{
  "id": "relation-a1b2c3d4e5f6",
  "from": "agent-markdown:AGENTS.md",
  "type": "depends-on",
  "to": "agent-markdown:.codex/skills/deployment-review/SKILL.md",
  "targetType": "asset",
  "confidence": "high",
  "evidenceIds": ["agent-markdown:AGENTS.md"]
}
```

IDs are derived from source, relationship type, and target, so equivalent scans
produce stable relationships independent of ordering.

## Relationship types

- `uses-tool`: an asset declares a tool.
- `uses-mcp-server`: an asset declares an MCP server.
- `uses-credential`: an asset references a credential name, never its value.
- `depends-on`: an asset depends on another skill or agentic asset.
- `owned-by`: an asset declares an owner.

## Target resolution

When the target asset is present in the same BOM, `targetType` is `asset` and
`to` contains its stable asset ID. When a declared skill or MCP server is absent,
the relationship is preserved as `asset-reference`. This makes incomplete
inventories visible instead of silently discarding dependencies.

External targets use canonical prefixes:

```text
tool:<tool-type>:<reference>
credential:<credential-type>:<reference>
owner:<owner-name>
```

## Evidence and confidence

Every relationship originates from a source asset and references evidence owned
by that asset. Validation rejects relationships with missing source assets,
invalid resolved targets, duplicate IDs, unsupported types, or foreign evidence.

## Drift behavior

For assets present in both baseline and proposed BOMs, OpsCustodian reports added
or removed tool, MCP, dependency, and ownership relationships. Credential drift
continues to use the dedicated credential finding to avoid duplicate alerts.
Relationships belonging to a wholly new or deleted asset are not reported again,
because the asset-level finding already represents that change.

## Current limits

- Matching is by normalized asset type and name within one BOM.
- Relationships do not yet cross repository boundaries.
- Runtime-discovered edges are not yet available.
- Natural-language prose is not mined for implicit dependencies.
- Alias, version constraint, and transitive dependency resolution are deferred.
