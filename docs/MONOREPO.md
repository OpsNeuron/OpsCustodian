# Monorepo boundaries

Repository scans can assign discovered assets to logical components using
repeatable `--boundary` flags:

```bash
opscustodian scan \
  --boundary services/payments=payments \
  --boundary services/search=search \
  --boundary .github=repository-automation \
  --output agentbom.json .
```

Each value is `path` or `path=component`. Without an explicit name, the final
path segment becomes the component name. Paths are repository-relative and use
`/` after normalization.

## Resolution rules

- The longest matching path wins, allowing a nested component to override a
  broader boundary.
- Component assignment is deterministic and stored on each Agent BOM asset.
- Assets outside every configured boundary remain valid with no component.
- Empty, absolute, duplicate, root, and parent-escaping paths are rejected.
- Boundaries classify assets; they do not change filesystem traversal,
  CODEOWNERS precedence, evidence paths, or policy decisions.

This explicit CLI contract is the first monorepo surface. Configuration-file
loading and automatic Backstage component boundaries remain planned.
