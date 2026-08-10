# Parser extension contract

First-party parsers implement the deliberately small internal interface:

```go
type Parser interface {
    Name() string
    Supports(discovery.Artifact) bool
    Parse(context.Context, discovery.Artifact) ([]model.Agent, error)
}
```

`Supports` identifies artifacts without network access or filesystem mutation.
`Parse` interprets only the supplied artifact and returns deterministic assets.
Cross-artifact resolution belongs in normalization, effective-access, ownership,
or correlation passes rather than parser-specific global state.

## Enforced registry rules

- Names match `^[a-z][a-z0-9-]*$` and remain stable across releases.
- Each parser name is registered once.
- A nil parser is invalid.
- Registry violations stop the scan because parser attribution would be
  ambiguous.

## Enforced result rules

Every emitted asset must have:

- A stable non-empty ID, supported type, and human-readable name.
- A source path equal to the artifact being parsed.
- At least one evidence record with a unique non-empty ID.
- Evidence whose `parser` equals `Parser.Name()` and whose path equals the
  artifact path.
- Capability evidence IDs that resolve inside the asset.
- Credential references only; `valueCaptured` must remain false.

An invalid asset is discarded and produces a `parser-contract-violation`
diagnostic. Other valid assets from the scan remain available. Duplicate asset
IDs across parsers produce `duplicate-asset-id` and the later asset is discarded.

## Error behavior

- Malformed supported input: return an error. Scanner emits
  `artifact-parse-failed` and continues.
- Unsupported input: `Supports` returns false.
- Discovery or registry integrity failure: fail the scan.
- Partial guesses must use evidence confidence rather than silently asserting
  high-confidence access.

## Contribution checklist

1. Add the parser under `internal/parsers/<ecosystem>`.
2. Register it explicitly in `internal/app`.
3. Add safe, malformed, and permission-expansion fixtures.
4. Verify deterministic JSON across repeated scans.
5. Document normalized mappings and known limitations.
6. Never capture credential values, invoke repository code, or require network
   access during an offline scan.

The interface remains internal during pre-alpha. A public parser SDK will be
introduced only after compatibility fixtures establish which contracts can be
stabilized without freezing implementation details prematurely.
