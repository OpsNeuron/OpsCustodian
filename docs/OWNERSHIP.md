# Ownership resolution

OpsCustodian resolves zero or more owners for each agentic asset. Explicit
frontmatter owners take precedence. When no explicit owner exists, the scanner
uses the longest matching Backstage Component scope and then falls back to the
selected GitHub CODEOWNERS file.

## Backstage components

Files named `catalog-info.yaml` or `catalog-info.yml` are read offline. Documents
with `kind: Component` contribute `metadata.name` as component identity and
`spec.owner` as ownership. Multi-document YAML is supported.

The catalog file's directory is its source scope. Nested component scopes win
over broader scopes. Backstage sets `component` when it is otherwise empty and
sets owners only when the asset has no explicit owner. A CLI `--boundary`
classification runs later and may override the component label, but never the
Backstage owner.

Malformed catalogs and Components missing `metadata.name` or `spec.owner`
produce diagnostics without hiding other inventory. Backstage-derived ownership
adds high-confidence evidence pointing to the catalog owner field.

## CODEOWNERS selection

The first existing file in GitHub's precedence order is used:

1. `.github/CODEOWNERS`
2. `CODEOWNERS` at repository root
3. `docs/CODEOWNERS`

Paths are case-sensitive. Within the selected file, the last matching rule wins.
A matching pattern with no owners explicitly leaves the asset unowned.

## Evidence

Inferred ownership adds high-confidence evidence. `owned-by` graph relationships
point to the Backstage or CODEOWNERS evidence rather than the asset definition.

## Supported pattern behavior

The initial matcher supports root anchoring, `*`, `**`, `?`, basename patterns,
directory patterns, multiple owners, inline comments, and last-match precedence.
Unsupported negation, character ranges, and escaped leading comments generate
diagnostics and are skipped.

This is a security-sensitive compatibility surface. The matcher is pending a
golden compatibility suite against GitHub behavior. Until that passes,
OpsCustodian ownership is advisory and must not be the sole approval authority.

## Approval semantics

Multiple owners are retained as distinct values. OpsCustodian does not currently
verify that a GitHub user or team exists or has write access; that requires an
optional GitHub API connector in the effective-access phase.
