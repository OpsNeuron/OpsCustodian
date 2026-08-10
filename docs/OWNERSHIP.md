# Ownership resolution

OpsCustodian resolves zero or more owners for each agentic asset. Explicit
frontmatter owners take precedence. When no explicit owner exists, the scanner
uses the selected GitHub CODEOWNERS file.

## CODEOWNERS selection

The first existing file in GitHub's precedence order is used:

1. `.github/CODEOWNERS`
2. `CODEOWNERS` at repository root
3. `docs/CODEOWNERS`

Paths are case-sensitive. Within the selected file, the last matching rule wins.
A matching pattern with no owners explicitly leaves the asset unowned.

## Evidence

Inferred ownership adds evidence containing the CODEOWNERS path, line, pattern,
and high confidence. `owned-by` graph relationships point to this evidence rather
than the asset definition when ownership came from CODEOWNERS.

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
