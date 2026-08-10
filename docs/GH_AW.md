# GitHub Agentic Workflows coverage

OpsCustodian discovers source workflows under `.github/workflows/*.md`. These
files contain YAML frontmatter and Markdown instructions and are compiled by
`gh aw` into `.lock.yml` GitHub Actions workflows.

## Normalized fields

- `name` and optional `owner`.
- `engine` as an execution control.
- GitHub `permissions` as canonical capabilities.
- `id-token: write` as OIDC token request, not repository write.
- `copilot-requests: write` as AI inference, not repository write.
- `safe-outputs` as gated write capabilities and a safety control.
- Built-in tools, custom MCP servers, and secret references.
- Declared skills as dependencies.
- Allowed network destinations as capabilities.
- Allowed and blocked network configuration as controls.
- `bash` and `edit` as shell execution and filesystem modification capabilities.
- Frontmatter imports in scalar and parameterized `uses`/`path` forms.
- Custom agent imports under `.github/agents/` as agent dependencies.
- Markdown `#import` and `#runtime-import` directives as dependencies.
- Companion `resources` as explicit unresolved resource dependencies.

Files without an `on` field are classified as shared `workflow` assets rather
than runnable agents. Local imports therefore resolve through the Agent BOM
relationship graph when their imported file is also discovered. Remote,
missing, runtime-only, and non-workflow resources remain visible as unresolved
typed references.

## Effective import composition

The first conservative composition pass follows resolved local shared-workflow
dependencies transitively. It inherits declared tools, MCP references,
credential references, network access, shell/edit capabilities, and safe-output
capabilities. Imported evidence is copied with each inherited capability.

GitHub repository permissions are validation-only under gh-aw semantics. They
are never granted to the caller by OpsCustodian. An imported permission that is
not sufficiently declared by the caller produces a
`GHAW_IMPORT_PERMISSION_UNSATISFIED` diagnostic. Active traversal cycles produce
`GHAW_IMPORT_CYCLE`; repeated imports already processed through another branch
are deduplicated rather than treated as cycles.

Import references retain their original locator, optional marker, and
`with`/`inputs` parameters in the Agent BOM. A required unresolved local
workflow produces `GHAW_IMPORT_UNRESOLVED`; an optional unresolved import does
not. Reusing the same resolved workflow with different parameter values produces
`GHAW_IMPORT_PARAMETER_CONFLICT`, matching the compiler's single-import rule.

Discovered shared workflows also retain `import-schema` as a typed control. The
composition pass validates required parameters, unknown parameters when
`additionalProperties: false`, JSON-compatible types, and enum membership.
Failures use the `GHAW_IMPORT_PARAMETER_REQUIRED`, `_UNKNOWN`, `_TYPE`, and
`_ENUM` diagnostic codes and never prevent the remaining inventory from being
produced.

## Evidence policy

Frontmatter is explicit configuration and receives high confidence. The Markdown
instruction body is retained as source evidence but is not interpreted as an
authorization grant. This avoids converting natural-language mentions into
effective permissions.

## Source and compiled workflow

The source `.md` asset and compiled `.lock.yml` workflow may both appear in Agent
BOM. They represent different layers: declared agent intent and effective GitHub
Actions configuration. Correlating these two layers and detecting compiler drift
is planned but not yet implemented.

## Current limitations

- Field-level first-wins precedence and conflict reporting are not complete.
- Existing-file checks for runtime imports, section selection, schema defaults,
  unions, nested object constraints, and string/number bounds are not evaluated yet.
- Tool-specific nested restrictions are not fully normalized.
- Effective defaults may change with the `gh-aw` version and are not version-pinned yet.
- Compilation has not been invoked as part of scanning.
- The parser is pending validation against the upstream JSON Schema and real repositories.
