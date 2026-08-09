# Agentic asset model

OpsCustodian inventories more than executable agents. The `assets` collection in
Agent BOM is a typed, vendor-neutral envelope for operationally relevant
agentic configuration.

## Asset types

- `agent`: an explicitly defined AI agent.
- `workflow`: an automated CI/CD workflow with agent-like operational authority.
- `mcp-server`: a configured MCP tool provider.
- `skill`: a reusable agent capability or instruction package.
- `instruction-set`: repository or editor instructions that influence agent behavior.

All asset types share identity, ownership, source, runtime, tools, capabilities,
controls, and evidence. Optional fields are omitted when they do not apply.

## Why one envelope?

A skill can add a tool to an agent; an MCP server exposes executable tools; a
workflow supplies credentials and runtime permissions; and an instruction file
can alter behavior. They differ in type but participate in the same access graph
and drift analysis. A shared envelope allows correlation without discarding type.

## Inference rules

- Explicit frontmatter has `high` confidence.
- Filename, path, and ecosystem convention inference has `medium` confidence.
- Markdown prose is not interpreted as permission by the initial parser.
- Tools are extracted only from recognized frontmatter keys.
- Secret values and arbitrary environment values are never extracted from prose.

The conservative approach intentionally misses some undeclared authority rather
than treating natural-language mentions as effective access. Runtime connectors
will later provide stronger evidence.

## Current discovery coverage

- `AGENTS.md`
- `CLAUDE.md`
- `.github/agents/*.md` and `*.mdc`
- `.codex/skills/**/SKILL.md`
- `.claude/skills/**/SKILL.md`
- `.agents/skills/**/SKILL.md`
- `.cursor/rules/*.md` and `*.mdc`

Recognized frontmatter fields include `name`, `title`, `owner`, `maintainer`,
`model`, `tools`, `allowed-tools`, `allowedTools`, `mcp-servers`, and
`mcpServers`. Unknown fields remain ignored until their semantics are normalized.

## Pre-alpha compatibility

Early development builds emitted a top-level `agents` array. The reader migrates
those documents in memory to `assets` and infers a missing type from runtime
metadata. New output emits only `assets`. This compatibility bridge will be
removed or formalized before the first stable schema guarantee.
