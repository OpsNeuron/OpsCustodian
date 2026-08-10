---
name: AI issue triage
owner: developer-experience
engine: codex
imports:
  - .github/agents/issue-reviewer.md
  - uses: shared/common-tools.md
    with:
      mode: read-only
  - uses: shared/common-tools.md
    with:
      mode: write
  - shared/optional-observability.md?
  - uses: shared/limits.md
    with:
      max-items: many
      unexpected: true
resources:
  - shared/helper-action.yml
on:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: read
tools:
  github:
    allowed:
      - issue_read
      - list_labels
  web-search:
mcp-servers:
  production-observer:
    command: production-observer
    args: ["--read-only"]
    env:
      OBSERVABILITY_TOKEN: ${{ secrets.OBSERVABILITY_TOKEN }}
skills:
  - .codex/skills/deployment-review/SKILL.md
network:
  allowed:
    - defaults
    - github
  blocked:
    - danger.example
safe-outputs:
  add-comment:
---

# Issue triage

{{#runtime-import .github/shared/triage-guidelines.md}}

Read the new issue, identify its type and urgency, and propose a helpful comment.
Use only the declared safe output to write back to GitHub.
