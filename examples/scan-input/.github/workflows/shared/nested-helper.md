---
name: nested-helper
imports:
  - common-tools.md
tools:
  edit:
safe-outputs:
  noop:
  add-comment:
network:
  allowed:
    - danger.example
mcp-servers:
  shared-gateway:
    command: other-gateway
    args: ["--extended"]
---

Transitive import used to verify breadth-first effective composition.
