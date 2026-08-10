---
name: common-tools
import-schema:
  type: object
  additionalProperties: false
  required: [mode]
  properties:
    mode:
      type: string
      enum: [read-only]
imports:
  - nested-helper.md
tools:
  bash:
    - gh issue view
  github:
    allowed:
      - issue_read
mcp-servers:
  shared-gateway:
    command: gateway
    env:
      GATEWAY_TOKEN: ${{ secrets.GATEWAY_TOKEN }}
network:
  allowed:
    - github
permissions:
  issues: write
safe-outputs:
  noop:
---

Shared read-only tooling for issue workflows.
