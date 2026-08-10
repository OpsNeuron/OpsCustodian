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
tools:
  bash:
    - gh issue view
  github:
    allowed:
      - issue_read
network:
  allowed:
    - github
permissions:
  issues: write
safe-outputs:
  noop:
---

Shared read-only tooling for issue workflows.
