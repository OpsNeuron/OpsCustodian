---
name: limits
import-schema:
  type: object
  additionalProperties: false
  required: [max-items, enabled]
  properties:
    max-items:
      type: integer
    enabled:
      type: boolean
---

Shared parameter contract used by the OpsCustodian compatibility fixture.
