# Explainable risk model

Risk scoring prioritizes semantic drift. It does not allow or deny changes;
OPA/Rego policy remains the authorization mechanism.

## Output

Each drift finding carries:

```json
{
  "score": 85,
  "level": "critical",
  "factors": [
    {"name": "effect", "score": 60, "reason": "capability effect is delete"},
    {"name": "production", "score": 20, "reason": "capability targets a production context"},
    {"name": "high-confidence", "score": 5, "reason": "finding is backed by explicit configuration"}
  ]
}
```

Scores are clamped to 0–100 and mapped to levels:

- `0–14`: info
- `15–34`: low
- `35–59`: medium
- `60–79`: high
- `80–100`: critical

## Current factors

- Capability effect: observe, read, execute, write, delete, admin, or unknown.
- Production or staging target.
- Wildcard action or resource scope.
- Effect escalation and canonical resource-scope expansion.
- Credential presence and production-indicating credential names.
- Human approval and safe-output controls as risk reductions.
- Evidence confidence.
- MCP, tool, dependency, unresolved target, and ownership relationship changes.
- Removal or weakening of approval, network, and safe-output controls.

## Design constraints

- Every score contribution is returned as a factor.
- Negative factors represent explicit guardrails, not assumed safety.
- No model or LLM assigns severity.
- Secret values never participate in scoring.
- Policy can deny any score and remains authoritative.
- Weights are pre-alpha and require fixture calibration before compatibility promises.

## Planned improvements

- Organization-configurable weight profiles.
- Canonical environment sensitivity rather than name heuristics.
- Provider-aware resource breadth and cross-repository scope sets.
- Effective identity privileges from GitHub, Kubernetes, and cloud connectors.
- Confidence-aware policy thresholds and false-positive feedback.
