package opscustodian

import rego.v1

default decision := {"deny": [], "warn": []}

decision := {
    "deny": [item | item := deny[_]],
    "warn": [item | item := warn[_]],
}

deny contains {
    "rule": "production-destructive-access-requires-approval",
    "title": "Destructive production access has no human approval",
    "message": sprintf("Agent %q can perform %s on %s without an approval control.", [agent.name, capability.action, capability.resource]),
    "severity": "critical",
    "agentId": agent.id,
    "remediation": "Add a humanApproval control or reduce the capability scope and effect.",
    "evidenceIds": object.get(capability, "evidenceIds", []),
} if {
    some agent in input.bom.assets
    some capability in agent.capabilities
    capability.environment == "production"
    capability.effect in {"delete", "admin"}
    not has_human_approval(agent)
}

deny contains {
    "rule": "new-production-credential-requires-review",
    "title": "Agent gained a production credential reference",
    "message": sprintf("A new credential reference %q was added to agent %q.", [change.subject, change.agentId]),
    "severity": "high",
    "agentId": change.agentId,
    "remediation": "Remove the credential or obtain approval from the platform security owner.",
} if {
    input.drift
    some change in input.drift.changes
    change.type == "credential-added"
    contains(upper(change.subject), "PROD")
}

warn contains {
    "rule": "agent-owner-required",
    "title": "Agent has no declared owner",
    "message": sprintf("Agent %q does not have an owner.", [agent.name]),
    "severity": "medium",
    "agentId": agent.id,
    "remediation": "Declare an owner directly or provide ownership through CODEOWNERS correlation.",
} if {
    some agent in input.bom.assets
    object.get(agent, "owner", "") == ""
}

has_human_approval(agent) if {
    some control in object.get(agent, "controls", [])
    control.type == "humanApproval"
}
