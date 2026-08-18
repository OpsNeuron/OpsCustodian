package opscustodian

import rego.v1

test_critical_current_state_finding_is_denied if {
    result := decision with input as finding_input("critical")
    count(result.deny) == 1
    result.deny[0].rule == "current-state-critical-finding"
    result.deny[0].remediationId == "kubernetes.reduce-rbac-privileges"
    result.deny[0].evidenceIds == ["role-evidence"]
}

test_high_current_state_finding_warns if {
    result := decision with input as finding_input("high")
    count(result.deny) == 0
    count(result.warn) == 1
    result.warn[0].rule == "current-state-high-finding"
}

test_medium_current_state_finding_does_not_gate if {
    result := decision with input as finding_input("medium")
    count(result.deny) == 0
    count(result.warn) == 0
}

finding_input(severity) := {
    "apiVersion": "opscustodian.dev/policy-input/v1alpha1",
    "bom": {
        "assets": [],
        "findings": [{
            "id": "finding-policy-test",
            "type": "kubernetes-rbac-privilege-escalation",
            "severity": severity,
            "assetId": "kubernetes:role:production/admin",
            "title": "Role can escalate privileges",
            "reason": "The role grants bind.",
            "remediationId": "kubernetes.reduce-rbac-privileges",
            "remediation": "Remove bind access.",
            "evidence": [{"assetId": "role:admin", "evidenceId": "role-evidence"}],
        }],
    },
}
