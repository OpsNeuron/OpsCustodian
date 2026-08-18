package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecisionNormalizeProducesStableContract(t *testing.T) {
	decision := Decision{
		Deny: []Message{{Rule: "require-approval", Title: "Approval required", Message: "production writes require approval", AgentID: "agent:deployer"}},
		Warn: []Message{{Rule: "pin-mcp", Title: "MCP server is unpinned", Message: "pin the server version"}},
	}

	decision.Normalize()
	if decision.Deny[0].Severity != "high" || decision.Warn[0].Severity != "medium" {
		t.Fatalf("unexpected default severities: %#v", decision)
	}
	if !strings.HasPrefix(decision.Deny[0].ID, "policy-") || !strings.HasPrefix(decision.Warn[0].ID, "policy-") {
		t.Fatalf("expected generated policy finding IDs: %#v", decision)
	}
	if err := decision.Validate(); err != nil {
		t.Fatalf("normalized decision should be valid: %v", err)
	}

	repeated := Decision{
		Deny: []Message{{Rule: "require-approval", Title: "Approval required", Message: "production writes require approval", AgentID: "agent:deployer"}},
		Warn: []Message{{Rule: "pin-mcp", Title: "MCP server is unpinned", Message: "pin the server version"}},
	}
	repeated.Normalize()
	if !reflect.DeepEqual(decision, repeated) {
		t.Fatalf("normalization is not deterministic:\nfirst:  %#v\nsecond: %#v", decision, repeated)
	}
}

func TestDecisionValidateRejectsBrokenContracts(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		contains string
	}{
		{name: "missing arrays", decision: Decision{}, contains: "deny and warn arrays"},
		{name: "missing required message fields", decision: Decision{Deny: []Message{{Severity: "high"}}, Warn: []Message{}}, contains: "rule, title, and message"},
		{name: "unsupported severity", decision: Decision{Deny: []Message{{Rule: "r", Title: "t", Message: "m", Severity: "urgent"}}, Warn: []Message{}}, contains: "unsupported severity"},
		{name: "invalid remediation ID", decision: Decision{Deny: []Message{{Rule: "r", Title: "t", Message: "m", Severity: "high", RemediationID: "Invalid Value"}}, Warn: []Message{}}, contains: "invalid remediation ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.decision.Validate()
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.contains)
			}
		})
	}
}
