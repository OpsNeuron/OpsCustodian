package validation

import (
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestValidateAcceptsEvidenceBackedAccessPath(t *testing.T) {
	if issues := Validate(validAccessPathBOM()); len(issues) != 0 {
		t.Fatalf("expected valid BOM, got %#v", issues)
	}
}

func TestValidateRejectsBrokenAccessPathContracts(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*model.AgentBOM)
	}{
		{name: "duplicate id", code: "duplicate", edit: func(bom *model.AgentBOM) { bom.AccessPaths = append(bom.AccessPaths, bom.AccessPaths[0]) }},
		{name: "unknown origin", code: "unknown-origin-asset", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Origin = "missing" }},
		{name: "invalid first step", code: "invalid-origin-step", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Steps[0].Kind = "principal" }},
		{name: "incomplete steps", code: "incomplete-access-path", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Steps = bom.AccessPaths[0].Steps[:1] }},
		{name: "unknown step asset", code: "unknown-step-asset", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Steps[1].AssetID = "missing" }},
		{name: "invalid step kind", code: "invalid-step-kind", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Steps[1].Kind = "permission" }},
		{name: "incomplete capability", code: "incomplete-capability", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Capability.Action = "" }},
		{name: "invalid confidence", code: "invalid-confidence", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Confidence = "certain" }},
		{name: "foreign evidence", code: "unknown-evidence", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].EvidenceIDs = []string{"foreign-evidence"} }},
		{name: "foreign capability evidence", code: "unknown-evidence", edit: func(bom *model.AgentBOM) { bom.AccessPaths[0].Capability.EvidenceIDs = []string{"foreign-evidence"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bom := validAccessPathBOM()
			test.edit(&bom)
			issues := Validate(bom)
			if !hasIssueCode(issues, test.code) {
				t.Fatalf("expected issue code %q, got %#v", test.code, issues)
			}
		})
	}
}

func validAccessPathBOM() model.AgentBOM {
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: "test", Revision: "test"},
		Assets: []model.Asset{
			{ID: "identity:agent", Type: "identity", Name: "agent", Source: model.Source{Path: "runtime.yaml"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "identity-evidence", Path: "runtime.yaml", Parser: "test", Confidence: "high"}}},
			{ID: "role:reader", Type: "authorization-role", Name: "reader", Source: model.Source{Path: "rbac.yaml"}, Capabilities: []model.Capability{{Action: "kubernetes.pods.get", Resource: "kubernetes:production/core/pods/*", Effect: "read", EvidenceIDs: []string{"role-evidence"}}}, Evidence: []model.Evidence{{ID: "role-evidence", Path: "rbac.yaml", Parser: "test", Confidence: "high"}}},
		},
		AccessPaths: []model.AccessPath{{
			ID: "access-path-test", Origin: "identity:agent", Confidence: "high",
			Steps:       []model.AccessPathStep{{Kind: "origin", AssetID: "identity:agent"}, {Kind: "entitlement", AssetID: "role:reader"}},
			Capability:  model.Capability{Action: "kubernetes.pods.get", Resource: "kubernetes:production/core/pods/*", Effect: "read", EvidenceIDs: []string{"role-evidence"}},
			EvidenceIDs: []string{"role-evidence"},
		}},
	}
}

func hasIssueCode(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
