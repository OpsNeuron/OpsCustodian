package drift

import (
	"reflect"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestCompareClassifiesSemanticEscalationWithStableEvidence(t *testing.T) {
	before := driftBOM("baseline", []model.Asset{
		driftAgent([]model.Capability{{
			Action:      "kubernetes.deployments.update",
			Resource:    "kubernetes:production/apps/deployments/payments",
			Effect:      "write",
			Environment: "production",
			EvidenceIDs: []string{"baseline-capability"},
			Scope:       &model.Scope{Kind: "kubernetes", Values: []string{"production", "apps", "deployments", "payments"}},
		}}, nil, []model.Control{{Type: "humanApproval", Value: true}}, []model.Evidence{
			{ID: "baseline-capability", Path: "k8s/baseline.yaml", Line: 12, Parser: "test", Confidence: "high"},
		}),
	})
	after := driftBOM("proposed", []model.Asset{
		driftAgent([]model.Capability{{
			Action:      "kubernetes.deployments.update",
			Resource:    "kubernetes:production/*",
			Effect:      "admin",
			Environment: "production",
			EvidenceIDs: []string{"proposed-capability"},
			Scope:       &model.Scope{Kind: "kubernetes", Values: []string{"production"}, Wildcard: true},
		}}, []model.CredentialReference{{Type: "kubernetes-secret", Reference: "production/deployer-token"}}, nil, []model.Evidence{
			{ID: "proposed-capability", Path: "k8s/proposed.yaml", Line: 27, Column: 5, Parser: "test", Confidence: "high"},
		}),
	})

	report := Compare(before, after)
	if report.BeforeRevision != "baseline" || report.AfterRevision != "proposed" {
		t.Fatalf("unexpected revisions: %#v", report)
	}
	if len(report.Changes) != 3 {
		t.Fatalf("expected escalation, credential, and control changes, got %#v", report.Changes)
	}

	escalation := requireChange(t, report, "capability-escalated", "kubernetes.deployments.update")
	if escalation.Severity != "critical" || escalation.Risk.Score != 100 {
		t.Fatalf("expected critical 100/100 escalation, got %#v", escalation.Risk)
	}
	if !strings.Contains(escalation.Reason, "effect increased from write to admin") || !strings.Contains(escalation.Reason, "wildcard") {
		t.Fatalf("expected effect and scope explanations, got %q", escalation.Reason)
	}
	wantLocations := []Location{{Path: "k8s/proposed.yaml", Line: 27, Column: 5}}
	if !reflect.DeepEqual(escalation.Locations, wantLocations) {
		t.Fatalf("locations = %#v, want %#v", escalation.Locations, wantLocations)
	}
	if escalation.ID == "" {
		t.Fatal("expected a stable finding ID")
	}
	if found, ok := Find(report, escalation.ID); !ok || !reflect.DeepEqual(found, escalation) {
		t.Fatalf("Find() did not return escalation %q", escalation.ID)
	}

	repeated := Compare(before, after)
	if !reflect.DeepEqual(report, repeated) {
		t.Fatalf("Compare() is not deterministic:\nfirst:  %#v\nsecond: %#v", report, repeated)
	}
	for _, change := range report.Changes {
		if change.ID == "" {
			t.Fatalf("change has no stable ID: %#v", change)
		}
	}
}

func TestCompareReportsAssetCapabilityAndRelationshipLifecycle(t *testing.T) {
	source := driftAgent([]model.Capability{{
		Action: "github.issues.read", Resource: "github:acme/platform/issues", Effect: "read",
		EvidenceIDs: []string{"old-capability"},
	}}, nil, nil, []model.Evidence{
		{ID: "old-capability", Path: ".github/agents/deployer.md", Line: 8, Parser: "test", Confidence: "high"},
		{ID: "relationship", Path: "k8s/binding.yaml", Line: 19, Parser: "test", Confidence: "high"},
	})
	target := model.Asset{ID: "identity:old", Type: "identity", Name: "old", Source: model.Source{Path: "k8s/old.yaml"}}
	removed := model.Asset{ID: "agent:removed", Type: "agent", Name: "removed", Source: model.Source{Path: "agents/removed.md"}}
	added := model.Asset{ID: "agent:added", Type: "agent", Name: "added", Source: model.Source{Path: "agents/added.md"}}

	before := driftBOM("before", []model.Asset{source, target, removed})
	before.Relationships = []model.Relationship{{
		ID: "runs-as:old", From: source.ID, Type: "runs-as", To: target.ID,
		TargetType: "asset", Confidence: "high", EvidenceIDs: []string{"relationship"},
	}}
	after := driftBOM("after", []model.Asset{
		driftAgent(nil, nil, nil, source.Evidence),
		{ID: "identity:new", Type: "identity", Name: "new", Source: model.Source{Path: "k8s/new.yaml"}},
		added,
	})
	after.Relationships = []model.Relationship{{
		ID: "runs-as:new", From: source.ID, Type: "runs-as", To: "identity:new",
		TargetType: "asset", Confidence: "high", EvidenceIDs: []string{"relationship"},
	}}

	report := Compare(before, after)
	for _, expected := range []struct{ changeType, subject string }{
		{"asset-added", "added"},
		{"asset-added", "new"},
		{"asset-removed", "removed"},
		{"asset-removed", "old"},
		{"capability-removed", "github.issues.read"},
		{"relationship-added", "runs-as"},
		{"relationship-removed", "runs-as"},
	} {
		requireChange(t, report, expected.changeType, expected.subject)
	}
	if len(report.Changes) != 7 {
		t.Fatalf("expected exactly 7 lifecycle findings, got %#v", report.Changes)
	}
}

func driftBOM(revision string, assets []model.Asset) model.AgentBOM {
	return model.AgentBOM{
		APIVersion: "opscustodian.dev/v1alpha1",
		Kind:       "AgentBOM",
		Metadata:   model.DocumentMetadata{Revision: revision},
		Assets:     assets,
	}
}

func driftAgent(capabilities []model.Capability, credentials []model.CredentialReference, controls []model.Control, evidence []model.Evidence) model.Asset {
	return model.Asset{
		ID: "agent:deployer", Type: "agent", Name: "deployer",
		Source:       model.Source{Path: ".github/agents/deployer.md"},
		Capabilities: capabilities, Credentials: credentials, Controls: controls, Evidence: evidence,
	}
}

func requireChange(t *testing.T, report Report, changeType, subject string) Change {
	t.Helper()
	for _, change := range report.Changes {
		if change.Type == changeType && change.Subject == subject {
			return change
		}
	}
	t.Fatalf("missing %s change for %q in %#v", changeType, subject, report.Changes)
	return Change{}
}
