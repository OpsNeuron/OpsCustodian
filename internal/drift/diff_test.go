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

func TestCompareReportsAccessPathEscalationRerouteAndLifecycle(t *testing.T) {
	assets := []model.Asset{
		{ID: "workflow:caller", Type: "workflow", Name: "caller", Source: model.Source{Path: ".github/workflows/caller.yml"}, Evidence: []model.Evidence{{ID: "caller-evidence", Path: ".github/workflows/caller.yml", Line: 10, Parser: "test", Confidence: "high"}}},
		{ID: "workflow:middle", Type: "workflow", Name: "middle", Source: model.Source{Path: ".github/workflows/middle.yml"}, Evidence: []model.Evidence{{ID: "middle-evidence", Path: ".github/workflows/middle.yml", Line: 20, Parser: "test", Confidence: "high"}}},
		{ID: "workflow:replacement", Type: "workflow", Name: "replacement", Source: model.Source{Path: ".github/workflows/replacement.yml"}, Evidence: []model.Evidence{{ID: "replacement-evidence", Path: ".github/workflows/replacement.yml", Line: 30, Parser: "test", Confidence: "high"}}},
	}
	read := model.Capability{Action: "github.contents.*", Resource: "github:repository", Effect: "read", EvidenceIDs: []string{"caller-evidence"}}
	write := read
	write.Effect = "write"
	baseline := model.AgentBOM{Metadata: model.DocumentMetadata{Revision: "baseline"}, Assets: assets, AccessPaths: []model.AccessPath{
		accessPathFixture("path-escalate", read, "workflow:middle"),
		accessPathFixture("path-reroute", model.Capability{Action: "github.issues.*", Resource: "github:repository", Effect: "read", EvidenceIDs: []string{"caller-evidence"}}, "workflow:middle"),
		accessPathFixture("path-remove", model.Capability{Action: "github.actions.*", Resource: "github:repository", Effect: "read", EvidenceIDs: []string{"caller-evidence"}}, "workflow:middle"),
	}}
	proposed := model.AgentBOM{Metadata: model.DocumentMetadata{Revision: "proposed"}, Assets: assets, AccessPaths: []model.AccessPath{
		accessPathFixture("different-id", write, "workflow:middle"),
		accessPathFixture("different-id", model.Capability{Action: "github.issues.*", Resource: "github:repository", Effect: "read", EvidenceIDs: []string{"caller-evidence"}}, "workflow:replacement"),
		accessPathFixture("path-added", model.Capability{Action: "github.oidc_token.issue", Resource: "github:oidc-token", Effect: "execute", EvidenceIDs: []string{"caller-evidence"}}, "workflow:middle"),
	}}

	report := Compare(baseline, proposed)
	escalated := requireChange(t, report, "access-path-escalated", "github.contents.*")
	if escalated.Severity != "critical" || escalated.Risk.Score != 90 {
		t.Fatalf("unexpected access path escalation: %#v", escalated)
	}
	rerouted := requireChange(t, report, "access-path-rerouted", "github.issues.*")
	if rerouted.After == rerouted.Before || len(rerouted.Locations) == 0 {
		t.Fatalf("reroute lacks path or evidence detail: %#v", rerouted)
	}
	requireChange(t, report, "access-path-added", "github.oidc_token.issue")
	requireChange(t, report, "access-path-removed", "github.actions.*")

	if repeated := Compare(baseline, proposed); !reflect.DeepEqual(report, repeated) {
		t.Fatalf("access path drift is not deterministic:\nfirst: %#v\nsecond: %#v", report, repeated)
	}
}

func TestCompareSuppressesOpaqueReusableCompositionControlDrift(t *testing.T) {
	asset := model.Asset{ID: "workflow:caller", Type: "workflow", Name: "caller", Source: model.Source{Path: "caller.yml"}, Evidence: []model.Evidence{{ID: "e", Path: "caller.yml", Parser: "test", Confidence: "high"}}}
	beforeAsset, afterAsset := asset, asset
	beforeAsset.Controls = []model.Control{{Type: "githubReusableWorkflowComposition", Value: []string{"before"}}}
	afterAsset.Controls = []model.Control{{Type: "githubReusableWorkflowComposition", Value: []string{"after"}}}
	report := Compare(model.AgentBOM{Assets: []model.Asset{beforeAsset}}, model.AgentBOM{Assets: []model.Asset{afterAsset}})
	if len(report.Changes) != 0 {
		t.Fatalf("derived composition emitted opaque control drift: %#v", report.Changes)
	}
}

func accessPathFixture(id string, capability model.Capability, delegation string) model.AccessPath {
	return model.AccessPath{
		ID: id, Origin: "workflow:caller", Confidence: "high",
		Steps:      []model.AccessPathStep{{Kind: "origin", AssetID: "workflow:caller"}, {Kind: "delegation", AssetID: delegation}},
		Capability: capability, EvidenceIDs: append([]string(nil), capability.EvidenceIDs...),
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
