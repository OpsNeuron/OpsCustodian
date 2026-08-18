package normalize

import (
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestBOMNormalizesAccessPathCapability(t *testing.T) {
	bom := model.AgentBOM{AccessPaths: []model.AccessPath{{
		ID: "path", Origin: "asset", Confidence: "high",
		Capability: model.Capability{
			Action: " Kubernetes.Pods.Get ", Resource: `kubernetes:Production\core\pods\*`, Effect: " READ ", Environment: " Production ",
			EvidenceIDs: []string{"evidence-b", "evidence-a", "evidence-b"},
		},
	}}}

	BOM(&bom)

	capability := bom.AccessPaths[0].Capability
	if capability.Action != "kubernetes.pods.get" || capability.Resource != "kubernetes:Production/core/pods/*" || capability.Effect != "read" || capability.Environment != "production" {
		t.Fatalf("unexpected normalized capability %#v", capability)
	}
	if capability.Scope == nil || capability.Scope.Kind != "kubernetes" || !capability.Scope.Wildcard || !reflect.DeepEqual(capability.Scope.Values, []string{"Production", "core", "pods"}) {
		t.Fatalf("unexpected inferred scope %#v", capability.Scope)
	}
	if !reflect.DeepEqual(capability.EvidenceIDs, []string{"evidence-a", "evidence-b"}) {
		t.Fatalf("unexpected evidence IDs %#v", capability.EvidenceIDs)
	}
}

func TestBOMDeduplicatesCapabilitiesAndRetainsEvidence(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{{
		ID: "asset", Type: "workload", Name: "asset",
		Capabilities: []model.Capability{
			{Action: "Kubernetes.Pods.Get", Resource: "kubernetes:production/core/pods/*", Effect: "READ", Environment: "Production", EvidenceIDs: []string{"evidence-a"}},
			{Action: "kubernetes.pods.get", Resource: "kubernetes:production/core/pods/*", Effect: "read", Environment: "production", EvidenceIDs: []string{"evidence-b"}},
		},
	}}}

	BOM(&bom)

	if len(bom.Assets[0].Capabilities) != 1 {
		t.Fatalf("expected one capability, got %#v", bom.Assets[0].Capabilities)
	}
	if !reflect.DeepEqual(bom.Assets[0].Capabilities[0].EvidenceIDs, []string{"evidence-a", "evidence-b"}) {
		t.Fatalf("expected merged evidence, got %#v", bom.Assets[0].Capabilities[0].EvidenceIDs)
	}
}

func TestBOMDeduplicatesFindingsRetainsEvidenceAndHighestSeverity(t *testing.T) {
	base := model.Finding{
		ID: "finding-stable", Type: "kubernetes-rbac-privilege-escalation", AssetID: "role:admin",
		Title: "Role can escalate", Reason: "Role grants bind.", RemediationID: "kubernetes.reduce-rbac-privileges",
		Remediation: "Remove bind.", Attributes: map[string]any{"signals": []string{"bind"}},
	}
	low := base
	low.Severity = "medium"
	low.Evidence = []model.FindingEvidence{{AssetID: "role:admin", EvidenceID: "evidence-b"}}
	high := base
	high.Severity = "critical"
	high.Evidence = []model.FindingEvidence{
		{AssetID: "role:admin", EvidenceID: "evidence-a"},
		{AssetID: "role:admin", EvidenceID: "evidence-b"},
	}
	bom := model.AgentBOM{Findings: []model.Finding{low, high}}

	BOM(&bom)

	if len(bom.Findings) != 1 || bom.Findings[0].Severity != "critical" {
		t.Fatalf("expected one critical finding, got %#v", bom.Findings)
	}
	expectedEvidence := []model.FindingEvidence{
		{AssetID: "role:admin", EvidenceID: "evidence-a"},
		{AssetID: "role:admin", EvidenceID: "evidence-b"},
	}
	if !reflect.DeepEqual(bom.Findings[0].Evidence, expectedEvidence) {
		t.Fatalf("expected merged deterministic evidence, got %#v", bom.Findings[0].Evidence)
	}
}

func TestBOMPreservesConflictingFindingIdentityForValidation(t *testing.T) {
	first := model.Finding{ID: "finding-collision", Type: "type-a", AssetID: "asset", Severity: "high", Title: "A", Reason: "A", RemediationID: "test.fix-a", Remediation: "A"}
	second := model.Finding{ID: "finding-collision", Type: "type-b", AssetID: "asset", Severity: "high", Title: "B", Reason: "B", RemediationID: "test.fix-b", Remediation: "B"}
	bom := model.AgentBOM{Findings: []model.Finding{second, first}}

	BOM(&bom)

	if len(bom.Findings) != 2 || bom.Findings[0].Type != "type-a" || bom.Findings[1].Type != "type-b" {
		t.Fatalf("conflicting identities must remain deterministic and visible to validation: %#v", bom.Findings)
	}
}

func TestBOMPreservesInvalidFindingSeverityForValidation(t *testing.T) {
	valid := model.Finding{ID: "finding", Type: "type", AssetID: "asset", Severity: "high", Title: "Title", Reason: "Reason", RemediationID: "test.fix", Remediation: "Fix"}
	invalid := valid
	invalid.Severity = "urgent"
	bom := model.AgentBOM{Findings: []model.Finding{valid, invalid}}

	BOM(&bom)

	if len(bom.Findings) != 2 {
		t.Fatalf("invalid severity must remain visible to validation: %#v", bom.Findings)
	}
}
