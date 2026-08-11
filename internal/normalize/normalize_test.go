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
