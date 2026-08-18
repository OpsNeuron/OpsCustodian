package effective

import (
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestComposeKubernetesRBACSpecializesScopeAndBuildsPaths(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		role("kubernetes:role:cluster/reader", "cluster/reader", []model.Capability{
			{Action: "kubernetes.pods.get", Resource: "kubernetes:cluster/reader/core/pods/*", Effect: "read", Environment: "cluster", EvidenceIDs: []string{"role-evidence"}},
			{Action: "kubernetes.non_resource_url.get", Resource: "kubernetes:cluster/non-resource-url/healthz", Effect: "read", Environment: "cluster", EvidenceIDs: []string{"role-evidence"}},
		}),
		binding("kubernetes:binding:production/reader", "production/reader", "cluster/reader", "production/agent"),
		identity("kubernetes:service-account:production/agent", "production/agent", false),
		workload("kubernetes:workload:production/deployment/agent", "production/deployment/agent", "production/agent", true),
	}}

	ComposeKubernetesRBAC(&bom)

	for _, assetID := range []string{"kubernetes:service-account:production/agent", "kubernetes:workload:production/deployment/agent"} {
		asset := assetByID(t, &bom, assetID)
		assertCapability(t, asset, "kubernetes.pods.get", "kubernetes:production/core/pods/*")
		assertNoCapability(t, asset, "kubernetes.non_resource_url.get", "kubernetes:cluster/non-resource-url/healthz")
	}
	if countDiagnostics(bom.Diagnostics, "KUBERNETES_RBAC_NON_RESOURCE_URL_NAMESPACED") != 1 {
		t.Fatalf("expected one namespaced non-resource URL diagnostic, got %#v", bom.Diagnostics)
	}
	if countDiagnostics(bom.Diagnostics, "KUBERNETES_RBAC_PRIVILEGE_ESCALATION") != 0 || countDiagnostics(bom.Diagnostics, "KUBERNETES_EFFECTIVE_ACCESS_EXPANSION") != 0 {
		t.Fatalf("ordinary all-object read access was classified as privilege escalation: %#v", bom.Diagnostics)
	}
	if len(bom.AccessPaths) != 2 {
		t.Fatalf("expected identity and workload access paths, got %d", len(bom.AccessPaths))
	}
	for _, path := range bom.AccessPaths {
		if path.Capability.Resource != "kubernetes:production/core/pods/*" {
			t.Fatalf("unexpected effective path resource %q", path.Capability.Resource)
		}
	}
}

func TestComposeKubernetesRBACAppliesWorkloadTokenPrecedence(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		identity("kubernetes:service-account:production/agent", "production/agent", false),
		workload("kubernetes:workload:production/deployment/agent", "production/deployment/agent", "production/agent", true),
	}}

	ComposeKubernetesRBAC(&bom)

	asset := assetByID(t, &bom, "kubernetes:workload:production/deployment/agent")
	assertCapability(t, asset, "kubernetes.service_account_token.use", "kubernetes:service-account/production/agent")
	control := controlByType(t, asset.Controls, "effectiveServiceAccountToken")
	value, ok := control.Value.(map[string]any)
	if !ok || value["enabled"] != true || value["source"] != "workload" {
		t.Fatalf("unexpected effective token control %#v", control.Value)
	}
	finding := findingByType(t, bom.Findings, "kubernetes-service-account-token-exposure", asset.ID)
	if finding.Severity != "medium" || finding.Attributes["source"] != "workload" {
		t.Fatalf("unexpected token exposure finding: %#v", finding)
	}
}

func TestComposeKubernetesRBACEmitsStructuredEffectiveAccessFinding(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		role("kubernetes:role:cluster/admin", "cluster/admin", []model.Capability{{
			Action: "kubernetes.*.*", Resource: "kubernetes:cluster/*/*/*", Effect: "admin", Environment: "cluster", EvidenceIDs: []string{"role-evidence"},
		}}),
		binding("kubernetes:binding:cluster/admin", "cluster/admin", "cluster/admin", "production/agent"),
		identity("kubernetes:service-account:production/agent", "production/agent", false),
	}}

	ComposeKubernetesRBAC(&bom)

	if len(bom.Findings) != 2 {
		t.Fatalf("expected role and effective-access findings, got %#v", bom.Findings)
	}
	finding := findingByType(t, bom.Findings, "kubernetes-effective-access-expansion", "kubernetes:service-account:production/agent")
	if finding.Type != "kubernetes-effective-access-expansion" || finding.Severity != "critical" || finding.AssetID != "kubernetes:service-account:production/agent" || finding.ID == "" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	foundRoleEvidence := false
	for _, reference := range finding.Evidence {
		if reference.AssetID == "kubernetes:role:cluster/admin" && reference.EvidenceID == "role-evidence" {
			foundRoleEvidence = true
		}
	}
	if !foundRoleEvidence {
		t.Fatalf("finding does not point to the granting role evidence: %#v", finding.Evidence)
	}
	if finding.Attributes["inheritedCapabilityCount"] != 1 || finding.Attributes["maxInheritedEffect"] != "admin" {
		t.Fatalf("unexpected structured finding attributes: %#v", finding.Attributes)
	}
	roleFinding := findingByType(t, bom.Findings, "kubernetes-rbac-privilege-escalation", "kubernetes:role:cluster/admin")
	if roleFinding.Severity != "critical" || len(roleFinding.Evidence) != 1 {
		t.Fatalf("unexpected RBAC escalation finding: %#v", roleFinding)
	}
}

func TestComposeKubernetesRBACEmitsProjectedTokenRiskFinding(t *testing.T) {
	asset := workload("kubernetes:workload:production/deployment/agent", "production/deployment/agent", "production/agent", false)
	asset.Controls = append(asset.Controls, model.Control{Type: "serviceAccountTokenProjection", Value: map[string]any{
		"audience": "kubernetes-default", "expirationSeconds": 86400, "mountedBy": []string{"agent"},
	}})
	bom := model.AgentBOM{Assets: []model.Asset{asset, identity("kubernetes:service-account:production/agent", "production/agent", false)}}

	ComposeKubernetesRBAC(&bom)

	finding := findingByType(t, bom.Findings, "kubernetes-projected-token-risk", asset.ID)
	if finding.Severity != "high" || finding.Attributes["expirationSeconds"] != 86400 {
		t.Fatalf("unexpected projected token finding: %#v", finding)
	}
	signals := finding.Attributes["signals"].([]string)
	if len(signals) != 2 || signals[0] != "default-audience" || signals[1] != "long-lived" {
		t.Fatalf("unexpected projected token signals: %#v", signals)
	}
}

func TestComposeKubernetesRBACAggregatesRolesAndReportsCycle(t *testing.T) {
	source := role("kubernetes:role:cluster/jobs-reader", "cluster/jobs-reader", []model.Capability{{
		Action: "kubernetes.jobs.get", Resource: "kubernetes:cluster/jobs-reader/batch/jobs/*", Effect: "read", Environment: "cluster", EvidenceIDs: []string{"role-evidence"},
	}})
	source.Controls = append(source.Controls, model.Control{Type: "kubernetesLabels", Value: map[string]string{"access": "reader"}})
	aggregate := role("kubernetes:role:cluster/observer", "cluster/observer", nil)
	aggregate.Controls = append(aggregate.Controls, aggregationControl("access", "reader"))
	cycleA := role("kubernetes:role:cluster/cycle-a", "cluster/cycle-a", nil)
	cycleA.Controls = append(cycleA.Controls,
		model.Control{Type: "kubernetesLabels", Value: map[string]string{"cycle": "a"}}, aggregationControl("cycle", "b"))
	cycleB := role("kubernetes:role:cluster/cycle-b", "cluster/cycle-b", nil)
	cycleB.Controls = append(cycleB.Controls,
		model.Control{Type: "kubernetesLabels", Value: map[string]string{"cycle": "b"}}, aggregationControl("cycle", "a"))
	bom := model.AgentBOM{Assets: []model.Asset{
		source, aggregate, cycleA, cycleB,
		binding("kubernetes:binding:cluster/observer", "cluster/observer", "cluster/observer", "production/agent"),
		identity("kubernetes:service-account:production/agent", "production/agent", false),
	}}

	ComposeKubernetesRBAC(&bom)

	assertCapability(t, assetByID(t, &bom, "kubernetes:role:cluster/observer"), "kubernetes.jobs.get", "kubernetes:cluster/observer/batch/jobs/*")
	assertCapability(t, assetByID(t, &bom, "kubernetes:service-account:production/agent"), "kubernetes.jobs.get", "kubernetes:cluster/batch/jobs/*")
	if countDiagnostics(bom.Diagnostics, "KUBERNETES_AGGREGATION_CYCLE") != 1 {
		t.Fatalf("expected one aggregation cycle diagnostic, got %#v", bom.Diagnostics)
	}
	cycleControl := controlByType(t, assetByID(t, &bom, "kubernetes:role:cluster/cycle-a").Controls, "kubernetesAggregationCycle")
	value := cycleControl.Value.(map[string]any)
	roles := value["roles"].([]string)
	if got := roles[0] + " -> " + roles[1] + " -> " + roles[2]; got != "cluster/cycle-a -> cluster/cycle-b -> cluster/cycle-a" {
		t.Fatalf("unexpected canonical cycle %q", got)
	}
}

func role(id, name string, capabilities []model.Capability) model.Asset {
	return model.Asset{ID: id, Type: "authorization-role", Name: name, Source: model.Source{Path: "rbac.yaml"}, Capabilities: capabilities, Evidence: []model.Evidence{{ID: "role-evidence", Path: "rbac.yaml", Parser: "kubernetes", Confidence: "high"}}}
}

func binding(id, name, roleName, identityName string) model.Asset {
	return model.Asset{ID: id, Type: "authorization-binding", Name: name, Source: model.Source{Path: "rbac.yaml"}, Dependencies: []model.Reference{{Type: "authorization-role", Reference: roleName}}, Identities: []model.Reference{{Type: "identity", Reference: identityName}}, Evidence: []model.Evidence{{ID: "binding-evidence-" + name, Path: "rbac.yaml", Parser: "kubernetes", Confidence: "high"}}}
}

func identity(id, name string, automount bool) model.Asset {
	return model.Asset{ID: id, Type: "identity", Name: name, Source: model.Source{Path: "runtime.yaml"}, Controls: []model.Control{{Type: "automountServiceAccountToken", Value: automount}}, Evidence: []model.Evidence{{ID: "identity-evidence", Path: "runtime.yaml", Parser: "kubernetes", Confidence: "high"}}}
}

func workload(id, name, identityName string, automount bool) model.Asset {
	return model.Asset{ID: id, Type: "workload", Name: name, Source: model.Source{Path: "runtime.yaml"}, Identities: []model.Reference{{Type: "identity", Reference: identityName}}, Controls: []model.Control{{Type: "automountServiceAccountToken", Value: automount}}, Evidence: []model.Evidence{{ID: "workload-evidence", Path: "runtime.yaml", Parser: "kubernetes", Confidence: "high"}}}
}

func aggregationControl(key, value string) model.Control {
	return model.Control{Type: "kubernetesAggregationRule", Value: []map[string]any{{"matchLabels": map[string]string{key: value}}}}
}

func assetByID(t *testing.T, bom *model.AgentBOM, id string) *model.Asset {
	t.Helper()
	for index := range bom.Assets {
		if bom.Assets[index].ID == id {
			return &bom.Assets[index]
		}
	}
	t.Fatalf("asset %s not found", id)
	return nil
}

func controlByType(t *testing.T, controls []model.Control, controlType string) model.Control {
	t.Helper()
	for _, control := range controls {
		if control.Type == controlType {
			return control
		}
	}
	t.Fatalf("control %s not found", controlType)
	return model.Control{}
}

func assertCapability(t *testing.T, asset *model.Asset, action, resource string) {
	t.Helper()
	for _, capability := range asset.Capabilities {
		if capability.Action == action && capability.Resource == resource {
			return
		}
	}
	t.Fatalf("capability %s on %s not found in %#v", action, resource, asset.Capabilities)
}

func assertNoCapability(t *testing.T, asset *model.Asset, action, resource string) {
	t.Helper()
	for _, capability := range asset.Capabilities {
		if capability.Action == action && capability.Resource == resource {
			t.Fatalf("unexpected capability %s on %s", action, resource)
		}
	}
}

func countDiagnostics(diagnostics []model.Diagnostic, code string) int {
	count := 0
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			count++
		}
	}
	return count
}

func findingByType(t *testing.T, findings []model.Finding, findingType, assetID string) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Type == findingType && finding.AssetID == assetID {
			return finding
		}
	}
	t.Fatalf("finding %s for %s not found in %#v", findingType, assetID, findings)
	return model.Finding{}
}
