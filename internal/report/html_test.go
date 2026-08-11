package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestWriteInventoryHTMLRendersSafeSelfContainedAccessPaths(t *testing.T) {
	bom := reportTestBOM()
	var output bytes.Buffer
	if err := WriteInventoryHTML(&output, bom); err != nil {
		t.Fatalf("write HTML report: %v", err)
	}
	html := output.String()

	assertHTMLContains(t, html,
		`id="path-search"`, `id="path-effect"`, `id="path-escalation"`,
		`data-query=`, `&rarr;`, `&middot;`, `querySelectorAll('.access-path')`,
		`&lt;script&gt;alert(1)&lt;/script&gt;`, `kubernetes:cluster/*/*`,
	)
	if strings.Contains(html, "#ZgotmplZ") {
		t.Fatal("report contains html/template sanitization sentinel #ZgotmplZ")
	}
	if strings.Contains(html, `<script>alert(1)</script>`) {
		t.Fatal("dynamic asset name was rendered as executable markup")
	}
	if count := strings.Count(html, `<article class="access-path"`); count != 2 {
		t.Fatalf("expected two access path cards, got %d", count)
	}
	if count := strings.Count(html, `data-escalation="true"`); count != 1 {
		t.Fatalf("expected one escalation card, got %d", count)
	}
	if count := strings.Count(html, `data-escalation="false"`); count != 1 {
		t.Fatalf("expected one ordinary card, got %d", count)
	}
	externalResource := regexp.MustCompile(`(?i)(?:src|href)=["'](?:https?:)?//`)
	if externalResource.MatchString(html) {
		t.Fatal("self-contained report contains an external script or stylesheet reference")
	}
}

func TestAccessPathEscalationClassification(t *testing.T) {
	tests := []struct {
		name       string
		capability model.Capability
		expected   bool
	}{
		{name: "read", capability: model.Capability{Action: "kubernetes.pods.get", Resource: "kubernetes:production/pods/app", Effect: "read"}},
		{name: "admin", capability: model.Capability{Action: "kubernetes.pods.update", Resource: "kubernetes:production/pods/app", Effect: "admin"}, expected: true},
		{name: "wildcard action", capability: model.Capability{Action: "kubernetes.*.*", Resource: "kubernetes:cluster", Effect: "read"}, expected: true},
		{name: "wildcard resource", capability: model.Capability{Action: "kubernetes.pods.get", Resource: "kubernetes:production/pods/*", Effect: "read"}, expected: true},
		{name: "bind", capability: model.Capability{Action: "kubernetes.roles.bind", Resource: "kubernetes:cluster/roles/app", Effect: "execute"}, expected: true},
		{name: "escalate", capability: model.Capability{Action: "kubernetes.roles.escalate", Resource: "kubernetes:cluster/roles/app", Effect: "execute"}, expected: true},
		{name: "impersonate", capability: model.Capability{Action: "kubernetes.users.impersonate", Resource: "kubernetes:cluster/users/app", Effect: "execute"}, expected: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := accessPathEscalation(test.capability); actual != test.expected {
				t.Fatalf("accessPathEscalation() = %t, expected %t", actual, test.expected)
			}
		})
	}
}

func reportTestBOM() model.AgentBOM {
	maliciousName := `<script>alert(1)</script>`
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: "test", Revision: "test", NormalizationVersion: "v1alpha1"},
		Assets: []model.Asset{
			{ID: "workload:test", Type: "workload", Name: maliciousName, Source: model.Source{Path: "runtime.yaml"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "workload-evidence", Path: "runtime.yaml", Parser: "test", Confidence: "high"}}},
			{ID: "identity:test", Type: "identity", Name: "agent", Source: model.Source{Path: "runtime.yaml"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "identity-evidence", Path: "runtime.yaml", Parser: "test", Confidence: "high"}}},
			{ID: "binding:test", Type: "authorization-binding", Name: "binding", Source: model.Source{Path: "rbac.yaml"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "binding-evidence", Path: "rbac.yaml", Parser: "test", Confidence: "high"}}},
			{ID: "role:test", Type: "authorization-role", Name: "role", Source: model.Source{Path: "rbac.yaml"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "role-evidence", Path: "rbac.yaml", Parser: "test", Confidence: "high"}}},
		},
		AccessPaths: []model.AccessPath{
			{ID: "access-path-read", Origin: "workload:test", Confidence: "high", Steps: reportPathSteps(), Capability: model.Capability{Action: "kubernetes.pods.get", Resource: "kubernetes:production/pods/app", Effect: "read", Environment: "production"}},
			{ID: "access-path-admin", Origin: "workload:test", Confidence: "high", Steps: reportPathSteps(), Capability: model.Capability{Action: "kubernetes.*.*", Resource: "kubernetes:cluster/*/*", Effect: "admin", Environment: "cluster"}},
		},
	}
}

func reportPathSteps() []model.AccessPathStep {
	return []model.AccessPathStep{
		{Kind: "origin", AssetID: "workload:test"},
		{Kind: "principal", AssetID: "identity:test"},
		{Kind: "grant", AssetID: "binding:test"},
		{Kind: "entitlement", AssetID: "role:test"},
	}
}

func assertHTMLContains(t *testing.T, html string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(html, value) {
			t.Errorf("HTML report does not contain %q", value)
		}
	}
}
