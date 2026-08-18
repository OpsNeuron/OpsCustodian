package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestReadOnlyAPIListsRepositoriesFindingsAndLatestBOM(t *testing.T) {
	memory := store.NewMemory()
	bom := serverTestBOM()
	snapshot, err := memory.PutSnapshot(context.Background(), bom)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(memory, "v0.5.0-test")

	repositories := performRequest(t, handler, http.MethodGet, "/api/v1/repositories")
	assertResponse(t, repositories, http.StatusOK, `"apiVersion":"`+contracts.ControlPlaneAPIVersion+`"`, `"latestRevision":"abc123"`, `"findingCount":1`)

	findings := performRequest(t, handler, http.MethodGet, "/api/v1/findings?severity=critical&repositoryId="+snapshot.RepositoryID)
	assertResponse(t, findings, http.StatusOK, `"id":"finding-server"`, `"remediationId":"kubernetes.reduce-rbac-privileges"`)

	latest := performRequest(t, handler, http.MethodGet, "/api/v1/repositories/"+snapshot.RepositoryID+"/bom")
	assertResponse(t, latest, http.StatusOK, `"repositoryId":"`+snapshot.RepositoryID+`"`, `"revision":"abc123"`)
}

func TestReadOnlyAPIExposesContractsAndSecurityHeaders(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "v0.5.0-test")
	response := performRequest(t, handler, http.MethodGet, "/api/v1/contracts")
	assertResponse(t, response, http.StatusOK, `"version":"v0.5.0-test"`, `"controlPlane":"`+contracts.ControlPlaneAPIVersion+`"`)
	for name, expected := range map[string]string{
		"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
	} {
		if actual := response.Header().Get(name); actual != expected {
			t.Errorf("%s = %q, want %q", name, actual, expected)
		}
	}
}

func TestReadOnlyAPIRejectsInvalidFiltersPathsAndMutation(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "dev")
	tests := []struct {
		method, path, code string
		status             int
	}{
		{http.MethodGet, "/api/v1/findings?severity=urgent", "invalid-severity", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/repositories/not-an-id/bom", "invalid-repository-id", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/repositories/repository-0000000000000000/bom", "repository-not-found", http.StatusNotFound},
		{http.MethodPost, "/api/v1/repositories", "", http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		response := performRequest(t, handler, test.method, test.path)
		if response.Code != test.status {
			t.Errorf("%s %s status = %d, want %d: %s", test.method, test.path, response.Code, test.status, response.Body.String())
		}
		if test.code != "" && !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
			t.Errorf("%s %s missing code %s: %s", test.method, test.path, test.code, response.Body.String())
		}
	}
}

func TestReadOnlyAPIUsesExplicitEmptyArrays(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "dev")
	for _, path := range []string{"/api/v1/repositories", "/api/v1/findings"} {
		response := performRequest(t, handler, http.MethodGet, path)
		var envelope struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Items == nil || len(envelope.Items) != 0 {
			t.Errorf("%s did not return an explicit empty array: %s, %v", path, response.Body.String(), err)
		}
	}
}

func performRequest(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertResponse(t *testing.T, response *httptest.ResponseRecorder, status int, fragments ...string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	for _, fragment := range fragments {
		if !strings.Contains(response.Body.String(), fragment) {
			t.Errorf("response missing %s: %s", fragment, response.Body.String())
		}
	}
}

func serverTestBOM() model.AgentBOM {
	asset := model.Asset{
		ID: "role:admin", Type: "authorization-role", Name: "admin", Source: model.Source{Path: "rbac.yaml"},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{{ID: "role-evidence", Path: "rbac.yaml", Parser: "test", Confidence: "high"}},
	}
	return model.AgentBOM{
		APIVersion: model.APIVersion, Kind: model.Kind,
		Metadata: model.DocumentMetadata{Source: "github:acme/platform", Revision: "abc123", NormalizationVersion: "v1alpha1"},
		Assets:   []model.Asset{asset},
		Findings: []model.Finding{{
			ID: "finding-server", Type: "kubernetes-rbac-privilege-escalation", Severity: "critical", AssetID: asset.ID,
			Title: "Role can escalate", Reason: "Role grants bind.", RemediationID: "kubernetes.reduce-rbac-privileges", Remediation: "Remove bind.",
			Evidence: []model.FindingEvidence{{AssetID: asset.ID, EvidenceID: "role-evidence"}},
		}},
	}
}
