package server

import (
	"bytes"
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
	previous := serverTestBOM()
	previous.Metadata.Revision = "before"
	previous.Metadata.GeneratedAt = "2026-08-17T00:00:00Z"
	previous.Findings[0].ID = "finding-before"
	if _, err := memory.PutSnapshot(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	bom.Metadata.GeneratedAt = "2026-08-18T00:00:00Z"
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
	assertResponse(t, latest, http.StatusOK, `"repositoryId":"`+snapshot.RepositoryID+`"`, `"snapshotId":"`+snapshot.SnapshotID+`"`, `"revision":"abc123"`)

	history := performRequest(t, handler, http.MethodGet, "/api/v1/repositories/"+snapshot.RepositoryID+"/snapshots?limit=1")
	assertResponse(t, history, http.StatusOK, `"generatedAt":"2026-08-17T00:00:00Z"`, `"nextCursor":`)
	var page struct {
		Items      []store.SnapshotSummary `json:"items"`
		NextCursor string                  `json:"nextCursor"`
	}
	if err := json.Unmarshal(history.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("invalid history page: %s, %v", history.Body.String(), err)
	}
	next := performRequest(t, handler, http.MethodGet, "/api/v1/repositories/"+snapshot.RepositoryID+"/snapshots?limit=1&cursor="+page.NextCursor)
	assertResponse(t, next, http.StatusOK, `"revision":"abc123"`)
	specific := performRequest(t, handler, http.MethodGet, "/api/v1/repositories/"+snapshot.RepositoryID+"/snapshots/"+snapshot.SnapshotID+"/bom")
	assertResponse(t, specific, http.StatusOK, `"snapshotId":"`+snapshot.SnapshotID+`"`)
	lifecycle := performRequest(t, handler, http.MethodGet, "/api/v1/finding-lifecycles?repositoryId="+snapshot.RepositoryID+"&status=introduced")
	assertResponse(t, lifecycle, http.StatusOK, `"findingId":"finding-server"`, `"status":"introduced"`, `"firstObservedAt":"2026-08-18T00:00:00Z"`)
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

func TestSnapshotIngestionRequiresWriteScopeAndPersistsRepository(t *testing.T) {
	memory := store.NewMemory()
	readToken := "snapshot-read-token-0123456789abcdefghijkl"
	writeToken := "snapshot-write-token-0123456789abcdefghijk"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{
		{ID: "inventory-reader", Token: readToken, Scopes: []string{ScopeInventoryRead}},
		{ID: "snapshot-writer", Token: writeToken, Scopes: []string{ScopeSnapshotsWrite}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(memory, "test", &authenticator, &authorizer)
	content, _ := json.Marshal(serverTestBOM())

	denied := httptest.NewRequest(http.MethodPost, "/api/v1/snapshots", bytes.NewReader(content))
	denied.Header.Set("Authorization", "Bearer "+readToken)
	denied.Header.Set("Content-Type", "application/json")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	assertResponse(t, deniedResponse, http.StatusForbidden, `"code":"authorization-denied"`)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/snapshots", bytes.NewReader(content))
	request.Header.Set("Authorization", "Bearer "+writeToken)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertResponse(t, response, http.StatusCreated, `"repositoryId":"repository-`, `"snapshotId":"snapshot-`, `"revision":"abc123"`)
	page, err := memory.ListRepositories(context.Background(), store.PageRequest{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("persisted repositories = %#v, err = %v", page, err)
	}

	conflicting := serverTestBOM()
	conflicting.Metadata.Generator = "different-generator"
	conflictContent, _ := json.Marshal(conflicting)
	conflict := httptest.NewRequest(http.MethodPost, "/api/v1/snapshots", bytes.NewReader(conflictContent))
	conflict.Header.Set("Authorization", "Bearer "+writeToken)
	conflict.Header.Set("Content-Type", "application/json")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflict)
	assertResponse(t, conflictResponse, http.StatusConflict, `"code":"immutable-snapshot-conflict"`)
}

func TestSnapshotIngestionRejectsUnsafeBodies(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "test")
	for _, test := range []struct {
		name, contentType, body string
		status                  int
		code                    string
	}{
		{"media type", "text/plain", `{}`, http.StatusUnsupportedMediaType, "content-type-required"},
		{"malformed", "application/json", `{`, http.StatusBadRequest, "invalid-json"},
		{"unknown field", "application/json", `{"unknown":true}`, http.StatusBadRequest, "invalid-json"},
		{"invalid contract", "application/json", `{}`, http.StatusUnprocessableEntity, "invalid-agent-bom"},
		{"trailing", "application/json", `{} {}`, http.StatusBadRequest, "invalid-json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/snapshots", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertResponse(t, response, test.status, `"code":"`+test.code+`"`)
		})
	}
}

func TestPaginationCursorIsBoundToCollectionScope(t *testing.T) {
	memory := store.NewMemory()
	for _, source := range []string{"github:acme/a", "github:acme/b"} {
		bom := serverTestBOM()
		bom.Metadata.Source = source
		if _, err := memory.PutSnapshot(context.Background(), bom); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHandler(memory, "dev")
	response := performRequest(t, handler, http.MethodGet, "/api/v1/repositories?limit=1")
	var page struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.NextCursor == "" {
		t.Fatalf("repository page has no cursor: %s, %v", response.Body.String(), err)
	}
	misused := performRequest(t, handler, http.MethodGet, "/api/v1/findings?cursor="+page.NextCursor)
	assertResponse(t, misused, http.StatusBadRequest, `"code":"invalid-cursor"`)
}

func TestReadOnlyAPIRejectsInvalidFiltersPathsAndMutation(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "dev")
	tests := []struct {
		method, path, code string
		status             int
	}{
		{http.MethodGet, "/api/v1/findings?severity=urgent", "invalid-severity", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/finding-lifecycles?status=unknown", "invalid-lifecycle-status", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/findings?limit=0", "invalid-limit", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/findings?cursor=invalid", "invalid-cursor", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/repositories/not-an-id/bom", "invalid-repository-id", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/repositories/repository-0000000000000000/snapshots/not-a-snapshot/bom", "invalid-snapshot-id", http.StatusBadRequest},
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
	for _, path := range []string{"/api/v1/repositories", "/api/v1/findings", "/api/v1/finding-lifecycles"} {
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
