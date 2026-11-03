package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
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

func TestHistoricalDriftComparesStoredSnapshotsWithRepositoryAuthorization(t *testing.T) {
	memory := store.NewMemory()
	before := serverTestBOM()
	before.Metadata.Revision = "before"
	before.Assets[0].Capabilities = []model.Capability{{Action: "kubernetes.deployments.update", Resource: "kubernetes:production/apps/payments", Effect: "write", Environment: "production", EvidenceIDs: []string{"role-evidence"}}}
	after := serverTestBOM()
	after.Metadata.Revision = "after"
	after.Assets[0].Capabilities = []model.Capability{{Action: "kubernetes.deployments.update", Resource: "kubernetes:production/*", Effect: "admin", Environment: "production", EvidenceIDs: []string{"role-evidence"}}}
	beforeSnapshot, err := memory.PutSnapshot(context.Background(), before)
	if err != nil {
		t.Fatal(err)
	}
	afterSnapshot, err := memory.PutSnapshot(context.Background(), after)
	if err != nil {
		t.Fatal(err)
	}
	token := "historical-drift-token-0123456789abcdef"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{{
		ID: "drift-reader", Token: token, Scopes: []string{ScopeFindingsRead}, Repositories: []string{beforeSnapshot.RepositoryID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(memory, "test", &authenticator, &authorizer)
	path := "/api/v1/repositories/" + beforeSnapshot.RepositoryID + "/drift?beforeSnapshotId=" + beforeSnapshot.SnapshotID + "&afterSnapshotId=" + afterSnapshot.SnapshotID
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertResponse(t, response, http.StatusOK, `"beforeRevision":"before"`, `"afterRevision":"after"`, `"type":"capability-escalated"`, `"changes":[`)

	invalid := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/"+beforeSnapshot.RepositoryID+"/drift", nil)
	invalid.Header.Set("Authorization", "Bearer "+token)
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	assertResponse(t, invalidResponse, http.StatusBadRequest, `"code":"invalid-snapshot-id"`)
}

func TestOrganizationGraphReturnsLatestAuthorizedRepositorySubgraphs(t *testing.T) {
	memory := store.NewMemory()
	allowed := serverTestBOM()
	allowed.Metadata.Source = "github:acme/allowed"
	allowed.Metadata.Revision = "allowed-1"
	allowed.Relationships = []model.Relationship{{
		ID: "relationship-self", From: allowed.Assets[0].ID, Type: "depends-on", To: allowed.Assets[0].ID,
		TargetType: "asset", Confidence: "high", EvidenceIDs: []string{"role-evidence"},
	}}
	allowed.AccessPaths = []model.AccessPath{{
		ID: "path-reader", Origin: allowed.Assets[0].ID,
		Steps:      []model.AccessPathStep{{Kind: "origin", AssetID: allowed.Assets[0].ID}, {Kind: "entitlement", AssetID: allowed.Assets[0].ID}},
		Capability: model.Capability{Action: "kubernetes.pods.get", Resource: "kubernetes:production/core/pods/*", Effect: "read", EvidenceIDs: []string{"role-evidence"}},
		Confidence: "high", EvidenceIDs: []string{"role-evidence"},
	}}
	allowedSnapshot, err := memory.PutSnapshot(context.Background(), allowed)
	if err != nil {
		t.Fatal(err)
	}
	denied := serverTestBOM()
	denied.Metadata.Source = "github:acme/denied"
	denied.Metadata.Revision = "denied-1"
	deniedSnapshot, err := memory.PutSnapshot(context.Background(), denied)
	if err != nil {
		t.Fatal(err)
	}
	token := "organization-graph-token-0123456789abcdef"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{{
		ID: "graph-reader", Token: token, Scopes: []string{ScopeInventoryRead}, Repositories: []string{allowedSnapshot.RepositoryID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(memory, "test", &authenticator, &authorizer)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/graph", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertResponse(t, response, http.StatusOK,
		`"repositoryId":"`+allowedSnapshot.RepositoryID+`"`, `"revision":"allowed-1"`,
		`"relationships":[{"id":"relationship-self"`, `"accessPaths":[{"id":"path-reader"`)
	if strings.Contains(response.Body.String(), deniedSnapshot.RepositoryID) || strings.Contains(response.Body.String(), "github:acme/denied") {
		t.Fatalf("organization graph leaked unauthorized repository: %s", response.Body.String())
	}

	matching := httptest.NewRequest(http.MethodGet, "/api/v1/graph?action=kubernetes.pods.get&relationshipType=depends-on", nil)
	matching.Header.Set("Authorization", "Bearer "+token)
	matchingResponse := httptest.NewRecorder()
	handler.ServeHTTP(matchingResponse, matching)
	assertResponse(t, matchingResponse, http.StatusOK, `"repositoryId":"`+allowedSnapshot.RepositoryID+`"`)

	notMatching := httptest.NewRequest(http.MethodGet, "/api/v1/graph?owner=security-team", nil)
	notMatching.Header.Set("Authorization", "Bearer "+token)
	notMatchingResponse := httptest.NewRecorder()
	handler.ServeHTTP(notMatchingResponse, notMatching)
	assertResponse(t, notMatchingResponse, http.StatusOK, `"items":[]`)

	deniedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/graph?repositoryId="+deniedSnapshot.RepositoryID, nil)
	deniedRequest.Header.Set("Authorization", "Bearer "+token)
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, deniedRequest)
	assertResponse(t, deniedResponse, http.StatusForbidden, `"code":"repository-authorization-denied"`)

	invalid := httptest.NewRequest(http.MethodGet, "/api/v1/graph?action=%20shell.execute", nil)
	invalid.Header.Set("Authorization", "Bearer "+token)
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	assertResponse(t, invalidResponse, http.StatusBadRequest, `"code":"invalid-graph-filter"`)
}

func TestAuditHistoryIsScopeAndRepositoryAuthorized(t *testing.T) {
	memory := store.NewMemory()
	repositoryID := store.RepositoryID("github:acme/allowed")
	event := audit.FromHTTPRequest(audit.HTTPRequestObservation{
		OccurredAt: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC), RequestID: "request-a",
		OrganizationID: "organization-0123456789abcdef", Identity: "operator-a", Method: http.MethodGet,
		Route: "/api/v1/repositories/{repositoryID}/bom", Status: http.StatusOK, Authentication: "authenticated", Authorization: "authorized",
		Snapshot: &audit.SnapshotIngestionObservation{RepositoryID: repositoryID},
	})
	if err := memory.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	token := "audit-history-token-0123456789abcdef"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{{
		ID: "audit-reader", Token: token, Scopes: []string{ScopeAuditRead}, Repositories: []string{repositoryID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(memory, "test", &authenticator, &authorizer)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?repositoryId="+repositoryID+"&eventName=opscustodian.http.request.completed", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertResponse(t, response, http.StatusOK, `"identityId":"operator-a"`, `"eventName":"opscustodian.http.request.completed"`)

	denied := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?repositoryId="+store.RepositoryID("github:acme/denied"), nil)
	denied.Header.Set("Authorization", "Bearer "+token)
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	assertResponse(t, deniedResponse, http.StatusForbidden, `"code":"repository-authorization-denied"`)
}

func TestReadOnlyAPIExposesContractsAndSecurityHeaders(t *testing.T) {
	handler := NewHandler(store.NewMemory(), "v0.5.0-test")
	response := performRequest(t, handler, http.MethodGet, "/api/v1/contracts")
	assertResponse(t, response, http.StatusOK,
		`"version":"v0.5.0-test"`,
		`"controlPlane":"`+contracts.ControlPlaneAPIVersion+`"`,
		`"policyDecision":"`+contracts.PolicyDecisionVersion+`"`,
		`"repositorySet":"`+contracts.RepositorySetAPIVersion+`"`,
		`"preflight":"`+contracts.PreflightAPIVersion+`"`,
	)
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

func TestRepositoryScopedCredentialFiltersCollectionsAndRejectsDirectAccess(t *testing.T) {
	memory := store.NewMemory()
	allowedBOM := serverTestBOM()
	allowedBOM.Metadata.Source, allowedBOM.Metadata.Revision = "github:acme/allowed", "allowed-revision"
	deniedBOM := serverTestBOM()
	deniedBOM.Metadata.Source, deniedBOM.Metadata.Revision = "github:acme/denied", "denied-revision"
	for _, bom := range []model.AgentBOM{allowedBOM, deniedBOM} {
		if _, err := memory.PutSnapshot(context.Background(), bom); err != nil {
			t.Fatal(err)
		}
	}
	allowedRepositoryID, deniedRepositoryID := store.RepositoryID(allowedBOM.Metadata.Source), store.RepositoryID(deniedBOM.Metadata.Source)
	token := "repository-scoped-token-0123456789abcdef"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{{
		ID: "allowed-reader", Token: token, Scopes: []string{ScopeInventoryRead, ScopeFindingsRead, ScopeSnapshotsWrite}, Repositories: []string{allowedRepositoryID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(memory, "test", &authenticator, &authorizer)
	request := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	repositories := request(http.MethodGet, "/api/v1/repositories", nil)
	if repositories.Code != http.StatusOK || !strings.Contains(repositories.Body.String(), allowedRepositoryID) || strings.Contains(repositories.Body.String(), deniedRepositoryID) {
		t.Fatalf("filtered repositories response = %d: %s", repositories.Code, repositories.Body.String())
	}
	if response := request(http.MethodGet, "/api/v1/repositories/"+deniedRepositoryID+"/bom", nil); response.Code != http.StatusForbidden {
		t.Fatalf("denied direct repository status = %d: %s", response.Code, response.Body.String())
	}
	findings := request(http.MethodGet, "/api/v1/findings", nil)
	if findings.Code != http.StatusOK || !strings.Contains(findings.Body.String(), allowedRepositoryID) || strings.Contains(findings.Body.String(), deniedRepositoryID) {
		t.Fatalf("filtered findings response = %d: %s", findings.Code, findings.Body.String())
	}
	content, _ := json.Marshal(deniedBOM)
	if response := request(http.MethodPost, "/api/v1/snapshots", bytes.NewReader(content)); response.Code != http.StatusForbidden {
		t.Fatalf("denied snapshot write status = %d: %s", response.Code, response.Body.String())
	}
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
