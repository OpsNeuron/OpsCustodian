package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestScopeAuthorizationSeparatesAuthenticationFromPermission(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	allowed, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	denied, _ := NewScopeAuthorizer([]string{ScopeContractsRead})

	for _, test := range []struct {
		name       string
		authorizer ScopeAuthorizer
		status     int
		code       string
	}{
		{name: "allowed", authorizer: allowed, status: http.StatusOK},
		{name: "denied", authorizer: denied, status: http.StatusForbidden, code: "authorization-denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler(store.NewMemory(), "test", &authenticator, &test.authorizer)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
			request.Header.Set("Authorization", "Bearer "+serverTestBearerToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || (test.code != "" && !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestScopeAuthorizationValidatesAndDoesNotExposeMutableState(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {""}, {"admin"}, {ScopeControlPlaneRead, "unknown"}} {
		if _, err := NewScopeAuthorizer(scopes); err == nil {
			t.Fatalf("invalid scopes accepted: %#v", scopes)
		}
	}
	authorizer, err := NewScopeAuthorizer([]string{ScopeControlPlaneRead, ScopeControlPlaneRead})
	if err != nil {
		t.Fatal(err)
	}
	if got := authorizer.Scopes(); len(got) != 1 || got[0] != ScopeControlPlaneRead {
		t.Fatalf("scopes = %#v", got)
	}
	content, err := json.Marshal(authorizer)
	if err != nil || string(content) != "{}" {
		t.Fatalf("serialized authorizer = %s, err = %v", content, err)
	}
}

func TestGranularScopesCannotCrossAPIBoundaries(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	for _, test := range []struct {
		scope         string
		path          string
		allowedStatus int
	}{
		{ScopeContractsRead, "/api/v1/contracts", http.StatusOK},
		{ScopeInventoryRead, "/api/v1/repositories", http.StatusOK},
		{ScopeInventoryRead, "/api/v1/graph", http.StatusOK},
		{ScopeAuditRead, "/api/v1/audit-events", http.StatusOK},
		{ScopeFindingsRead, "/api/v1/findings", http.StatusOK},
		{ScopeFindingsRead, "/api/v1/repositories/repository-0123456789abcdef/drift", http.StatusBadRequest},
	} {
		authorizer, _ := NewScopeAuthorizer([]string{test.scope})
		handler := newHandler(store.NewMemory(), "test", &authenticator, &authorizer)
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Header.Set("Authorization", "Bearer "+serverTestBearerToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.allowedStatus {
			t.Fatalf("scope %s path %s status = %d", test.scope, test.path, response.Code)
		}
	}
}

func TestControlPlaneReadDoesNotGrantSnapshotWrites(t *testing.T) {
	authenticator, _ := NewBearerAuthenticator(serverTestBearerToken)
	authorizer, _ := NewScopeAuthorizer([]string{ScopeControlPlaneRead})
	handler := newHandler(store.NewMemory(), "test", &authenticator, &authorizer)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/snapshots", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+serverTestBearerToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("read scope write status = %d", response.Code)
	}
}
