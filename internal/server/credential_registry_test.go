package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestCredentialRegistryReloadAtomicallyRotatesIdentityAndScopes(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	oldToken := "atomic-old-token-0123456789abcdefghijkl"
	newToken := "atomic-new-token-0123456789abcdefghijkl"
	registry, err := newCredentialRegistry([]BearerCredential{{ID: "old-reader", Token: oldToken, Scopes: []string{ScopeInventoryRead}}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authenticator, authorizer, _ := registry.Security()
	handler := newHandler(store.NewMemory(), "test", &authenticator, &authorizer)
	assertCredentialStatus(t, handler, oldToken, "/api/v1/repositories", http.StatusOK)

	if err := registry.Reload([]BearerCredential{{ID: "new-reader", Token: newToken, Scopes: []string{ScopeFindingsRead}}}); err != nil {
		t.Fatal(err)
	}
	assertCredentialStatus(t, handler, oldToken, "/api/v1/repositories", http.StatusUnauthorized)
	assertCredentialStatus(t, handler, newToken, "/api/v1/findings", http.StatusOK)
	assertCredentialStatus(t, handler, newToken, "/api/v1/repositories", http.StatusForbidden)

	if err := registry.Reload([]BearerCredential{{ID: "invalid", Token: "short", Scopes: []string{ScopeControlPlaneRead}}}); err == nil {
		t.Fatal("invalid reload was accepted")
	}
	assertCredentialStatus(t, handler, newToken, "/api/v1/findings", http.StatusOK)
}

func TestCredentialRegistryPinsSnapshotForInFlightRequest(t *testing.T) {
	oldToken := "pinned-old-token-0123456789abcdefghijkl"
	newToken := "pinned-new-token-0123456789abcdefghijkl"
	registry, err := NewCredentialRegistry([]BearerCredential{{ID: "old-reader", Token: oldToken, Scopes: []string{ScopeInventoryRead}}})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, authorizer, _ := registry.Security()
	reload := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if err := registry.Reload([]BearerCredential{{ID: "new-reader", Token: newToken, Scopes: []string{ScopeFindingsRead}}}); err != nil {
			t.Fatal(err)
		}
		authorizer.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, request)
	})
	handler := authenticator.middleware(reload)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
	request.Header.Set("Authorization", "Bearer "+oldToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("in-flight status = %d", response.Code)
	}
}

func assertCredentialStatus(t *testing.T, handler http.Handler, token, path string, status int) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("%s status = %d, want %d", path, response.Code, status)
	}
}
