package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

const serverTestBearerToken = "opscustodian-test-token-0123456789abcdef"

func TestAuthenticatedHandlerProtectsAPIAndLeavesHealthPublic(t *testing.T) {
	authenticator, err := NewBearerAuthenticator(serverTestBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthenticatedHandler(store.NewMemory(), "test", authenticator)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}
	readiness := httptest.NewRecorder()
	handler.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readiness.Code != http.StatusOK {
		t.Fatalf("readiness status = %d", readiness.Code)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" || !strings.Contains(unauthorized.Body.String(), `"code":"authentication-required"`) {
		t.Fatalf("unauthorized response = %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	if unauthorized.Header().Get("Cache-Control") != "no-store" || unauthorized.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unauthorized security headers = %v", unauthorized.Header())
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer "+serverTestBearerToken)
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized response = %d %s", authorized.Code, authorized.Body.String())
	}
}

func TestBearerAuthenticationRejectsAmbiguousOrInvalidCredentials(t *testing.T) {
	authenticator, err := NewBearerAuthenticator(serverTestBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthenticatedHandler(store.NewMemory(), "test", authenticator)
	tests := []struct {
		name    string
		headers []string
	}{
		{"wrong", []string{"Bearer opscustodian-wrong-token-0123456789abcdef"}},
		{"wrong scheme", []string{"Basic " + serverTestBearerToken}},
		{"missing space", []string{"Bearer" + serverTestBearerToken}},
		{"embedded whitespace", []string{"Bearer opscustodian-test-token-0123456789 abcdef"}},
		{"multiple", []string{"Bearer " + serverTestBearerToken, "Bearer " + serverTestBearerToken}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil)
			for _, value := range test.headers {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestBearerAuthenticatorValidatesSecretAndDoesNotSerializeIt(t *testing.T) {
	for _, token := range []string{
		"short",
		strings.Repeat("x", maximumBearerTokenBytes+1),
		strings.Repeat("x", 31) + " ",
		strings.Repeat("x", 31) + "\x00",
		strings.Repeat("x", 31) + "é",
		strings.Repeat("x", 31) + "?",
		strings.Repeat("x", 30) + "=x",
	} {
		if _, err := NewBearerAuthenticator(token); err == nil {
			t.Fatalf("invalid token accepted: length %d", len(token))
		}
	}
	for _, token := range []string{
		"valid-token_0123456789.ABCDEFGHIJK",
		"valid~token+0123456789/ABCDEFGHIJK=",
		"valid-token-0123456789ABCDEFGHIJK==",
	} {
		if _, err := NewBearerAuthenticator(token); err != nil {
			t.Fatalf("valid bearer token rejected: %v", err)
		}
	}
	authenticator, err := NewBearerAuthenticator(serverTestBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), serverTestBearerToken) || string(content) != "{}" {
		t.Fatalf("serialized authenticator = %s", content)
	}
}

func TestIdentifiedBearerAuthenticatorValidatesStableCredentialID(t *testing.T) {
	for _, identity := range []string{"", "UPPER", "1reader", "ab", strings.Repeat("a", 64), "reader_one"} {
		if _, err := NewIdentifiedBearerAuthenticator(identity, serverTestBearerToken); err == nil {
			t.Fatalf("invalid credential ID accepted: %q", identity)
		}
	}
	authenticator, err := NewIdentifiedBearerAuthenticator("platform-reader", serverTestBearerToken)
	if err != nil || authenticator.CredentialID() != "platform-reader" {
		t.Fatalf("credential ID = %q, err = %v", authenticator.CredentialID(), err)
	}
	content, err := json.Marshal(authenticator)
	if err != nil || strings.Contains(string(content), "platform-reader") || string(content) != "{}" {
		t.Fatalf("serialized authenticator = %s, err = %v", content, err)
	}
}

func TestBearerCredentialRegistryUsesIndependentIdentitiesAndScopes(t *testing.T) {
	inventoryToken := "inventory-reader-token-0123456789abcdef"
	findingsToken := "findings-reader-token-0123456789abcdef0"
	authenticator, authorizer, err := NewBearerCredentialSecurity([]BearerCredential{
		{ID: "inventory-reader", Token: inventoryToken, Scopes: []string{ScopeInventoryRead}},
		{ID: "findings-reader", Token: findingsToken, Scopes: []string{ScopeFindingsRead}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := newHandler(store.NewMemory(), "test", &authenticator, &authorizer)
	for _, test := range []struct {
		token, path string
		status      int
	}{
		{inventoryToken, "/api/v1/repositories", http.StatusOK},
		{inventoryToken, "/api/v1/findings", http.StatusForbidden},
		{findingsToken, "/api/v1/findings", http.StatusOK},
		{findingsToken, "/api/v1/repositories", http.StatusForbidden},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("token path %s status = %d, want %d", test.path, response.Code, test.status)
		}
	}
}

func TestBearerCredentialRegistryRejectsAmbiguousConfiguration(t *testing.T) {
	token := "duplicate-credential-token-0123456789abcdef"
	for _, credentials := range [][]BearerCredential{
		{{ID: "same-reader", Token: token, Scopes: []string{ScopeInventoryRead}}, {ID: "same-reader", Token: token + "x", Scopes: []string{ScopeFindingsRead}}},
		{{ID: "first-reader", Token: token, Scopes: []string{ScopeInventoryRead}}, {ID: "second-reader", Token: token, Scopes: []string{ScopeFindingsRead}}},
	} {
		if _, _, err := NewBearerCredentialSecurity(credentials); err == nil {
			t.Fatalf("ambiguous credentials accepted: %#v", credentials)
		}
	}
}

func TestBearerCredentialRepositoryGrantsAreValidated(t *testing.T) {
	validRepository := store.RepositoryID("github:acme/allowed")
	base := BearerCredential{ID: "repository-reader", Token: "repository-reader-token-0123456789abcdef", Scopes: []string{ScopeInventoryRead}}
	for _, repositories := range [][]string{{validRepository}, {"invalid"}, {validRepository, validRepository}} {
		credential := base
		credential.Repositories = repositories
		_, _, err := NewBearerCredentialSecurity([]BearerCredential{credential})
		if len(repositories) == 1 && repositories[0] == validRepository {
			if err != nil {
				t.Fatalf("valid repository grant rejected: %v", err)
			}
		} else if err == nil {
			t.Fatalf("invalid repository grants accepted: %#v", repositories)
		}
	}
}

func TestBearerCredentialLifecycleSupportsBoundedRotation(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	credentials := []BearerCredential{
		{ID: "old-reader", Token: "old-rotation-token-0123456789abcdefghijk", Scopes: []string{ScopeInventoryRead}, ExpiresAt: "2026-08-20T12:05:00Z"},
		{ID: "new-reader", Token: "new-rotation-token-0123456789abcdefghijk", Scopes: []string{ScopeInventoryRead}, NotBefore: "2026-08-20T11:55:00Z"},
		{ID: "future-reader", Token: "future-token-0123456789abcdefghijklmnop", Scopes: []string{ScopeInventoryRead}, NotBefore: "2026-08-20T12:05:00Z"},
		{ID: "disabled-reader", Token: "disabled-token-0123456789abcdefghijkl", Scopes: []string{ScopeInventoryRead}, Disabled: true},
	}
	authenticator, _, err := newBearerCredentialSecurity(credentials, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		token, identity string
		allowed         bool
	}{
		{credentials[0].Token, "old-reader", true},
		{credentials[1].Token, "new-reader", true},
		{credentials[2].Token, "", false},
		{credentials[3].Token, "", false},
	} {
		identity, allowed := authenticator.authenticate([]string{"Bearer " + test.token})
		if identity != test.identity || allowed != test.allowed {
			t.Fatalf("credential result = %q, %v; want %q, %v", identity, allowed, test.identity, test.allowed)
		}
	}
}

func TestBearerCredentialLifecycleRejectsInvalidWindows(t *testing.T) {
	base := BearerCredential{ID: "window-reader", Token: "window-reader-token-0123456789abcdefghijk", Scopes: []string{ScopeInventoryRead}}
	for _, mutate := range []func(*BearerCredential){
		func(value *BearerCredential) { value.NotBefore = "tomorrow" },
		func(value *BearerCredential) { value.ExpiresAt = "tomorrow" },
		func(value *BearerCredential) {
			value.NotBefore = "2026-08-21T00:00:00Z"
			value.ExpiresAt = "2026-08-20T00:00:00Z"
		},
	} {
		credential := base
		mutate(&credential)
		if _, _, err := NewBearerCredentialSecurity([]BearerCredential{credential}); err == nil {
			t.Fatalf("invalid lifecycle accepted: %#v", credential)
		}
	}
}
