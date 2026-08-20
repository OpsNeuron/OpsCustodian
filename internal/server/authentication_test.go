package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	for _, token := range []string{"short", strings.Repeat("x", maximumBearerTokenBytes+1), strings.Repeat("x", 31) + " "} {
		if _, err := NewBearerAuthenticator(token); err == nil {
			t.Fatalf("invalid token accepted: length %d", len(token))
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
