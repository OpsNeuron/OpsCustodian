package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	serverauth "github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestControlPlaneCompositionAlwaysUsesAuthentication(t *testing.T) {
	config := validRuntimeConfig()
	server, err := NewControlPlaneHTTPServer(config, store.NewMemory(), "test")
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	server.Handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthorized.Code)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/contracts", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer "+controlPlaneTestAPIToken)
	authorized := httptest.NewRecorder()
	server.Handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, body = %s", authorized.Code, authorized.Body.String())
	}
}

func TestControlPlaneCompositionRejectsMissingSecurityDependencies(t *testing.T) {
	config := validRuntimeConfig()
	config.Authenticator = serverauth.BearerAuthenticator{}
	if _, err := NewControlPlaneHTTPServer(config, store.NewMemory(), "test"); err == nil {
		t.Fatal("missing authenticator was accepted")
	}
	if _, err := NewControlPlaneHTTPServer(validRuntimeConfig(), nil, "test"); err == nil {
		t.Fatal("missing reader was accepted")
	}
}
