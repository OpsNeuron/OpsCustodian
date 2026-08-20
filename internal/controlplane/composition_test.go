package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opscustodian/opscustodian/internal/audit"
	serverauth "github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

func TestControlPlaneCompositionAlwaysUsesAuthentication(t *testing.T) {
	config := validRuntimeConfig()
	server, err := NewControlPlaneHTTPServer(config, store.NewMemory(), "test", discardRequestAuditSink{}, func(err error) { t.Fatalf("audit failure: %v", err) })
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
	if _, err := NewControlPlaneHTTPServer(config, store.NewMemory(), "test", discardRequestAuditSink{}, func(error) {}); err == nil {
		t.Fatal("missing authenticator was accepted")
	}
	if _, err := NewControlPlaneHTTPServer(validRuntimeConfig(), nil, "test", discardRequestAuditSink{}, func(error) {}); err == nil {
		t.Fatal("missing reader was accepted")
	}
	if _, err := NewControlPlaneHTTPServer(validRuntimeConfig(), store.NewMemory(), "test", nil, func(error) {}); err == nil {
		t.Fatal("missing audit sink was accepted")
	}
}

type discardRequestAuditSink struct{}

func (discardRequestAuditSink) Record(context.Context, audit.Event) error { return nil }
