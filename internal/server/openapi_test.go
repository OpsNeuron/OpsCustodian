package server

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"gopkg.in/yaml.v3"
)

func TestOpenAPIDocumentsEveryReadOnlyRoute(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var document struct {
		OpenAPI    string                    `yaml:"openapi"`
		APIVersion string                    `yaml:"x-opscustodian-api-version"`
		Paths      map[string]map[string]any `yaml:"paths"`
		Security   []map[string][]string     `yaml:"security"`
		Components struct {
			SecuritySchemes map[string]map[string]any `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if document.OpenAPI != "3.1.0" || document.APIVersion != contracts.ControlPlaneAPIVersion {
		t.Fatalf("unexpected OpenAPI contract: %#v", document)
	}
	if len(document.Security) != 1 || document.Security[0]["bearerAuth"] == nil || document.Components.SecuritySchemes["bearerAuth"]["scheme"] != "bearer" {
		t.Fatalf("OpenAPI bearer security contract is missing: %#v", document.Security)
	}
	health, ok := document.Paths["/healthz"]["get"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI health operation is invalid")
	}
	security, exists := health["security"]
	if !exists || len(security.([]any)) != 0 {
		t.Fatalf("OpenAPI health operation must explicitly disable authentication: %#v", security)
	}
	readiness, ok := document.Paths["/readyz"]["get"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI readiness operation is invalid")
	}
	security, exists = readiness["security"]
	if !exists || len(security.([]any)) != 0 {
		t.Fatalf("OpenAPI readiness operation must explicitly disable authentication: %#v", security)
	}
	paths := []string{
		"/healthz", "/readyz", "/api/v1/contracts", "/api/v1/repositories", "/api/v1/graph", "/api/v1/audit-events",
		"/api/v1/repositories/{repositoryId}/bom",
		"/api/v1/repositories/{repositoryId}/snapshots",
		"/api/v1/repositories/{repositoryId}/snapshots/{snapshotId}/bom",
		"/api/v1/repositories/{repositoryId}/drift",
		"/api/v1/findings",
		"/api/v1/finding-lifecycles",
	}
	for _, path := range paths {
		if _, exists := document.Paths[path]["get"]; !exists {
			t.Errorf("OpenAPI does not document GET %s", path)
		}
		if path != "/healthz" && path != "/readyz" {
			operation := document.Paths[path]["get"].(map[string]any)
			if operation["x-opscustodian-required-scope"] != requiredScope(http.MethodGet, path) {
				t.Errorf("OpenAPI GET %s scope = %v, want %s", path, operation["x-opscustodian-required-scope"], requiredScope(http.MethodGet, path))
			}
		}
	}
	post, ok := document.Paths["/api/v1/snapshots"]["post"].(map[string]any)
	if !ok || post["x-opscustodian-required-scope"] != requiredScope(http.MethodPost, "/api/v1/snapshots") {
		t.Fatalf("OpenAPI snapshot ingestion scope is missing: %#v", post)
	}
}
