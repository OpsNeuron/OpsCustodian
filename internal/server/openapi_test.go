package server

import (
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
	paths := []string{
		"/healthz", "/api/v1/contracts", "/api/v1/repositories",
		"/api/v1/repositories/{repositoryId}/bom",
		"/api/v1/repositories/{repositoryId}/snapshots",
		"/api/v1/repositories/{repositoryId}/snapshots/{snapshotId}/bom",
		"/api/v1/findings",
		"/api/v1/finding-lifecycles",
	}
	for _, path := range paths {
		if _, exists := document.Paths[path]["get"]; !exists {
			t.Errorf("OpenAPI does not document GET %s", path)
		}
		if path != "/healthz" {
			operation := document.Paths[path]["get"].(map[string]any)
			if operation["x-opscustodian-required-scope"] != requiredScope(path) {
				t.Errorf("OpenAPI GET %s scope = %v, want %s", path, operation["x-opscustodian-required-scope"], requiredScope(path))
			}
		}
	}
}
