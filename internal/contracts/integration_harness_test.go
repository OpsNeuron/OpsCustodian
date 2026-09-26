package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIntegrationHarnessIsIsolatedSecretFreeAndContractValid(t *testing.T) {
	root := filepath.Join("..", "..")
	compose, err := os.ReadFile(filepath.Join(root, "integration", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Name     string `yaml:"name"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(compose, &document); err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	if document.Name != "opscustodian-integration" || !document.Networks["integration"].Internal || strings.Contains(text, "ports:") {
		t.Fatalf("integration isolation contract is invalid")
	}
	for _, forbidden := range []string{"POSTGRES_PASSWORD: opscustodian", "OPSCUSTODIAN_API_TOKEN: integration-operator", "network_mode: host", "privileged: true"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("integration compose contains forbidden setting %q", forbidden)
		}
	}

	repositorySet, err := os.ReadFile(filepath.Join(root, "integration", "repository-set.json"))
	if err != nil {
		t.Fatal(err)
	}
	var repositoryDocument struct {
		APIVersion   string `json:"apiVersion"`
		Kind         string `json:"kind"`
		Repositories []struct {
			Connector string `json:"connector"`
			Location  string `json:"location"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(repositorySet, &repositoryDocument); err != nil {
		t.Fatal(err)
	}
	if repositoryDocument.APIVersion != "opscustodian.dev/ingestion/v1alpha1" || repositoryDocument.Kind != "RepositorySet" || len(repositoryDocument.Repositories) != 1 || repositoryDocument.Repositories[0].Connector != "local" || repositoryDocument.Repositories[0].Location != "/fixtures/scan-input" {
		t.Fatalf("integration RepositorySet = %#v", repositoryDocument)
	}

	collector, err := os.ReadFile(filepath.Join(root, "integration", "otel-collector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var collectorConfig map[string]any
	if err := yaml.Unmarshal(collector, &collectorConfig); err != nil || collectorConfig["receivers"] == nil || collectorConfig["exporters"] == nil || collectorConfig["service"] == nil {
		t.Fatalf("collector configuration is incomplete: %v", err)
	}

	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "FROM golang:1.25.13-alpine AS build") {
		t.Fatal("Dockerfile builder does not match the Go module baseline")
	}
}
