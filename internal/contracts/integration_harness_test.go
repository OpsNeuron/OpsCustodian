package contracts_test

import (
	"encoding/json"
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"regexp"
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
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	moduleGo := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)\r?$`).FindSubmatch(module)
	builderGo := regexp.MustCompile(`(?m)^FROM golang:([0-9]+\.[0-9]+\.[0-9]+)-alpine@sha256:[0-9a-f]{64} AS build\r?$`).FindSubmatch(dockerfile)
	if len(moduleGo) != 2 || len(builderGo) != 2 || version.Compare("go"+string(builderGo[1]), "go"+string(moduleGo[1])) < 0 {
		t.Fatalf("Dockerfile Go builder must be digest-pinned at or above the go.mod version")
	}
	if err := validateOPAImageAlignment(dockerfile, compose); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{
		"FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS certificates",
		"FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092",
	} {
		if !strings.Contains(string(dockerfile), base) {
			t.Fatalf("Dockerfile base image is not pinned to reviewed reference %q", base)
		}
	}
}

func TestOPAImageContractAllowsPinnedPatchUpgrades(t *testing.T) {
	digest := strings.Repeat("a", 64)
	dockerfile := []byte("FROM openpolicyagent/opa:1.21.4-static@sha256:" + digest + " AS opa\n")
	compose := []byte("    image: openpolicyagent/opa:1.21.4-static@sha256:" + digest + "\n")
	if err := validateOPAImageAlignment(dockerfile, compose); err != nil {
		t.Fatalf("safe OPA patch upgrade rejected: %v", err)
	}
	if err := validateOPAImageAlignment(dockerfile, []byte("    image: openpolicyagent/opa:1.21.3-static@sha256:"+digest+"\n")); err == nil {
		t.Fatal("mismatched OPA runtime versions accepted")
	}
	if err := validateOPAImageAlignment(dockerfile, []byte("    image: openpolicyagent/opa:1.21.4-static@sha256:"+strings.Repeat("b", 64)+"\n")); err == nil {
		t.Fatal("mismatched OPA runtime digests accepted")
	}
	if err := validateOPAImageAlignment(
		[]byte("FROM openpolicyagent/opa:1.21.2-static@sha256:"+digest+" AS opa\n"),
		[]byte("    image: openpolicyagent/opa:1.21.2-static@sha256:"+digest+"\n"),
	); err == nil {
		t.Fatal("OPA runtime downgrade accepted")
	}
}

func validateOPAImageAlignment(dockerfile, compose []byte) error {
	dockerReference := regexp.MustCompile(`(?m)^FROM openpolicyagent/opa:([0-9]+\.[0-9]+\.[0-9]+)-static@sha256:([0-9a-f]{64}) AS opa\r?$`).FindSubmatch(dockerfile)
	composeReference := regexp.MustCompile(`(?m)^\s+image: openpolicyagent/opa:([0-9]+\.[0-9]+\.[0-9]+)-static@sha256:([0-9a-f]{64})\r?$`).FindSubmatch(compose)
	if len(dockerReference) != 3 || len(composeReference) != 3 {
		return fmt.Errorf("OPA images must use digest-pinned static references")
	}
	if version.Compare("go"+string(dockerReference[1]), "go1.21.3") < 0 {
		return fmt.Errorf("OPA image version must not be older than 1.21.3")
	}
	if string(dockerReference[1]) != string(composeReference[1]) || string(dockerReference[2]) != string(composeReference[2]) {
		return fmt.Errorf("Dockerfile and integration Compose must use the same OPA version and digest")
	}
	return nil
}
