package ingestion

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConnectorRegistryRoutesRepositoryWithoutCredentials(t *testing.T) {
	connector := &recordingConnector{name: "test", result: FetchResult{Unchanged: true}}
	registry, err := NewConnectorRegistry(connector)
	if err != nil {
		t.Fatal(err)
	}
	repository := Repository{Source: "github:acme/platform", Connector: "test", Revision: "abc123"}
	result, err := registry.Fetch(context.Background(), FetchRequest{Repository: repository, KnownRevision: "abc123"})
	if err != nil || !result.Unchanged || connector.repository.Source != repository.Source || connector.knownRevision != "abc123" {
		t.Fatalf("result = %#v, connector = %#v, err = %v", result, connector, err)
	}
	if _, err := registry.Fetch(context.Background(), FetchRequest{Repository: Repository{Connector: "missing"}}); err == nil {
		t.Fatal("unknown connector was accepted")
	}
}

func TestLocalConnectorSkipsKnownRevision(t *testing.T) {
	root := t.TempDir()
	connector := LocalConnector{}
	result, err := connector.Fetch(context.Background(), Repository{
		Source: "github:acme/platform", Connector: LocalConnectorName, Location: root, Revision: "abc123",
	}, "abc123")
	if err != nil || !result.Unchanged {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestLocalConnectorProducesDeterministicBOM(t *testing.T) {
	root := t.TempDir()
	workflow := []byte("name: inventory\non:\n  workflow_dispatch:\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo safe\n")
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "inventory.yml"), workflow, 0o600); err != nil {
		t.Fatal(err)
	}
	connector := NewLocalConnector()
	repository := Repository{Source: "github:acme/platform", Connector: LocalConnectorName, Location: root, Revision: "abc123"}
	first, err := connector.Fetch(context.Background(), repository, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := connector.Fetch(context.Background(), repository, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.BOM.Metadata.GeneratedAt != "" || first.BOM.Metadata.Source != repository.Source || first.BOM.Metadata.Revision != repository.Revision || first.BOM.Metadata.Generator != "opscustodian/local-connector" {
		t.Fatalf("BOM metadata = %#v", first.BOM.Metadata)
	}
	if !reflect.DeepEqual(first.BOM, second.BOM) {
		t.Fatal("same local source and revision produced different Agent BOMs")
	}
}

func TestLocalConnectorRejectsUnsafeConfiguration(t *testing.T) {
	connector := NewLocalConnector()
	for name, repository := range map[string]Repository{
		"relative":        {Source: "github:acme/platform", Connector: LocalConnectorName, Location: ".", Revision: "abc123"},
		"wrong connector": {Source: "github:acme/platform", Connector: "github", Location: t.TempDir(), Revision: "abc123"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := connector.Fetch(context.Background(), repository, ""); err == nil {
				t.Fatal("unsafe repository was accepted")
			}
		})
	}
}

type recordingConnector struct {
	name          string
	result        FetchResult
	repository    Repository
	knownRevision string
}

func (connector *recordingConnector) Name() string { return connector.name }
func (connector *recordingConnector) Fetch(_ context.Context, repository Repository, knownRevision string) (FetchResult, error) {
	connector.repository, connector.knownRevision = repository, knownRevision
	return connector.result, nil
}
