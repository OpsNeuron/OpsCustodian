package ingestion

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const githubConnectorTestSHA = "0123456789abcdef0123456789abcdef01234567"

func TestGitHubConnectorSkipsKnownImmutableRevision(t *testing.T) {
	archives := &fakeGitHubArchives{}
	connector, err := NewGitHubConnector(fakeGitHubRevisions{revision: githubConnectorTestSHA}, archives)
	if err != nil {
		t.Fatal(err)
	}
	result, err := connector.Fetch(context.Background(), githubConnectorTestRepository(), githubConnectorTestSHA)
	if err != nil || !result.Unchanged || archives.calls != 0 {
		t.Fatalf("result = %#v, archive calls = %d, err = %v", result, archives.calls, err)
	}
}

func TestGitHubConnectorScansMaterializedCheckoutDeterministicallyAndCleansUp(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "ci.yml"), []byte("name: CI\non:\n  workflow_dispatch:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleaned := 0
	archives := &fakeGitHubArchives{checkout: func() *MaterializedCheckout {
		return &MaterializedCheckout{Root: root, cleanup: func() error { cleaned++; return nil }}
	}}
	connector, _ := NewGitHubConnector(fakeGitHubRevisions{revision: githubConnectorTestSHA}, archives)
	first, err := connector.Fetch(context.Background(), githubConnectorTestRepository(), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := connector.Fetch(context.Background(), githubConnectorTestRepository(), "")
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 2 || first.BOM.Metadata.Source != "github:acme/platform" || first.BOM.Metadata.Revision != githubConnectorTestSHA || first.BOM.Metadata.GeneratedAt != "" || first.BOM.Metadata.Generator != "opscustodian/github-connector" {
		t.Fatalf("cleaned = %d, metadata = %#v", cleaned, first.BOM.Metadata)
	}
	if !reflect.DeepEqual(first.BOM, second.BOM) {
		t.Fatal("same GitHub revision produced different Agent BOMs")
	}
}

func TestGitHubConnectorPreservesCleanupFailureAndRejectsInvalidDependencies(t *testing.T) {
	if _, err := NewGitHubConnector(nil, &fakeGitHubArchives{}); err == nil {
		t.Fatal("missing revision resolver was accepted")
	}
	root := t.TempDir()
	archives := &fakeGitHubArchives{checkout: func() *MaterializedCheckout {
		return &MaterializedCheckout{Root: root, cleanup: func() error { return errors.New("cleanup failed") }}
	}}
	connector, _ := NewGitHubConnector(fakeGitHubRevisions{revision: githubConnectorTestSHA}, archives)
	_, err := connector.Fetch(context.Background(), githubConnectorTestRepository(), "")
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestGitHubConnectorCleansCheckoutAfterScannerFailure(t *testing.T) {
	cleaned := false
	archives := &fakeGitHubArchives{checkout: func() *MaterializedCheckout {
		return &MaterializedCheckout{Root: t.TempDir(), cleanup: func() error { cleaned = true; return nil }}
	}}
	connector, _ := NewGitHubConnector(fakeGitHubRevisions{revision: githubConnectorTestSHA}, archives)
	repository := githubConnectorTestRepository()
	repository.Boundaries = []string{"../outside=unsafe"}
	if _, err := connector.Fetch(context.Background(), repository, ""); err == nil || !cleaned {
		t.Fatalf("scanner error = %v, cleaned = %v", err, cleaned)
	}
}

type fakeGitHubRevisions struct {
	revision string
	err      error
}

func (resolver fakeGitHubRevisions) Resolve(context.Context, Repository) (string, error) {
	return resolver.revision, resolver.err
}

type fakeGitHubArchives struct {
	calls    int
	checkout func() *MaterializedCheckout
	err      error
}

func (archives *fakeGitHubArchives) Acquire(context.Context, Repository, string) (*MaterializedCheckout, error) {
	archives.calls++
	if archives.err != nil {
		return nil, archives.err
	}
	if archives.checkout == nil {
		return nil, errors.New("unexpected archive acquisition")
	}
	return archives.checkout(), nil
}

func githubConnectorTestRepository() Repository {
	return Repository{Source: "github:acme/platform", Connector: GitHubConnectorName, Ref: "main", MaxFileSize: 2 << 20}
}
