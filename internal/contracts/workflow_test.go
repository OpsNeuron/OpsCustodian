package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)
var semanticVersion = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)

func TestGitHubWorkflowsUsePinnedActionsAndBoundedPermissions(t *testing.T) {
	root := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{
		"ci.yml":                 false,
		"release.yml":            false,
		"vulnerability-scan.yml": false,
	}
	if len(entries) != len(expected) {
		t.Fatalf("workflow count = %d, expected %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			t.Fatalf("unexpected workflow %s", entry.Name())
		}
		expected[entry.Name()] = true
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if strings.Contains(text, "pull_request_target") || !strings.Contains(text, "permissions:\n  contents: read") {
			t.Fatalf("workflow %s has unsafe trigger or root permissions", entry.Name())
		}
		var document any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		var actions []string
		collectWorkflowActions(document, &actions)
		if len(actions) == 0 {
			t.Fatalf("workflow %s contains no actions", entry.Name())
		}
		for _, action := range actions {
			if !pinnedAction.MatchString(action) {
				t.Errorf("workflow %s action is not pinned to a full SHA: %s", entry.Name(), action)
			}
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected workflow %s was not found", name)
		}
	}
}

func TestVulnerabilityScannerVersionAndEntryPointsStayAligned(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "scripts", "verify-vulnerabilities.sh"),
		filepath.Join(root, "scripts", "verify-vulnerabilities.cmd"),
	}
	var expectedVersion string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		version := semanticVersion.FindString(string(content))
		if version == "" {
			t.Fatalf("%s does not pin a scanner version", path)
		}
		if expectedVersion == "" {
			expectedVersion = version
		} else if version != expectedVersion {
			t.Fatalf("scanner version = %s in %s, expected %s", version, path, expectedVersion)
		}
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "vulnerability-scan.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "bash ./scripts/verify-vulnerabilities.sh") {
		t.Fatal("vulnerability workflow does not invoke the reviewed scanner entry point")
	}
}

func collectWorkflowActions(value any, actions *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "uses" {
				if action, ok := child.(string); ok {
					*actions = append(*actions, action)
				}
				continue
			}
			collectWorkflowActions(child, actions)
		}
	case []any:
		for _, child := range typed {
			collectWorkflowActions(child, actions)
		}
	}
}
