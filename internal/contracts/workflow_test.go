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

func TestGitHubWorkflowsUsePinnedActionsAndBoundedPermissions(t *testing.T) {
	root := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("workflow count = %d, expected 2", len(entries))
	}
	for _, entry := range entries {
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
