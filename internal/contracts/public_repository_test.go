package contracts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPublicRepositorySurface(t *testing.T) {
	root := filepath.Join("..", "..")
	required := []string{
		"README.md",
		"LICENSE",
		"SECURITY.md",
		"CONTRIBUTING.md",
		"CODE_OF_CONDUCT.md",
		"SUPPORT.md",
		filepath.Join(".github", "CODEOWNERS"),
		filepath.Join(".github", "pull_request_template.md"),
		filepath.Join(".github", "ISSUE_TEMPLATE", "beta-feedback.yml"),
	}
	for _, name := range required {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Errorf("required public repository file %q is unavailable", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".github", "ISSUE_TEMPLATE", "alpha-feedback.yml")); !os.IsNotExist(err) {
		t.Error("obsolete alpha feedback template must not remain in the public beta")
	}

	assertPublicText(t, filepath.Join(root, "README.md"), []string{
		"is the current public beta",
		"docs/BETA_SUPPORT_MATRIX.md",
		"CODE_OF_CONDUCT.md",
		"SUPPORT.md",
	}, []string{
		"Public alpha under active development",
		"First-beta release candidate under validation",
	})
	assertPublicText(t, filepath.Join(root, "CONTRIBUTING.md"), []string{
		"in its first public beta",
		"Code of Conduct",
	}, []string{
		"OpsCustodian is a public alpha",
		"preparing its first public beta",
	})
	assertPublicText(t, filepath.Join(root, "docs", "LIMITATIONS.md"), []string{
		"# First-public-beta limitations",
		"pre-v1 interfaces",
	}, []string{
		"# Public alpha limitations",
		"# First-beta candidate limitations",
		"latest published release remains `v0.5.0-alpha`",
	})

	for _, name := range []string{
		filepath.Join(".github", "ISSUE_TEMPLATE", "bug.yml"),
		filepath.Join(".github", "ISSUE_TEMPLATE", "parser-compatibility.yml"),
		filepath.Join(".github", "ISSUE_TEMPLATE", "beta-feedback.yml"),
		filepath.Join(".github", "ISSUE_TEMPLATE", "config.yml"),
	} {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Errorf("decode %s: %v", name, err)
		}
		if len(document) == 0 {
			t.Errorf("issue configuration %s is empty", name)
		}
	}
}

func assertPublicText(t *testing.T, filename string, required, forbidden []string) {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	text := string(content)
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Errorf("%s is missing %q", filename, value)
		}
	}
	for _, value := range forbidden {
		if strings.Contains(text, value) {
			t.Errorf("%s retains stale text %q", filename, value)
		}
	}
}
