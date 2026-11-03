package contracts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBetaSupportMatrixPreservesNarrowOperationalBoundary(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "BETA_SUPPORT_MATRIX.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	required := []string{
		"PostgreSQL | Supported | 17.4",
		"Exactly one",
		"OIDC authentication is not implemented",
		"GitHub PAT | Not supported",
		"No Kubernetes version is in the first-beta support matrix",
		"There is no supported skip-version path",
		"v0.5.0-alpha",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Fatalf("beta support matrix is missing required boundary %q", value)
		}
	}
}
