package contracts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBetaThreatModelPreservesSecurityBoundaries(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "THREAT_MODEL.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	required := []string{
		"Client input cannot choose the effective organization",
		"Credential reload is atomic",
		"Policy evaluation fails closed",
		"Audit delivery cannot silently degrade",
		"no built-in per-client rate limiter",
		"not cryptographically append-only or WORM",
		"not a penetration test",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Fatalf("beta threat model is missing required boundary %q", value)
		}
	}
}
