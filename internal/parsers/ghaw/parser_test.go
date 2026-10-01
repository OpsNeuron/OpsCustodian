package ghaw

import (
	"context"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
)

func TestParseRejectsDuplicateFrontmatterKeys(t *testing.T) {
	_, err := (Parser{}).Parse(context.Background(), discovery.Artifact{
		RelPath: ".github/workflows/reviewer.md",
		Content: []byte("---\nname: first\nname: second\non: issues\n---\nReview issues.\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate mapping key") {
		t.Fatalf("Parse() error = %v, expected duplicate mapping key rejection", err)
	}
}
