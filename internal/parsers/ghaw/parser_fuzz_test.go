package ghaw

import (
	"context"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func FuzzParseAgenticWorkflow(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("---\nname: issue reviewer\non: issues\npermissions:\n  contents: read\n  issues: write\ntools:\n  bash: {}\nsafe-outputs:\n  add-comment: {}\n---\nReview ${{ secrets.REVIEW_TOKEN }}.\n"),
		[]byte("---\nname: composed\nimports:\n  - uses: ./shared/common.md\n    with:\n      mode: safe\nnetwork:\n  allowed: [github]\n  blocked: [example.test]\n---\n{{#import? ./optional.md}}\n"),
		[]byte("---\nname: [broken\n---\n"),
		[]byte("workflow without frontmatter\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 256<<10 {
			t.Skip()
		}
		artifact := discovery.Artifact{RelPath: ".github/workflows/fuzz.md", Content: content}
		first, firstErr := (Parser{}).Parse(context.Background(), artifact)
		second, secondErr := (Parser{}).Parse(context.Background(), artifact)
		if ghawErrorText(firstErr) != ghawErrorText(secondErr) {
			t.Fatalf("parse error is not deterministic: %q != %q", ghawErrorText(firstErr), ghawErrorText(secondErr))
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("accepted agentic workflow parse is not deterministic")
		}
		if firstErr != nil {
			return
		}
		bom := model.AgentBOM{
			APIVersion: model.APIVersion,
			Kind:       model.Kind,
			Metadata:   model.DocumentMetadata{Source: "fuzz", Revision: "fuzz"},
			Assets:     first,
		}
		if issues := validation.Validate(bom); len(issues) != 0 {
			t.Fatalf("accepted agentic workflow violates Agent BOM contract: %#v", issues)
		}
	})
}

func ghawErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
