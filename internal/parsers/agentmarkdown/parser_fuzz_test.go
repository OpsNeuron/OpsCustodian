package agentmarkdown

import (
	"context"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func FuzzParseAgentMarkdown(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("---\nname: reviewer\nowner: platform\ntools: [issues, contents]\nmcp-servers: [github]\n---\nReview issues.\n"),
		[]byte("---\nname: deployer\nallowed-tools: shell, edit\nskills: [release]\nmodel: preferred\n---\nDeploy safely.\n"),
		[]byte("---\nname: [broken\n---\n"),
		[]byte("Instructions without frontmatter.\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 256<<10 {
			t.Skip()
		}
		artifact := discovery.Artifact{RelPath: ".github/agents/fuzz.agent.md", Content: content}
		first, firstErr := (Parser{}).Parse(context.Background(), artifact)
		second, secondErr := (Parser{}).Parse(context.Background(), artifact)
		if agentMarkdownErrorText(firstErr) != agentMarkdownErrorText(secondErr) {
			t.Fatalf("parse error is not deterministic: %q != %q", agentMarkdownErrorText(firstErr), agentMarkdownErrorText(secondErr))
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("accepted agent Markdown parse is not deterministic")
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
			t.Fatalf("accepted agent Markdown violates Agent BOM contract: %#v", issues)
		}
	})
}

func agentMarkdownErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
