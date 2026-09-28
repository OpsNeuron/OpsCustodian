package mcp

import (
	"context"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func FuzzParseConfiguration(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"mcpServers":{"review":{"command":"npx","args":["reviewer@1.2.3"],"env":{"TOKEN":"ignored"}}}}`),
		[]byte("mcpServers:\n  gateway:\n    url: https://example.test/mcp?token=ignored\n"),
		[]byte(`{"servers":{"container":{"command":"docker","args":["run","example/reviewer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}}`),
		[]byte("mcpServers: [unterminated\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 256<<10 {
			t.Skip()
		}
		path := "mcp.yaml"
		if len(content) > 0 && content[0] == '{' {
			path = "mcp.json"
		}
		artifact := discovery.Artifact{RelPath: path, Content: content}
		first, firstErr := (Parser{}).Parse(context.Background(), artifact)
		second, secondErr := (Parser{}).Parse(context.Background(), artifact)
		if mcpErrorText(firstErr) != mcpErrorText(secondErr) {
			t.Fatalf("parse error is not deterministic: %q != %q", mcpErrorText(firstErr), mcpErrorText(secondErr))
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("accepted MCP configuration parse is not deterministic")
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
			t.Fatalf("accepted MCP configuration violates Agent BOM contract: %#v", issues)
		}
	})
}

func mcpErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
