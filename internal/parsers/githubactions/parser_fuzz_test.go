package githubactions

import (
	"context"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func FuzzParseWorkflow(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("name: review\non: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n"),
		[]byte("name: privileged\non: pull_request_target\npermissions: write-all\njobs:\n  run:\n    runs-on: self-hosted\n    steps:\n      - run: echo '${{ github.event.pull_request.title }}'\n"),
		[]byte("jobs: [unterminated"),
		[]byte("true\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 256<<10 {
			t.Skip()
		}
		artifact := discovery.Artifact{RelPath: ".github/workflows/fuzz.yml", Content: content}
		first, firstErr := (Parser{}).Parse(context.Background(), artifact)
		second, secondErr := (Parser{}).Parse(context.Background(), artifact)
		if errorText(firstErr) != errorText(secondErr) {
			t.Fatalf("parse error is not deterministic: %q != %q", errorText(firstErr), errorText(secondErr))
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("accepted workflow parse is not deterministic")
		}
		if firstErr != nil {
			return
		}
		if len(first) != 1 {
			t.Fatalf("accepted workflow produced %d assets, expected 1", len(first))
		}
		bom := model.AgentBOM{
			APIVersion: model.APIVersion,
			Kind:       model.Kind,
			Metadata:   model.DocumentMetadata{Source: "fuzz", Revision: "fuzz"},
			Assets:     first,
		}
		if issues := validation.Validate(bom); len(issues) != 0 {
			t.Fatalf("accepted workflow violates Agent BOM contract: %#v", issues)
		}
	})
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
