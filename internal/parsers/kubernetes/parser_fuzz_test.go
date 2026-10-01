package kubernetes

import (
	"context"
	"reflect"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/validation"
)

func FuzzParseManifest(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: agent\n  namespace: production\n"),
		[]byte("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: reader\nrules:\n  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get]\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: worker\nspec:\n  serviceAccountName: agent\n  containers: []\n"),
		[]byte("---\n---\napiVersion: [broken\n"),
		[]byte("kind: ConfigMap\nmetadata:\n  name: ignored\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 256<<10 {
			t.Skip()
		}
		artifact := discovery.Artifact{RelPath: "deploy/fuzz.yaml", Content: content}
		first, firstErr := (Parser{}).Parse(context.Background(), artifact)
		second, secondErr := (Parser{}).Parse(context.Background(), artifact)
		if kubernetesErrorText(firstErr) != kubernetesErrorText(secondErr) {
			t.Fatalf("parse error is not deterministic: %q != %q", kubernetesErrorText(firstErr), kubernetesErrorText(secondErr))
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("accepted Kubernetes parse is not deterministic")
		}
		if firstErr != nil {
			return
		}
		for _, asset := range first {
			bom := model.AgentBOM{
				APIVersion: model.APIVersion,
				Kind:       model.Kind,
				Metadata:   model.DocumentMetadata{Source: "fuzz", Revision: "fuzz"},
				Assets:     []model.Asset{asset},
			}
			if issues := validation.Validate(bom); len(issues) != 0 {
				t.Fatalf("accepted Kubernetes asset violates Agent BOM contract: %#v", issues)
			}
		}
	})
}

func kubernetesErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
