package ownership

import (
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

type backstageComponent struct {
	name, owner, scope, catalogPath string
	ownerLine                       int
}

func ApplyBackstage(bom *model.AgentBOM, artifacts []discovery.Artifact) []model.Diagnostic {
	var components []backstageComponent
	var diagnostics []model.Diagnostic
	for _, artifact := range artifacts {
		base := strings.ToLower(path.Base(artifact.RelPath))
		if base != "catalog-info.yaml" && base != "catalog-info.yml" {
			continue
		}
		parsed, issues := parseBackstageCatalog(artifact)
		components = append(components, parsed...)
		diagnostics = append(diagnostics, issues...)
	}
	sort.Slice(components, func(i, j int) bool {
		if len(components[i].scope) != len(components[j].scope) {
			return len(components[i].scope) > len(components[j].scope)
		}
		return components[i].catalogPath < components[j].catalogPath
	})
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		for _, component := range components {
			if !withinScope(asset.Source.Path, component.scope) {
				continue
			}
			if asset.Component == "" {
				asset.Component = component.name
			}
			if len(asset.Owners) == 0 && component.owner != "" {
				asset.Owners = []string{component.owner}
				asset.Evidence = append(asset.Evidence, model.Evidence{
					ID: backstageEvidenceID(component, asset.ID), Path: component.catalogPath, Line: component.ownerLine,
					Parser: "backstage", Confidence: "high", Observation: "ownership resolved from Backstage component " + component.name,
				})
			}
			break
		}
	}
	return diagnostics
}

func parseBackstageCatalog(artifact discovery.Artifact) ([]backstageComponent, []model.Diagnostic) {
	decoder := yaml.NewDecoder(strings.NewReader(string(artifact.Content)))
	var components []backstageComponent
	var diagnostics []model.Diagnostic
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			diagnostics = append(diagnostics, backstageDiagnostic(artifact.RelPath, "invalid-backstage-catalog", fmt.Sprintf("document %d: %v", documentIndex, err)))
			break
		}
		if len(document.Content) == 0 {
			continue
		}
		root := document.Content[0]
		if !strings.EqualFold(nodeScalar(mappingNode(root, "kind")), "Component") {
			continue
		}
		metadata, spec := mappingNode(root, "metadata"), mappingNode(root, "spec")
		name := nodeScalar(mappingNode(metadata, "name"))
		ownerNode := mappingNode(spec, "owner")
		owner := nodeScalar(ownerNode)
		if name == "" || owner == "" {
			diagnostics = append(diagnostics, backstageDiagnostic(artifact.RelPath, "incomplete-backstage-component", fmt.Sprintf("document %d Component requires metadata.name and spec.owner", documentIndex)))
			continue
		}
		scope := path.Dir(artifact.RelPath)
		if scope == "." {
			scope = ""
		}
		components = append(components, backstageComponent{name: name, owner: owner, scope: scope, catalogPath: artifact.RelPath, ownerLine: ownerNode.Line})
	}
	return components, diagnostics
}

func mappingNode(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func nodeScalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func withinScope(assetPath, scope string) bool {
	assetPath = strings.Trim(strings.ReplaceAll(assetPath, "\\", "/"), "/")
	return scope == "" || assetPath == scope || strings.HasPrefix(assetPath, scope+"/")
}

func backstageEvidenceID(component backstageComponent, assetID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", component.catalogPath, component.ownerLine, assetID)))
	return fmt.Sprintf("backstage-%x", sum[:6])
}

func backstageDiagnostic(catalogPath, code, message string) model.Diagnostic {
	return model.Diagnostic{Severity: "warning", Code: code, Path: catalogPath, Parser: "backstage", Message: message}
}
