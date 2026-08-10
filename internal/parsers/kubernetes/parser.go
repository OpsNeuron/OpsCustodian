package kubernetes

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

func (Parser) Name() string { return "kubernetes" }
func (Parser) Supports(artifact discovery.Artifact) bool {
	ext := strings.ToLower(filepath.Ext(artifact.RelPath))
	return ext == ".yaml" || ext == ".yml"
}

func (Parser) Parse(_ context.Context, artifact discovery.Artifact) ([]model.Agent, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(artifact.Content)))
	var assets []model.Asset
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse Kubernetes YAML document %d: %w", documentIndex, err)
		}
		if len(document.Content) == 0 {
			continue
		}
		root := document.Content[0]
		apiVersion := scalar(mapping(root, "apiVersion"))
		kind := scalar(mapping(root, "kind"))
		if apiVersion == "" || kind == "" {
			continue
		}
		metadata := mapping(root, "metadata")
		name := scalar(mapping(metadata, "name"))
		if name == "" {
			continue
		}
		namespace := scalar(mapping(metadata, "namespace"))
		if namespace == "" {
			namespace = "default"
		}
		evidenceID := stableEvidenceID(artifact.RelPath, documentIndex, kind, namespace, name)
		evidence := model.Evidence{ID: evidenceID, Path: artifact.RelPath, Line: root.Line, Parser: "kubernetes", Confidence: "high", Observation: apiVersion + " " + kind}
		switch kind {
		case "ServiceAccount":
			assets = append(assets, serviceAccountAsset(artifact.RelPath, namespace, name, evidence))
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job":
			assets = append(assets, workloadAsset(root, artifact.RelPath, kind, namespace, name, evidence))
		}
	}
	return assets, nil
}

func serviceAccountAsset(sourcePath, namespace, name string, evidence model.Evidence) model.Asset {
	qualified := namespace + "/" + name
	return model.Asset{
		ID: "kubernetes:service-account:" + qualified, Type: "identity", Name: qualified,
		Source:       model.Source{Path: sourcePath},
		Capabilities: []model.Capability{{Action: "kubernetes.authenticate", Resource: "kubernetes:service-account/" + qualified, Effect: "execute", EvidenceIDs: []string{evidence.ID}}},
		Evidence:     []model.Evidence{evidence},
	}
}

func workloadAsset(root *yaml.Node, sourcePath, kind, namespace, name string, evidence model.Evidence) model.Asset {
	podSpec := mapping(root, "spec")
	if kind != "Pod" {
		template := mapping(podSpec, "template")
		podSpec = mapping(template, "spec")
	}
	serviceAccount := scalar(mapping(podSpec, "serviceAccountName"))
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	qualifiedWorkload := namespace + "/" + strings.ToLower(kind) + "/" + name
	qualifiedIdentity := namespace + "/" + serviceAccount
	return model.Asset{
		ID: "kubernetes:workload:" + qualifiedWorkload, Type: "workload", Name: qualifiedWorkload,
		Source: model.Source{Path: sourcePath}, Runtime: &model.Runtime{Type: "kubernetes", Reference: kind},
		Identities:   []model.Reference{{Type: "identity", Reference: qualifiedIdentity}},
		Capabilities: []model.Capability{{Action: "kubernetes.workload.run", Resource: "kubernetes:" + qualifiedWorkload, Effect: "execute", EvidenceIDs: []string{evidence.ID}}},
		Evidence:     []model.Evidence{evidence},
	}
}

func mapping(node *yaml.Node, key string) *yaml.Node {
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
func scalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}
func stableEvidenceID(path string, document int, kind, namespace, name string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s:%s:%s", path, document, kind, namespace, name)))
	return fmt.Sprintf("kubernetes-%x", sum[:6])
}
