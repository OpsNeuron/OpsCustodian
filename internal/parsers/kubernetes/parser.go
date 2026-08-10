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
			assets = append(assets, serviceAccountAsset(root, artifact.RelPath, namespace, name, evidence))
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job":
			assets = append(assets, workloadAsset(root, artifact.RelPath, kind, namespace, name, evidence))
		case "Role", "ClusterRole":
			assets = append(assets, roleAsset(root, artifact.RelPath, kind, namespace, name, evidence))
		case "RoleBinding", "ClusterRoleBinding":
			assets = append(assets, bindingAsset(root, artifact.RelPath, kind, namespace, name, evidence))
		}
	}
	return assets, nil
}

func roleAsset(root *yaml.Node, sourcePath, kind, namespace, name string, evidence model.Evidence) model.Asset {
	qualified := namespace + "/" + name
	environment := namespace
	if kind == "ClusterRole" {
		qualified, environment = "cluster/"+name, "cluster"
	}
	asset := model.Asset{
		ID: "kubernetes:role:" + qualified, Type: "authorization-role", Name: qualified,
		Source: model.Source{Path: sourcePath}, Evidence: []model.Evidence{evidence},
	}
	rules := mapping(root, "rules")
	if rules != nil && rules.Kind == yaml.SequenceNode {
		for _, rule := range rules.Content {
			apiGroups := scalarList(mapping(rule, "apiGroups"), "core")
			resources := scalarList(mapping(rule, "resources"), "*")
			verbs := scalarList(mapping(rule, "verbs"), "*")
			for _, apiGroup := range apiGroups {
				for _, resource := range resources {
					for _, verb := range verbs {
						asset.Capabilities = append(asset.Capabilities, model.Capability{
							Action:   "kubernetes." + normalizeSegment(resource) + "." + normalizeSegment(verb),
							Resource: "kubernetes:" + qualified + "/" + normalizeSegment(apiGroup) + "/" + resource,
							Effect:   rbacEffect(verb), Environment: environment, EvidenceIDs: []string{evidence.ID},
						})
					}
				}
			}
		}
	}
	return asset
}

func bindingAsset(root *yaml.Node, sourcePath, kind, namespace, name string, evidence model.Evidence) model.Asset {
	qualified := namespace + "/" + name
	if kind == "ClusterRoleBinding" {
		qualified = "cluster/" + name
	}
	asset := model.Asset{
		ID: "kubernetes:binding:" + qualified, Type: "authorization-binding", Name: qualified,
		Source: model.Source{Path: sourcePath}, Evidence: []model.Evidence{evidence},
		Capabilities: []model.Capability{{Action: "kubernetes.rbac.bind", Resource: "kubernetes:" + qualified, Effect: "execute", EvidenceIDs: []string{evidence.ID}}},
	}
	roleRef := mapping(root, "roleRef")
	roleName, roleKind := scalar(mapping(roleRef, "name")), scalar(mapping(roleRef, "kind"))
	if roleName != "" {
		roleReference := namespace + "/" + roleName
		if roleKind == "ClusterRole" {
			roleReference = "cluster/" + roleName
		}
		asset.Dependencies = append(asset.Dependencies, model.Reference{Type: "authorization-role", Reference: roleReference})
	}
	subjects := mapping(root, "subjects")
	if subjects != nil && subjects.Kind == yaml.SequenceNode {
		for _, subject := range subjects.Content {
			if scalar(mapping(subject, "kind")) != "ServiceAccount" {
				continue
			}
			subjectName := scalar(mapping(subject, "name"))
			subjectNamespace := scalar(mapping(subject, "namespace"))
			if subjectNamespace == "" {
				subjectNamespace = namespace
			}
			if subjectName != "" {
				asset.Identities = append(asset.Identities, model.Reference{Type: "identity", Reference: subjectNamespace + "/" + subjectName})
			}
		}
	}
	return asset
}

func scalarList(node *yaml.Node, fallback string) []string {
	if node == nil {
		return []string{fallback}
	}
	if node.Kind == yaml.ScalarNode {
		return []string{strings.TrimSpace(node.Value)}
	}
	if node.Kind != yaml.SequenceNode {
		return []string{fallback}
	}
	var result []string
	for _, item := range node.Content {
		if value := scalar(item); value != "" {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return []string{fallback}
	}
	return result
}

func normalizeSegment(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "/", ".")
	return strings.ReplaceAll(value, "-", "_")
}

func rbacEffect(verb string) string {
	switch strings.ToLower(verb) {
	case "get", "list", "watch":
		return "read"
	case "create", "update", "patch":
		return "write"
	case "delete", "deletecollection":
		return "delete"
	case "bind", "escalate", "impersonate", "*":
		return "admin"
	default:
		return "execute"
	}
}

func serviceAccountAsset(root *yaml.Node, sourcePath, namespace, name string, evidence model.Evidence) model.Asset {
	qualified := namespace + "/" + name
	asset := model.Asset{
		ID: "kubernetes:service-account:" + qualified, Type: "identity", Name: qualified,
		Source:       model.Source{Path: sourcePath},
		Capabilities: []model.Capability{{Action: "kubernetes.authenticate", Resource: "kubernetes:service-account/" + qualified, Effect: "execute", EvidenceIDs: []string{evidence.ID}}},
		Evidence:     []model.Evidence{evidence},
	}
	if value, specified := boolean(mapping(root, "automountServiceAccountToken")); specified {
		asset.Controls = append(asset.Controls, model.Control{Type: "automountServiceAccountToken", Value: value})
	}
	return asset
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
	asset := model.Asset{
		ID: "kubernetes:workload:" + qualifiedWorkload, Type: "workload", Name: qualifiedWorkload,
		Source: model.Source{Path: sourcePath}, Runtime: &model.Runtime{Type: "kubernetes", Reference: kind},
		Identities:   []model.Reference{{Type: "identity", Reference: qualifiedIdentity}},
		Capabilities: []model.Capability{{Action: "kubernetes.workload.run", Resource: "kubernetes:" + qualifiedWorkload, Effect: "execute", EvidenceIDs: []string{evidence.ID}}},
		Evidence:     []model.Evidence{evidence},
	}
	if value, specified := boolean(mapping(podSpec, "automountServiceAccountToken")); specified {
		asset.Controls = append(asset.Controls, model.Control{Type: "automountServiceAccountToken", Value: value})
	}
	return asset
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
func boolean(node *yaml.Node) (bool, bool) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, false
	}
	var value bool
	if err := node.Decode(&value); err != nil {
		return false, false
	}
	return value, true
}
func stableEvidenceID(path string, document int, kind, namespace, name string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s:%s:%s", path, document, kind, namespace, name)))
	return fmt.Sprintf("kubernetes-%x", sum[:6])
}
