package ghaw

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

var (
	secretPattern         = regexp.MustCompile(`(?i)secrets\.([A-Z0-9_]+)`)
	markdownImportPattern = regexp.MustCompile(`\{\{#(runtime-)?import(\?)?\s+([^\s}]+)`)
)

func (Parser) Name() string { return "github-agentic-workflows" }

func (Parser) Supports(artifact discovery.Artifact) bool {
	path := strings.ToLower(artifact.RelPath)
	return strings.HasPrefix(path, ".github/workflows/") && filepath.Ext(path) == ".md"
}

func (Parser) Parse(_ context.Context, artifact discovery.Artifact) ([]model.Agent, error) {
	frontmatter, err := parseFrontmatter(artifact.Content)
	if err != nil {
		return nil, fmt.Errorf("parse gh-aw frontmatter in %s: %w", artifact.RelPath, err)
	}
	name := scalar(mappingValue(frontmatter, "name"))
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(artifact.RelPath), filepath.Ext(artifact.RelPath))
	}
	evidenceID := stableID(artifact.RelPath)
	assetType := "agent"
	if mappingValue(frontmatter, "on") == nil {
		assetType = "workflow"
	}
	asset := model.Agent{
		ID: "gh-aw:" + artifact.RelPath, Type: assetType, Name: name,
		Source:  model.Source{Path: artifact.RelPath},
		Runtime: &model.Runtime{Type: "github-agentic-workflow", Reference: artifact.RelPath},
		Evidence: []model.Evidence{{
			ID: evidenceID, Path: artifact.RelPath, Line: 2, Parser: "github-agentic-workflows",
			Confidence: "high", Observation: "gh-aw workflow frontmatter",
		}},
	}
	if owner := scalar(mappingValue(frontmatter, "owner")); owner != "" {
		asset.Owners = []string{owner}
	}
	if engine := scalar(mappingValue(frontmatter, "engine")); engine != "" {
		asset.Controls = append(asset.Controls, model.Control{Type: "engine", Value: engine})
	}
	asset.Capabilities = append(asset.Capabilities, permissionCapabilities(mappingValue(frontmatter, "permissions"), evidenceID)...)
	safeOutputs := mappingValue(frontmatter, "safe-outputs")
	asset.Capabilities = append(asset.Capabilities, safeOutputCapabilities(safeOutputs, evidenceID)...)
	if names := mappingKeys(safeOutputs, "jobs"); len(names) > 0 {
		asset.Controls = append(asset.Controls, model.Control{Type: "safeOutputs", Value: names})
	}
	asset.Tools = append(asset.Tools, toolReferences(mappingValue(frontmatter, "tools"))...)
	asset.Capabilities = append(asset.Capabilities, toolCapabilities(mappingValue(frontmatter, "tools"), evidenceID)...)
	asset.Tools = append(asset.Tools, mcpReferences(mappingValue(frontmatter, "mcp-servers"))...)
	if tools := mappingValue(frontmatter, "tools"); tools != nil {
		asset.Tools = append(asset.Tools, mcpReferences(mappingValue(tools, "mcp-servers"))...)
	}
	asset.Tools = uniqueReferences(asset.Tools)
	for _, skill := range stringList(mappingValue(frontmatter, "skills")) {
		asset.Dependencies = append(asset.Dependencies, model.Reference{Type: "skill", Reference: normalizeSkillReference(skill)})
	}
	asset.Dependencies = append(asset.Dependencies, importReferences(mappingValue(frontmatter, "imports"))...)
	asset.Dependencies = append(asset.Dependencies, resourceReferences(mappingValue(frontmatter, "resources"))...)
	asset.Dependencies = append(asset.Dependencies, markdownImportReferences(artifact.Content)...)
	asset.Dependencies = uniqueReferences(asset.Dependencies)
	asset.Controls = append(asset.Controls, networkControls(mappingValue(frontmatter, "network"))...)
	asset.Capabilities = append(asset.Capabilities, networkCapabilities(mappingValue(frontmatter, "network"), evidenceID)...)
	asset.Credentials = credentialReferences(artifact.Content)
	asset.Capabilities = uniqueCapabilities(asset.Capabilities)
	return []model.Agent{asset}, nil
}

func importReferences(node *yaml.Node) []model.Reference {
	if node == nil {
		return nil
	}
	items := node.Content
	if node.Kind != yaml.SequenceNode {
		items = []*yaml.Node{node}
	}
	var result []model.Reference
	for _, item := range items {
		value := scalar(item)
		var parameters map[string]any
		if item.Kind == yaml.MappingNode {
			value = scalar(mappingValue(item, "uses"))
			if value == "" {
				value = scalar(mappingValue(item, "path"))
			}
			parameterNode := mappingValue(item, "with")
			if parameterNode == nil { parameterNode = mappingValue(item, "inputs") }
			if parameterNode != nil { _ = parameterNode.Decode(&parameters) }
		}
		if value != "" {
			result = append(result, importReference(value, parameters))
		}
	}
	return result
}

func importReference(value string, parameters map[string]any) model.Reference {
	raw := strings.TrimSpace(value)
	optional := strings.HasSuffix(raw, "?")
	clean := strings.TrimSuffix(raw, "?")
	withoutSection := strings.SplitN(clean, "#", 2)[0]
	lower := strings.ToLower(strings.ReplaceAll(withoutSection, "\\", "/"))
	kind := "workflow"
	if strings.Contains(lower, "/agents/") || strings.HasPrefix(lower, ".github/agents/") {
		kind = "agent"
	}
	return model.Reference{Type: kind, Reference: importedName(withoutSection), Locator: clean, Optional: optional, Parameters: parameters}
}

func resourceReferences(node *yaml.Node) []model.Reference {
	values := stringList(node)
	result := make([]model.Reference, 0, len(values))
	for _, value := range values {
		result = append(result, model.Reference{Type: "resource", Reference: strings.TrimSpace(value)})
	}
	return result
}

func markdownImportReferences(content []byte) []model.Reference {
	var result []model.Reference
	for _, match := range markdownImportPattern.FindAllStringSubmatch(string(content), -1) {
		if len(match) < 4 {
			continue
		}
		kind := "workflow"
		if match[1] == "runtime-" {
			kind = "instruction-set"
		}
		result = append(result, model.Reference{Type: kind, Reference: importedName(match[3]), Locator: match[3], Optional: match[2] == "?"})
	}
	return result
}

func importedName(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), "?")
	value = strings.SplitN(value, "#", 2)[0]
	if at := strings.LastIndex(value, "@"); at > strings.LastIndex(value, "/") {
		value = value[:at]
	}
	base := filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func parseFrontmatter(content []byte) (*yaml.Node, error) {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return nil, fmt.Errorf("workflow must start with YAML frontmatter")
	}
	end := strings.Index(text[4:], "\n---")
	if end < 0 {
		return nil, fmt.Errorf("frontmatter has no closing delimiter")
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text[4:4+end]), &document); err != nil {
		return nil, err
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("frontmatter must be a mapping")
	}
	return document.Content[0], nil
}

func permissionCapabilities(node *yaml.Node, evidenceID string) []model.Capability {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		switch strings.ToLower(node.Value) {
		case "read-all":
			return []model.Capability{{Action: "github.repository.*", Resource: "github:repository", Effect: "read", EvidenceIDs: []string{evidenceID}}}
		case "write-all":
			return []model.Capability{{Action: "github.repository.*", Resource: "github:repository", Effect: "write", EvidenceIDs: []string{evidenceID}}}
		default:
			return nil
		}
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	for index := 0; index+1 < len(node.Content); index += 2 {
		rawScope := strings.ToLower(node.Content[index].Value)
		scope := strings.ReplaceAll(rawScope, "-", ".")
		effect := strings.ToLower(scalar(node.Content[index+1]))
		if effect == "" || effect == "none" {
			continue
		}
		if rawScope == "id-token" && effect == "write" {
			result = append(result, model.Capability{Action: "identity.oidc.request", Resource: "github:oidc-token", Effect: "execute", EvidenceIDs: []string{evidenceID}})
			continue
		}
		if rawScope == "copilot-requests" && effect == "write" {
			result = append(result, model.Capability{Action: "ai.inference.request", Resource: "github:copilot", Effect: "execute", EvidenceIDs: []string{evidenceID}})
			continue
		}
		result = append(result, model.Capability{Action: "github." + scope + ".*", Resource: "github:repository", Effect: effect, EvidenceIDs: []string{evidenceID}})
	}
	return result
}

func safeOutputCapabilities(node *yaml.Node, evidenceID string) []model.Capability {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	for index := 0; index+1 < len(node.Content); index += 2 {
		name := node.Content[index].Value
		if name == "jobs" {
			continue
		}
		result = append(result, model.Capability{
			Action:   "github.safe-output." + strings.ReplaceAll(name, "-", "."),
			Resource: "github:repository", Effect: "write", EvidenceIDs: []string{evidenceID},
		})
	}
	return result
}

func toolReferences(node *yaml.Node) []model.Reference {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	ignored := map[string]struct{}{"timeout": {}, "startup-timeout": {}, "mcp-servers": {}}
	var result []model.Reference
	for index := 0; index+1 < len(node.Content); index += 2 {
		name := node.Content[index].Value
		if _, skip := ignored[name]; skip {
			continue
		}
		result = append(result, model.Reference{Type: "gh-aw-tool", Reference: name})
	}
	return result
}

func toolCapabilities(node *yaml.Node, evidenceID string) []model.Capability {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	if mappingValue(node, "bash") != nil {
		result = append(result, model.Capability{Action: "shell.execute", Resource: "workspace:commands", Effect: "execute", EvidenceIDs: []string{evidenceID}})
	}
	if mappingValue(node, "edit") != nil {
		result = append(result, model.Capability{Action: "filesystem.modify", Resource: "workspace:repository", Effect: "write", EvidenceIDs: []string{evidenceID}})
	}
	return result
}

func mcpReferences(node *yaml.Node) []model.Reference {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Reference
	for index := 0; index+1 < len(node.Content); index += 2 {
		result = append(result, model.Reference{Type: "mcp-server", Reference: node.Content[index].Value})
	}
	return result
}

func networkControls(node *yaml.Node) []model.Control {
	if node == nil {
		return []model.Control{{Type: "networkPolicy", Value: "defaults"}}
	}
	if node.Kind == yaml.ScalarNode {
		return []model.Control{{Type: "networkPolicy", Value: node.Value}}
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	return []model.Control{
		{Type: "networkAllowed", Value: stringList(mappingValue(node, "allowed"))},
		{Type: "networkBlocked", Value: stringList(mappingValue(node, "blocked"))},
	}
}

func networkCapabilities(node *yaml.Node, evidenceID string) []model.Capability {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	for _, target := range stringList(mappingValue(node, "allowed")) {
		result = append(result, model.Capability{Action: "network.connect", Resource: "network:" + target, Effect: "execute", EvidenceIDs: []string{evidenceID}})
	}
	return result
}

func credentialReferences(content []byte) []model.CredentialReference {
	seen := map[string]struct{}{}
	for _, match := range secretPattern.FindAllStringSubmatch(string(content), -1) {
		if len(match) == 2 {
			seen[strings.ToUpper(match[1])] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]model.CredentialReference, 0, len(names))
	for _, name := range names {
		result = append(result, model.CredentialReference{Type: "github-actions-secret", Reference: name, ValueCaptured: false})
	}
	return result
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
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

func mappingKeys(node *yaml.Node, excluded ...string) []string {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	exclusions := map[string]struct{}{}
	for _, value := range excluded {
		exclusions[value] = struct{}{}
	}
	var result []string
	for index := 0; index+1 < len(node.Content); index += 2 {
		value := node.Content[index].Value
		if _, skip := exclusions[value]; !skip {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func scalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func stringList(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		return []string{strings.TrimSpace(node.Value)}
	}
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var result []string
	for _, item := range node.Content {
		if value := scalar(item); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func normalizeSkillReference(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if strings.HasSuffix(strings.ToLower(value), "/skill.md") {
		value = strings.TrimSuffix(value, "/SKILL.md")
		value = strings.TrimSuffix(value, "/skill.md")
	}
	if strings.Contains(value, "/") {
		return filepath.Base(value)
	}
	return value
}

func uniqueReferences(values []model.Reference) []model.Reference {
	seen := map[string]model.Reference{}
	for _, value := range values {
		if value.Reference != "" {
			seen[value.Type+"\x00"+value.Reference] = value
		}
	}
	result := make([]model.Reference, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Type+result[i].Reference < result[j].Type+result[j].Reference })
	return result
}

func uniqueCapabilities(values []model.Capability) []model.Capability {
	seen := map[string]model.Capability{}
	for _, value := range values {
		seen[value.Action+"\x00"+value.Resource+"\x00"+value.Effect] = value
	}
	result := make([]model.Capability, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Action+result[i].Resource+result[i].Effect < result[j].Action+result[j].Resource+result[j].Effect
	})
	return result
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("gh-aw-%x", sum[:6])
}
