package agentmarkdown

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/parsers/yamlguard"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

func (Parser) Name() string { return "agent-markdown" }

func (Parser) Supports(artifact discovery.Artifact) bool {
	lowerPath := strings.ToLower(artifact.RelPath)
	base := strings.ToLower(filepath.Base(lowerPath))
	ext := strings.ToLower(filepath.Ext(lowerPath))
	if base == "agents.md" || base == "claude.md" {
		return true
	}
	if strings.HasPrefix(lowerPath, ".github/agents/") && (ext == ".md" || ext == ".mdc") {
		return true
	}
	if strings.HasPrefix(lowerPath, ".cursor/rules/") && (ext == ".md" || ext == ".mdc") {
		return true
	}
	return base == "skill.md" && (strings.Contains(lowerPath, ".claude/skills/") || strings.Contains(lowerPath, ".codex/skills/") || strings.Contains(lowerPath, ".agents/skills/"))
}

func (Parser) Parse(_ context.Context, artifact discovery.Artifact) ([]model.Agent, error) {
	metadata, hasFrontmatter, err := parseFrontmatter(artifact.Content)
	if err != nil {
		return nil, fmt.Errorf("parse frontmatter in %s: %w", artifact.RelPath, err)
	}
	lowerPath := strings.ToLower(artifact.RelPath)
	assetType := assetType(lowerPath)
	name := firstScalar(metadata, "name", "title")
	if name == "" {
		name = inferredName(artifact.RelPath, assetType)
	}
	owner := firstScalar(metadata, "owner", "maintainer")
	evidenceID := "agent-markdown:" + artifact.RelPath
	confidence := "medium"
	line := 1
	if hasFrontmatter {
		confidence = "high"
		line = 2
	}

	asset := model.Agent{
		ID: "agent-markdown:" + artifact.RelPath, Type: assetType, Name: name,
		Source:  model.Source{Path: artifact.RelPath},
		Runtime: runtimeFor(lowerPath, artifact.RelPath),
		Capabilities: []model.Capability{{
			Action: "agent.instructions.apply", Resource: assetResource(assetType, name),
			Effect: "execute", EvidenceIDs: []string{evidenceID},
		}},
		Evidence: []model.Evidence{{
			ID: evidenceID, Path: artifact.RelPath, Line: line, Parser: "agent-markdown",
			Confidence: confidence, Observation: "agentic Markdown asset",
		}},
	}
	if owner != "" {
		asset.Owners = []string{owner}
	}

	toolNames := append([]string{}, scalarList(metadata, "tools")...)
	toolNames = append(toolNames, scalarList(metadata, "allowed-tools")...)
	toolNames = append(toolNames, scalarList(metadata, "allowedTools")...)
	for _, name := range uniqueSorted(toolNames) {
		asset.Tools = append(asset.Tools, model.Reference{Type: "declared-tool", Reference: name})
	}
	for _, name := range uniqueSorted(append(scalarList(metadata, "mcp-servers"), scalarList(metadata, "mcpServers")...)) {
		asset.Tools = append(asset.Tools, model.Reference{Type: "mcp-server", Reference: name})
	}
	dependencyNames := append([]string{}, scalarList(metadata, "skills")...)
	dependencyNames = append(dependencyNames, scalarList(metadata, "dependencies")...)
	for _, name := range uniqueSorted(dependencyNames) {
		asset.Dependencies = append(asset.Dependencies, model.Reference{Type: "skill", Reference: name})
	}
	if selectedModel := firstScalar(metadata, "model"); selectedModel != "" {
		asset.Controls = append(asset.Controls, model.Control{Type: "modelPreference", Value: selectedModel})
	}
	return []model.Agent{asset}, nil
}

func parseFrontmatter(content []byte) (*yaml.Node, bool, error) {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return nil, false, nil
	}
	end := strings.Index(text[4:], "\n---\n")
	if end < 0 {
		return nil, false, fmt.Errorf("frontmatter has no closing delimiter")
	}
	header := text[4 : 4+end]
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(header), &document); err != nil {
		return nil, false, err
	}
	if len(document.Content) == 0 {
		return nil, true, nil
	}
	if err := yamlguard.ValidateMappingKeys(&document); err != nil {
		return nil, false, err
	}
	return document.Content[0], true, nil
}

func firstScalar(node *yaml.Node, keys ...string) string {
	for _, key := range keys {
		value := mappingValue(node, key)
		if value != nil && value.Kind == yaml.ScalarNode {
			return strings.TrimSpace(value.Value)
		}
	}
	return ""
}

func scalarList(node *yaml.Node, key string) []string {
	value := mappingValue(node, key)
	if value == nil {
		return nil
	}
	if value.Kind == yaml.ScalarNode {
		parts := strings.FieldsFunc(value.Value, func(r rune) bool { return r == ',' || r == '\n' })
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		return parts
	}
	if value.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]string, 0, len(value.Content))
	for _, item := range value.Content {
		if item.Kind == yaml.ScalarNode && strings.TrimSpace(item.Value) != "" {
			result = append(result, strings.TrimSpace(item.Value))
		}
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

func assetType(lowerPath string) string {
	if strings.Contains(lowerPath, "/skills/") || strings.Contains(lowerPath, "skills/") {
		return "skill"
	}
	if strings.HasPrefix(lowerPath, ".github/agents/") {
		return "agent"
	}
	return "instruction-set"
}

func inferredName(path, kind string) string {
	base := filepath.Base(path)
	if strings.EqualFold(base, "SKILL.md") {
		return filepath.Base(filepath.Dir(path))
	}
	if strings.EqualFold(base, "AGENTS.md") {
		return "repository-agents"
	}
	if strings.EqualFold(base, "CLAUDE.md") {
		return "claude-instructions"
	}
	name := strings.TrimSuffix(base, filepath.Ext(base))
	name = strings.TrimSuffix(name, ".agent")
	if name == "" {
		return kind
	}
	return name
}

func runtimeFor(lowerPath, reference string) *model.Runtime {
	runtimeType := "repository-instructions"
	switch {
	case strings.Contains(lowerPath, ".claude/") || strings.HasSuffix(lowerPath, "claude.md"):
		runtimeType = "claude-code"
	case strings.Contains(lowerPath, ".codex/"):
		runtimeType = "codex"
	case strings.Contains(lowerPath, ".cursor/"):
		runtimeType = "cursor"
	case strings.Contains(lowerPath, ".github/agents/"):
		runtimeType = "github-agent"
	}
	return &model.Runtime{Type: runtimeType, Reference: reference}
}

func assetResource(kind, name string) string { return kind + ":" + name }

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
