package githubactions

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

var secretPattern = regexp.MustCompile(`(?i)secrets\.([A-Z0-9_]+)`)

func (Parser) Name() string { return "github-actions" }

func (Parser) Supports(a discovery.Artifact) bool {
	return strings.HasPrefix(a.RelPath, ".github/workflows/") &&
		(filepath.Ext(a.RelPath) == ".yml" || filepath.Ext(a.RelPath) == ".yaml")
}

func (Parser) Parse(_ context.Context, a discovery.Artifact) ([]model.Agent, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(a.Content, &root); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions workflow %s: %w", a.RelPath, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow %s must be a mapping", a.RelPath)
	}
	doc := root.Content[0]
	name := scalarValue(mappingValue(doc, "name"))
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(a.RelPath), filepath.Ext(a.RelPath))
	}
	evidenceID := stableID("gha", a.RelPath)
	agent := model.Agent{
		ID:   "github-actions:" + a.RelPath,
		Name: name,
		Source: model.Source{Path: a.RelPath},
		Runtime: &model.Runtime{Type: "github-actions", Reference: a.RelPath},
		Evidence: []model.Evidence{{
			ID: evidenceID, Path: a.RelPath, Line: doc.Line, Column: doc.Column,
			Parser: "github-actions", Confidence: "high", Observation: "workflow definition",
		}},
	}

	permissions := mappingValue(doc, "permissions")
	agent.Capabilities = append(agent.Capabilities, permissionCapabilities(permissions, evidenceID)...)
	jobs := mappingValue(doc, "jobs")
	if jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
			jobEvidence := stableID("gha-job", a.RelPath+":"+jobName)
			agent.Evidence = append(agent.Evidence, model.Evidence{
				ID: jobEvidence, Path: a.RelPath, Line: job.Line, Column: job.Column,
				Parser: "github-actions", Confidence: "high", Observation: "job " + jobName,
			})
			agent.Capabilities = append(agent.Capabilities,
				permissionCapabilities(mappingValue(job, "permissions"), jobEvidence)...)
			if environment := scalarValue(mappingValue(job, "environment")); environment != "" {
				agent.Controls = append(agent.Controls, model.Control{Type: "environment", Value: environment})
			}
		}
	}

	seenSecrets := map[string]struct{}{}
	for _, match := range secretPattern.FindAllStringSubmatch(string(a.Content), -1) {
		if len(match) != 2 {
			continue
		}
		name := strings.ToUpper(match[1])
		if _, exists := seenSecrets[name]; exists {
			continue
		}
		seenSecrets[name] = struct{}{}
		agent.Credentials = append(agent.Credentials, model.CredentialReference{
			Type: "github-actions-secret", Reference: name, ValueCaptured: false,
		})
	}
	sort.Slice(agent.Credentials, func(i, j int) bool {
		return agent.Credentials[i].Reference < agent.Credentials[j].Reference
	})
	agent.Capabilities = uniqueCapabilities(agent.Capabilities)
	return []model.Agent{agent}, nil
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
		case "{}", "none":
			return nil
		}
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	for i := 0; i+1 < len(node.Content); i += 2 {
		scope := strings.ToLower(node.Content[i].Value)
		level := strings.ToLower(node.Content[i+1].Value)
		if level == "none" || level == "" {
			continue
		}
		result = append(result, model.Capability{
			Action: "github." + strings.ReplaceAll(scope, "-", ".") + ".*",
			Resource: "github:repository", Effect: level, EvidenceIDs: []string{evidenceID},
		})
	}
	return result
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func stableID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s-%x", prefix, sum[:6])
}

func uniqueCapabilities(values []model.Capability) []model.Capability {
	seen := map[string]model.Capability{}
	for _, value := range values {
		key := value.Action + "\x00" + value.Resource + "\x00" + value.Effect + "\x00" + value.Environment
		seen[key] = value
	}
	result := make([]model.Capability, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Action+result[i].Effect < result[j].Action+result[j].Effect
	})
	return result
}
