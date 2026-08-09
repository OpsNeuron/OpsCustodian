package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

type document struct {
	MCPServers map[string]server `json:"mcpServers" yaml:"mcpServers"`
	Servers    map[string]server `json:"servers" yaml:"servers"`
}

type server struct {
	Command string            `json:"command" yaml:"command"`
	URL     string            `json:"url" yaml:"url"`
	Args    []string          `json:"args" yaml:"args"`
	Env     map[string]string `json:"env" yaml:"env"`
}

func (Parser) Name() string { return "mcp" }

func (Parser) Supports(a discovery.Artifact) bool {
	base := strings.ToLower(filepath.Base(a.RelPath))
	return base == "mcp.json" || base == ".mcp.json" || base == "mcp.yaml" || base == "mcp.yml"
}

func (Parser) Parse(_ context.Context, a discovery.Artifact) ([]model.Agent, error) {
	var doc document
	var err error
	if strings.HasSuffix(strings.ToLower(a.RelPath), ".json") {
		err = json.Unmarshal(a.Content, &doc)
	} else {
		err = yaml.Unmarshal(a.Content, &doc)
	}
	if err != nil {
		return nil, fmt.Errorf("parse MCP configuration %s: %w", a.RelPath, err)
	}
	for name, value := range doc.Servers {
		if _, exists := doc.MCPServers[name]; !exists {
			if doc.MCPServers == nil {
				doc.MCPServers = map[string]server{}
			}
			doc.MCPServers[name] = value
		}
	}

	names := make([]string, 0, len(doc.MCPServers))
	for name := range doc.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	agents := make([]model.Agent, 0, len(names))
	for _, name := range names {
		value := doc.MCPServers[name]
		reference := value.URL
		transport := "remote"
		if reference == "" {
			reference = strings.TrimSpace(strings.Join(append([]string{value.Command}, value.Args...), " "))
			transport = "stdio"
		}
		evidenceID := stableID(a.RelPath + ":" + name)
		agent := model.Agent{
			ID: "mcp:" + a.RelPath + ":" + name, Type: "mcp-server", Name: name,
			Source:  model.Source{Path: a.RelPath},
			Runtime: &model.Runtime{Type: "mcp-server", Reference: reference},
			Tools:   []model.Reference{{Type: "mcp-server", Reference: name}},
			Capabilities: []model.Capability{{
				Action: "mcp.tools.invoke", Resource: "mcp:" + name, Effect: "execute",
				EvidenceIDs: []string{evidenceID},
			}},
			Controls: []model.Control{{Type: "transport", Value: transport}},
			Evidence: []model.Evidence{{
				ID: evidenceID, Path: a.RelPath, Parser: "mcp", Confidence: "high",
				Observation: "configured MCP server " + name,
			}},
		}
		envNames := make([]string, 0, len(value.Env))
		for envName := range value.Env {
			envNames = append(envNames, envName)
		}
		sort.Strings(envNames)
		for _, envName := range envNames {
			agent.Credentials = append(agent.Credentials, model.CredentialReference{
				Type: "environment-reference", Reference: envName, ValueCaptured: false,
			})
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("mcp-%x", sum[:6])
}
