package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
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

var exactVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
var sha256DigestPattern = regexp.MustCompile(`(?i)@sha256:[0-9a-f]{64}$`)

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
		evidenceID := stableID(a.RelPath + ":" + name)
		provenance, reference := classifyProvenance(value, evidenceID)
		agent := model.Agent{
			ID: "mcp:" + a.RelPath + ":" + name, Type: "mcp-server", Name: name,
			Source:  model.Source{Path: a.RelPath},
			Runtime: &model.Runtime{Type: "mcp-server", Reference: reference},
			Tools:   []model.Reference{{Type: "mcp-server", Reference: name}},
			Capabilities: []model.Capability{{
				Action: "mcp.tools.invoke", Resource: "mcp:" + name, Effect: "execute",
				EvidenceIDs: []string{evidenceID},
			}},
			Controls: []model.Control{
				{Type: "transport", Value: provenance.Transport},
				{Type: "mcpServerProvenance", Value: provenance},
			},
			Evidence: []model.Evidence{{
				ID: evidenceID, Path: a.RelPath, Parser: "mcp", Confidence: "high",
				Observation: "configured MCP server " + name,
			}},
		}
		if !provenance.Pinned {
			agent.Controls = append(agent.Controls, model.Control{Type: "mcpMutableRuntimeExposure", Value: provenance})
		}
		if provenance.SourceType == "remote-endpoint" && !provenance.TLS {
			agent.Controls = append(agent.Controls, model.Control{Type: "mcpInsecureTransportExposure", Value: provenance})
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

func classifyProvenance(value server, evidenceID string) (model.MCPServerProvenance, string) {
	if strings.TrimSpace(value.URL) != "" {
		return classifyRemoteProvenance(value.URL, evidenceID)
	}
	command := strings.ToLower(filepath.Base(strings.TrimSpace(value.Command)))
	provenance := model.MCPServerProvenance{
		Transport: "stdio", Launcher: command, SourceType: "system-executable",
		PinType: "unversioned", Integrity: "unknown", EvidenceIDs: []string{evidenceID},
	}
	switch command {
	case "npx", "npx.exe", "pnpm", "pnpm.exe", "yarn", "yarn.exe", "bunx", "bunx.exe":
		candidate := firstPackageArgument(value.Args)
		name, version := splitNPMPackage(candidate)
		provenance.SourceType, provenance.Registry, provenance.Package, provenance.Version = "npm-package", "npm", name, version
		classifyVersionPin(&provenance, version)
	case "uvx", "uvx.exe", "pipx", "pipx.exe":
		candidate := firstPackageArgument(value.Args)
		name, version := splitPythonPackage(candidate)
		provenance.SourceType, provenance.Registry, provenance.Package, provenance.Version = "python-package", "pypi", name, version
		classifyVersionPin(&provenance, version)
	case "docker", "docker.exe", "podman", "podman.exe":
		image := containerImageArgument(value.Args)
		provenance.SourceType, provenance.Registry, provenance.Package = "oci-image", "oci", image
		switch {
		case sha256DigestPattern.MatchString(image):
			provenance.PinType, provenance.Pinned, provenance.Integrity = "digest", true, "sha256"
		case strings.Contains(image, ":"):
			provenance.PinType, provenance.Integrity = "tag", "none"
		default:
			provenance.PinType, provenance.Integrity = "latest", "none"
		}
	default:
		if localReference := localExecutionReference(value.Command, value.Args); localReference != "" {
			provenance.Package = localReference
			if strings.HasPrefix(localReference, "../") {
				provenance.SourceType, provenance.PinType, provenance.Integrity = "external-local-path", "outside-repository", "unknown"
			} else {
				provenance.SourceType, provenance.PinType, provenance.Pinned, provenance.Integrity = "local-path", "same-revision", true, "same-revision"
			}
		}
	}
	return provenance, provenanceReference(provenance)
}

func classifyRemoteProvenance(rawURL, evidenceID string) (model.MCPServerProvenance, string) {
	provenance := model.MCPServerProvenance{
		Transport: "remote", SourceType: "remote-endpoint", PinType: "endpoint-unversioned",
		Integrity: "unknown", EvidenceIDs: []string{evidenceID},
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil {
		provenance.EndpointHost = parsed.Hostname()
		provenance.TLS = strings.EqualFold(parsed.Scheme, "https")
		parsed.User, parsed.RawQuery, parsed.Fragment = nil, "", ""
		return provenance, parsed.String()
	}
	return provenance, "remote-endpoint"
}

func classifyVersionPin(provenance *model.MCPServerProvenance, version string) {
	switch {
	case exactVersionPattern.MatchString(version):
		provenance.PinType, provenance.Pinned, provenance.Integrity = "exact-version", true, "version"
	case version == "":
		provenance.PinType, provenance.Integrity = "unversioned", "none"
	case strings.EqualFold(version, "latest"):
		provenance.PinType, provenance.Integrity = "latest", "none"
	case strings.ContainsAny(version, "^~*<>=|"):
		provenance.PinType, provenance.Integrity = "version-range", "none"
	default:
		provenance.PinType, provenance.Integrity = "tag", "none"
	}
}

func firstPackageArgument(args []string) string {
	skipNext := false
	valueFlags := map[string]struct{}{"--registry": {}, "--cache": {}, "--userconfig": {}, "--prefix": {}}
	for index, arg := range args {
		arg = strings.TrimSpace(arg)
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "-p" || arg == "--package" || arg == "--from" {
			if index+1 < len(args) {
				return strings.TrimSpace(args[index+1])
			}
			return ""
		}
		if strings.HasPrefix(arg, "--package=") || strings.HasPrefix(arg, "--from=") {
			return strings.TrimSpace(strings.SplitN(arg, "=", 2)[1])
		}
		if _, takesValue := valueFlags[arg]; takesValue {
			skipNext = true
			continue
		}
		if arg != "" && !strings.HasPrefix(arg, "-") && arg != "dlx" {
			return arg
		}
	}
	return ""
}

func splitNPMPackage(value string) (string, string) {
	index := strings.LastIndex(value, "@")
	if index > 0 {
		return value[:index], value[index+1:]
	}
	return value, ""
}

func splitPythonPackage(value string) (string, string) {
	if parts := strings.SplitN(value, "==", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	return value, ""
}

func containerImageArgument(args []string) string {
	seenRun := false
	skipNext := false
	valueFlags := map[string]struct{}{"-e": {}, "--env": {}, "-v": {}, "--volume": {}, "--mount": {}, "--name": {}, "--network": {}, "-w": {}, "--workdir": {}, "-u": {}, "--user": {}}
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "run" {
			seenRun = true
			continue
		}
		if !seenRun {
			continue
		}
		if _, takesValue := valueFlags[arg]; takesValue {
			skipNext = true
			continue
		}
		if arg != "" && !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return ""
}

func localExecutionReference(command string, args []string) string {
	values := append([]string{command}, args...)
	for _, value := range values {
		value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
		if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "$/") {
			return value
		}
	}
	return ""
}

func provenanceReference(value model.MCPServerProvenance) string {
	switch value.SourceType {
	case "npm-package":
		return "npm:" + value.Package + versionSuffix(value.Version)
	case "python-package":
		return "pypi:" + value.Package + versionSuffix(value.Version)
	case "oci-image":
		return "oci:" + value.Package
	case "local-path", "external-local-path":
		return "local:" + value.Package
	default:
		return "executable:" + value.Launcher
	}
}

func versionSuffix(version string) string {
	if version == "" {
		return ""
	}
	return "@" + version
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("mcp-%x", sum[:6])
}
