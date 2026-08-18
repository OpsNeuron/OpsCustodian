package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

func TestParseClassifiesMCPRuntimeProvenanceWithoutCapturingSecrets(t *testing.T) {
	content := `{
  "mcpServers": {
		"npm-pinned": {"command":"npx","args":["--registry","https://registry.example.com","-y","@acme/mcp-server@1.2.3","--token","super-secret"]},
    "npm-latest": {"command":"npx","args":["@acme/mcp-server@latest"]},
    "python-pinned": {"command":"uvx","args":["acme-mcp==2.4.0"]},
    "container-digest": {"command":"docker","args":["run","--env","TOKEN=super-secret","ghcr.io/acme/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
    "local": {"command":"node","args":["./tools/mcp.js","--token","super-secret"]},
    "remote-tls": {"url":"https://user:super-secret@mcp.example.com/sse?token=super-secret"},
    "remote-plain": {"url":"http://mcp.example.com/sse"}
  }
}`
	assets, err := (Parser{}).Parse(context.Background(), discovery.Artifact{RelPath: ".mcp.json", Content: []byte(content)})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(assets) != 7 {
		t.Fatalf("expected 7 MCP assets, got %d", len(assets))
	}

	tests := []struct {
		name, sourceType, pinType, integrity string
		pinned, tls                          bool
	}{
		{"npm-pinned", "npm-package", "exact-version", "version", true, false},
		{"npm-latest", "npm-package", "latest", "none", false, false},
		{"python-pinned", "python-package", "exact-version", "version", true, false},
		{"container-digest", "oci-image", "digest", "sha256", true, false},
		{"local", "local-path", "same-revision", "same-revision", true, false},
		{"remote-tls", "remote-endpoint", "endpoint-unversioned", "unknown", false, true},
		{"remote-plain", "remote-endpoint", "endpoint-unversioned", "unknown", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			asset := mcpAssetByName(t, assets, test.name)
			provenance := mcpProvenance(t, asset)
			if provenance.SourceType != test.sourceType || provenance.PinType != test.pinType || provenance.Integrity != test.integrity || provenance.Pinned != test.pinned || provenance.TLS != test.tls {
				t.Fatalf("unexpected provenance: %#v", provenance)
			}
			if strings.Contains(asset.Runtime.Reference, "super-secret") || strings.Contains(strings.ToLower(asset.Runtime.Reference), "token=") {
				t.Fatalf("runtime reference captured a secret-bearing argument: %q", asset.Runtime.Reference)
			}
		})
	}
	plain := mcpAssetByName(t, assets, "remote-plain")
	if !hasMCPControl(plain, "mcpMutableRuntimeExposure") || !hasMCPControl(plain, "mcpInsecureTransportExposure") {
		t.Fatalf("insecure remote endpoint lacks exposure controls: %#v", plain.Controls)
	}
}

func TestParseTreatsVersionRangeAndOutsideRepositoryPathAsUnpinned(t *testing.T) {
	content := `{"mcpServers":{"range":{"command":"npx","args":["server@^1.2.0"]},"outside":{"command":"node","args":["../shared/server.js"]}}}`
	assets, err := (Parser{}).Parse(context.Background(), discovery.Artifact{RelPath: "mcp.json", Content: []byte(content)})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if value := mcpProvenance(t, mcpAssetByName(t, assets, "range")); value.PinType != "version-range" || value.Pinned {
		t.Fatalf("version range classified as pinned: %#v", value)
	}
	if value := mcpProvenance(t, mcpAssetByName(t, assets, "outside")); value.SourceType != "external-local-path" || value.Pinned {
		t.Fatalf("outside-repository path classified as same revision: %#v", value)
	}
}

func mcpAssetByName(t *testing.T, assets []model.Agent, name string) model.Agent {
	t.Helper()
	for _, asset := range assets {
		if asset.Name == name {
			return asset
		}
	}
	t.Fatalf("MCP asset %q not found", name)
	return model.Agent{}
}

func mcpProvenance(t *testing.T, asset model.Agent) model.MCPServerProvenance {
	t.Helper()
	for _, control := range asset.Controls {
		if control.Type == "mcpServerProvenance" {
			value, ok := control.Value.(model.MCPServerProvenance)
			if !ok {
				t.Fatalf("unexpected provenance control type: %T", control.Value)
			}
			return value
		}
	}
	t.Fatal("mcpServerProvenance control not found")
	return model.MCPServerProvenance{}
}

func hasMCPControl(asset model.Agent, controlType string) bool {
	for _, control := range asset.Controls {
		if control.Type == controlType {
			return true
		}
	}
	return false
}
