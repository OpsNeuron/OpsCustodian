package effective

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestComposeMCPFindingsClassifiesCurrentStateProvenance(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		mcpFindingAsset("mcp:pinned", model.MCPServerProvenance{SourceType: "npm-package", Package: "@acme/server", Version: "1.2.3", PinType: "exact-version", Pinned: true, Integrity: "version"}),
		mcpFindingAsset("mcp:latest", model.MCPServerProvenance{SourceType: "npm-package", Package: "@acme/server", Version: "latest", PinType: "latest", Integrity: "none"}),
		mcpFindingAsset("mcp:remote", model.MCPServerProvenance{SourceType: "remote-endpoint", Transport: "remote", EndpointHost: "MCP.EXAMPLE.COM", PinType: "endpoint-unversioned", Integrity: "unknown"}),
		mcpFindingAsset("mcp:outside", model.MCPServerProvenance{SourceType: "external-local-path", Package: "../server", PinType: "outside-repository", Integrity: "unknown"}),
	}}

	ComposeMCPFindings(&bom)

	if len(bom.Findings) != 3 {
		t.Fatalf("expected three MCP findings, got %#v", bom.Findings)
	}
	if findingByType(t, bom.Findings, "mcp-runtime-unpinned", "mcp:latest").Severity != "high" {
		t.Fatal("mutable npm runtime did not produce a high finding")
	}
	remote := findingByType(t, bom.Findings, "mcp-insecure-transport", "mcp:remote")
	if remote.Attributes["endpointHost"] != "mcp.example.com" || remote.Attributes["tls"] != false {
		t.Fatalf("unexpected sanitized remote attributes: %#v", remote.Attributes)
	}
	if findingByType(t, bom.Findings, "mcp-repository-boundary-escape", "mcp:outside").ID == "" {
		t.Fatal("outside-repository finding lacks a stable ID")
	}
	content, _ := json.Marshal(bom.Findings)
	if strings.Contains(string(content), "secret-value") {
		t.Fatalf("secret leaked into findings: %s", content)
	}
}

func TestComposeMCPFindingsDecodesPersistedControlShape(t *testing.T) {
	asset := mcpFindingAsset("mcp:persisted", model.MCPServerProvenance{})
	asset.Controls[0].Value = map[string]any{
		"sourceType": "oci-image", "package": "ghcr.io/acme/server:latest", "pinType": "tag", "pinned": false, "integrity": "none",
	}
	bom := model.AgentBOM{Assets: []model.Asset{asset}}
	ComposeMCPFindings(&bom)
	if len(bom.Findings) != 1 || bom.Findings[0].Type != "mcp-runtime-unpinned" {
		t.Fatalf("persisted control was not analyzed: %#v", bom.Findings)
	}
}

func mcpFindingAsset(id string, provenance model.MCPServerProvenance) model.Asset {
	return model.Asset{
		ID: id, Type: "mcp-server", Name: id, Source: model.Source{Path: ".mcp.json"},
		Controls:    []model.Control{{Type: "mcpServerProvenance", Value: provenance}},
		Credentials: []model.CredentialReference{{Type: "environment-reference", Reference: "TOKEN_SECRET_VALUE", ValueCaptured: false}},
		Evidence:    []model.Evidence{{ID: "mcp-evidence-" + id, Path: ".mcp.json", Parser: "mcp", Confidence: "high"}},
	}
}
