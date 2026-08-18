package effective

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

// ComposeMCPFindings converts secret-safe MCP provenance into current-state
// findings without process execution, registry lookup, or network IO.
func ComposeMCPFindings(bom *model.AgentBOM) {
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		if asset.Type != "mcp-server" {
			continue
		}
		provenance, ok := mcpServerProvenance(asset.Controls)
		if !ok {
			continue
		}
		evidence := assetFindingEvidence(asset, "mcp")
		attributes := mcpFindingAttributes(provenance)
		if provenance.SourceType == "external-local-path" {
			appendFinding(bom, model.Finding{
				Type: "mcp-repository-boundary-escape", Severity: "high", AssetID: asset.ID,
				Title:         "MCP runtime executes outside the repository boundary",
				Reason:        "MCP executable path is outside the scanned repository revision.",
				RemediationID: "mcp.enforce-repository-boundary",
				Remediation:   "Move the executable into the governed repository or replace it with an immutable, verified package or image reference.",
				Evidence:      evidence, Attributes: attributes,
			})
		}
		if provenance.SourceType == "remote-endpoint" && !provenance.TLS {
			appendFinding(bom, model.Finding{
				Type: "mcp-insecure-transport", Severity: "high", AssetID: asset.ID,
				Title:         "Remote MCP server does not use TLS",
				Reason:        "Remote MCP endpoint uses plaintext or an unknown transport scheme.",
				RemediationID: "mcp.require-tls",
				Remediation:   "Use an HTTPS endpoint with certificate validation and keep credentials outside the URL.",
				Evidence:      evidence, Attributes: attributes,
			})
		}
		if mutableMCPRuntime(provenance) {
			severity := "medium"
			if provenance.SourceType == "npm-package" || provenance.SourceType == "python-package" || provenance.SourceType == "oci-image" {
				severity = "high"
			}
			appendFinding(bom, model.Finding{
				Type: "mcp-runtime-unpinned", Severity: severity, AssetID: asset.ID,
				Title:         "MCP runtime identity is mutable or unverified",
				Reason:        fmt.Sprintf("MCP runtime uses %s pinning with %s integrity.", provenance.PinType, provenance.Integrity),
				RemediationID: "mcp.pin-runtime",
				Remediation:   "Pin packages to an exact version and OCI images to a SHA-256 digest; govern system executable versions outside the BOM.",
				Evidence:      evidence, Attributes: attributes,
			})
		}
	}
}

func mcpServerProvenance(controls []model.Control) (model.MCPServerProvenance, bool) {
	for _, control := range controls {
		if control.Type != "mcpServerProvenance" {
			continue
		}
		if value, ok := control.Value.(model.MCPServerProvenance); ok {
			return value, true
		}
		content, err := json.Marshal(control.Value)
		if err != nil {
			return model.MCPServerProvenance{}, false
		}
		var value model.MCPServerProvenance
		if err := json.Unmarshal(content, &value); err != nil {
			return model.MCPServerProvenance{}, false
		}
		return value, true
	}
	return model.MCPServerProvenance{}, false
}

func mutableMCPRuntime(value model.MCPServerProvenance) bool {
	if value.Pinned || value.SourceType == "local-path" || value.SourceType == "external-local-path" || value.SourceType == "remote-endpoint" {
		return false
	}
	return value.PinType != ""
}

func mcpFindingAttributes(value model.MCPServerProvenance) map[string]any {
	attributes := map[string]any{
		"transport": value.Transport, "sourceType": value.SourceType,
		"pinType": value.PinType, "pinned": value.Pinned, "integrity": value.Integrity,
	}
	if value.Registry != "" {
		attributes["registry"] = value.Registry
	}
	if value.Package != "" {
		attributes["package"] = value.Package
	}
	if value.Version != "" {
		attributes["version"] = value.Version
	}
	if value.EndpointHost != "" {
		attributes["endpointHost"] = strings.ToLower(value.EndpointHost)
		attributes["tls"] = value.TLS
	}
	return attributes
}
