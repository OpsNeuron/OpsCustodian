package validation

import (
	"fmt"

	"github.com/opscustodian/opscustodian/internal/model"
)

type Issue struct {
	Path    string `json:"path" yaml:"path"`
	Code    string `json:"code" yaml:"code"`
	Message string `json:"message" yaml:"message"`
}

func Validate(bom model.AgentBOM) []Issue {
	var issues []Issue
	if bom.APIVersion != model.APIVersion {
		issues = append(issues, issue("apiVersion", "unsupported-api-version", "expected "+model.APIVersion))
	}
	if bom.Kind != model.Kind {
		issues = append(issues, issue("kind", "unsupported-kind", "expected "+model.Kind))
	}
	if bom.Metadata.Source == "" {
		issues = append(issues, issue("metadata.source", "required", "source is required"))
	}
	if bom.Metadata.Revision == "" {
		issues = append(issues, issue("metadata.revision", "required", "revision is required"))
	}

	agentIDs := map[string]struct{}{}
	evidenceByAsset := map[string]map[string]struct{}{}
	for agentIndex, agent := range bom.Assets {
		base := fmt.Sprintf("assets[%d]", agentIndex)
		if agent.ID == "" {
			issues = append(issues, issue(base+".id", "required", "asset id is required"))
		} else if _, exists := agentIDs[agent.ID]; exists {
			issues = append(issues, issue(base+".id", "duplicate", "asset id must be unique"))
		} else {
			agentIDs[agent.ID] = struct{}{}
		}
		if agent.Name == "" {
			issues = append(issues, issue(base+".name", "required", "asset name is required"))
		}
		if !validAssetType(agent.Type) {
			issues = append(issues, issue(base+".type", "unsupported-asset-type", "type must identify a supported agentic asset"))
		}
		if agent.Source.Path == "" {
			issues = append(issues, issue(base+".source.path", "required", "source path is required"))
		}
		ownerNames := map[string]struct{}{}
		for ownerIndex, owner := range agent.Owners {
			path := fmt.Sprintf("%s.owners[%d]", base, ownerIndex)
			if owner == "" {
				issues = append(issues, issue(path, "required", "owner name cannot be empty"))
				continue
			}
			if _, exists := ownerNames[owner]; exists {
				issues = append(issues, issue(path, "duplicate", "owner names must be unique"))
			}
			ownerNames[owner] = struct{}{}
		}

		evidenceIDs := map[string]struct{}{}
		for evidenceIndex, evidence := range agent.Evidence {
			path := fmt.Sprintf("%s.evidence[%d]", base, evidenceIndex)
			if evidence.ID == "" {
				issues = append(issues, issue(path+".id", "required", "evidence id is required"))
			} else if _, exists := evidenceIDs[evidence.ID]; exists {
				issues = append(issues, issue(path+".id", "duplicate", "evidence id must be unique within an agent"))
			} else {
				evidenceIDs[evidence.ID] = struct{}{}
			}
			if evidence.Path == "" || evidence.Parser == "" || evidence.Confidence == "" {
				issues = append(issues, issue(path, "incomplete-evidence", "path, parser, and confidence are required"))
			}
		}
		if len(agent.Evidence) == 0 {
			issues = append(issues, issue(base+".evidence", "required", "at least one evidence item is required"))
		}
		if agent.ID != "" {
			evidenceByAsset[agent.ID] = evidenceIDs
		}

		for credentialIndex, credential := range agent.Credentials {
			path := fmt.Sprintf("%s.credentials[%d]", base, credentialIndex)
			if credential.Type == "" || credential.Reference == "" {
				issues = append(issues, issue(path, "incomplete-reference", "credential type and reference are required"))
			}
			if credential.ValueCaptured {
				issues = append(issues, issue(path+".valueCaptured", "secret-value-forbidden", "credential values cannot be captured"))
			}
		}
		for capabilityIndex, capability := range agent.Capabilities {
			path := fmt.Sprintf("%s.capabilities[%d]", base, capabilityIndex)
			if capability.Action == "" || capability.Resource == "" || capability.Effect == "" {
				issues = append(issues, issue(path, "incomplete-capability", "action, resource, and effect are required"))
			}
			for _, evidenceID := range capability.EvidenceIDs {
				if _, exists := evidenceIDs[evidenceID]; !exists {
					issues = append(issues, issue(path+".evidenceIds", "unknown-evidence", "capability references unknown evidence "+evidenceID))
				}
			}
		}
	}
	relationIDs := map[string]struct{}{}
	for relationIndex, relation := range bom.Relationships {
		base := fmt.Sprintf("relationships[%d]", relationIndex)
		if relation.ID == "" {
			issues = append(issues, issue(base+".id", "required", "relationship id is required"))
		} else if _, exists := relationIDs[relation.ID]; exists {
			issues = append(issues, issue(base+".id", "duplicate", "relationship id must be unique"))
		} else {
			relationIDs[relation.ID] = struct{}{}
		}
		if _, exists := agentIDs[relation.From]; !exists {
			issues = append(issues, issue(base+".from", "unknown-source-asset", "relationship source must reference an asset in this BOM"))
		}
		if relation.To == "" || !validRelationshipType(relation.Type) || !validRelationshipTargetType(relation.TargetType) {
			issues = append(issues, issue(base, "invalid-relationship", "relationship type, target, and target type must be supported"))
		}
		if relation.TargetType == "asset" {
			if _, exists := agentIDs[relation.To]; !exists {
				issues = append(issues, issue(base+".to", "unknown-target-asset", "asset relationship target must exist in this BOM"))
			}
		}
		if !validConfidence(relation.Confidence) {
			issues = append(issues, issue(base+".confidence", "invalid-confidence", "confidence must be low, medium, or high"))
		}
		for _, evidenceID := range relation.EvidenceIDs {
			if _, exists := evidenceByAsset[relation.From][evidenceID]; !exists {
				issues = append(issues, issue(base+".evidenceIds", "unknown-evidence", "relationship evidence must belong to its source asset"))
			}
		}
	}
	return issues
}

func issue(path, code, message string) Issue {
	return Issue{Path: path, Code: code, Message: message}
}

func validAssetType(value string) bool {
	switch value {
	case "agent", "workflow", "mcp-server", "skill", "instruction-set":
		return true
	default:
		return false
	}
}

func validRelationshipType(value string) bool {
	switch value {
	case "uses-tool", "uses-mcp-server", "uses-credential", "depends-on", "owned-by":
		return true
	default:
		return false
	}
}

func validRelationshipTargetType(value string) bool {
	switch value {
	case "asset", "asset-reference", "tool", "credential", "owner":
		return true
	default:
		return false
	}
}

func validConfidence(value string) bool {
	return value == "low" || value == "medium" || value == "high"
}
