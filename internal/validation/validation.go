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
	for agentIndex, agent := range bom.Agents {
		base := fmt.Sprintf("agents[%d]", agentIndex)
		if agent.ID == "" {
			issues = append(issues, issue(base+".id", "required", "agent id is required"))
		} else if _, exists := agentIDs[agent.ID]; exists {
			issues = append(issues, issue(base+".id", "duplicate", "agent id must be unique"))
		} else {
			agentIDs[agent.ID] = struct{}{}
		}
		if agent.Name == "" {
			issues = append(issues, issue(base+".name", "required", "agent name is required"))
		}
		if agent.Source.Path == "" {
			issues = append(issues, issue(base+".source.path", "required", "source path is required"))
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
	return issues
}

func issue(path, code, message string) Issue {
	return Issue{Path: path, Code: code, Message: message}
}
