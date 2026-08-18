package effective

import (
	"encoding/json"
	"sort"

	"github.com/opscustodian/opscustodian/internal/model"
)

type githubTriggerFinding struct {
	Event         string `json:"event"`
	TrustBoundary string `json:"trustBoundary"`
}

type githubFlowFinding struct {
	Job, Trigger, Source, Sink, Action string
	EvidenceIDs                        []string `json:"evidenceIds"`
}

type githubRunnerFinding struct {
	Job         string   `json:"job"`
	Kind        string   `json:"kind"`
	Labels      []string `json:"labels"`
	Group       string   `json:"group"`
	EvidenceIDs []string `json:"evidenceIds"`
}

type githubDependencyFinding struct {
	Job, Kind, Reference, PinType string
	EvidenceIDs                   []string `json:"evidenceIds"`
}

// ComposeGitHubActionsFindings converts parser controls into current-state
// findings without querying GitHub or assuming unknown repository settings.
func ComposeGitHubActionsFindings(bom *model.AgentBOM) {
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		if asset.Type != "workflow" {
			continue
		}
		var triggers []githubTriggerFinding
		decodeControl(asset.Controls, "githubPrivilegedTriggerExposure", &triggers)
		if len(triggers) > 0 {
			sort.Slice(triggers, func(i, j int) bool {
				return triggers[i].Event+triggers[i].TrustBoundary < triggers[j].Event+triggers[j].TrustBoundary
			})
			appendFinding(bom, model.Finding{
				Type: "github-actions-privileged-trigger", Severity: "medium", AssetID: asset.ID,
				Title:       "Workflow uses a privileged trigger boundary",
				Reason:      "Workflow trigger can bridge lower-trust activity into a privileged repository context.",
				Remediation: "Avoid privileged triggers where possible and never execute or check out untrusted content in their jobs.",
				Evidence:    firstParserEvidence(asset, "github-actions"), Attributes: map[string]any{"exposures": triggers},
			})
		}

		var flows []githubFlowFinding
		decodeControl(asset.Controls, "githubUntrustedDataFlow", &flows)
		if len(flows) > 0 {
			severity := "high"
			for _, flow := range flows {
				if flow.Sink == "runner-shell" {
					severity = "critical"
				}
			}
			appendFinding(bom, model.Finding{
				Type: "github-actions-untrusted-data-flow", Severity: severity, AssetID: asset.ID,
				Title:       "Untrusted GitHub event data reaches an executable sink",
				Reason:      "Workflow passes attacker-influenced event data into a runner shell, workspace, or privileged artifact flow.",
				Remediation: "Use fixed trusted references and pass untrusted strings through quoted environment variables rather than expression interpolation.",
				Evidence:    evidenceForControlItems(asset, flowEvidenceIDs(flows)), Attributes: map[string]any{"flows": sanitizedFlows(flows)},
			})
		}

		var runners []githubRunnerFinding
		decodeControl(asset.Controls, "githubSelfHostedRunnerExposure", &runners)
		if len(runners) > 0 {
			severity := "medium"
			if len(flows) > 0 {
				severity = "critical"
			}
			appendFinding(bom, model.Finding{
				Type: "github-actions-self-hosted-runner-exposure", Severity: severity, AssetID: asset.ID,
				Title:       "Workflow executes on a self-hosted runner",
				Reason:      "Self-hosted runners do not provide GitHub-hosted ephemeral isolation guarantees.",
				Remediation: "Use ephemeral isolated runners, restrict trigger trust, and prevent untrusted jobs from sharing persistent runner state.",
				Evidence:    evidenceForControlItems(asset, runnerEvidenceIDs(runners)), Attributes: map[string]any{"runners": sanitizedRunners(runners), "untrustedDataFlow": len(flows) > 0},
			})
		}

		var dependencies []githubDependencyFinding
		decodeControl(asset.Controls, "githubMutableDependencyExposure", &dependencies)
		if len(dependencies) > 0 {
			appendFinding(bom, model.Finding{
				Type: "github-actions-mutable-dependency", Severity: "high", AssetID: asset.ID,
				Title:       "Workflow executes a mutable dependency reference",
				Reason:      "External action, reusable workflow, or container reference can resolve to different code without a repository change.",
				Remediation: "Pin GitHub actions and reusable workflows to a full commit SHA and containers to a SHA-256 digest.",
				Evidence:    evidenceForControlItems(asset, dependencyEvidenceIDs(dependencies)), Attributes: map[string]any{"dependencies": sanitizedDependencies(dependencies)},
			})
		}
	}
}

func decodeControl(controls []model.Control, controlType string, target any) bool {
	for _, control := range controls {
		if control.Type != controlType {
			continue
		}
		content, err := json.Marshal(control.Value)
		return err == nil && json.Unmarshal(content, target) == nil
	}
	return false
}

func firstParserEvidence(asset *model.Asset, parser string) []model.FindingEvidence {
	for _, evidence := range asset.Evidence {
		if evidence.Parser == parser {
			return []model.FindingEvidence{{AssetID: asset.ID, EvidenceID: evidence.ID}}
		}
	}
	return nil
}

func evidenceForControlItems(asset *model.Asset, ids []string) []model.FindingEvidence {
	wanted := map[string]struct{}{}
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	var result []model.FindingEvidence
	for _, evidence := range asset.Evidence {
		if _, exists := wanted[evidence.ID]; exists {
			result = append(result, model.FindingEvidence{AssetID: asset.ID, EvidenceID: evidence.ID})
		}
	}
	if len(result) == 0 {
		return firstParserEvidence(asset, "github-actions")
	}
	return result
}

func flowEvidenceIDs(values []githubFlowFinding) []string {
	var result []string
	for _, value := range values {
		result = append(result, value.EvidenceIDs...)
	}
	return result
}
func runnerEvidenceIDs(values []githubRunnerFinding) []string {
	var result []string
	for _, value := range values {
		result = append(result, value.EvidenceIDs...)
	}
	return result
}
func dependencyEvidenceIDs(values []githubDependencyFinding) []string {
	var result []string
	for _, value := range values {
		result = append(result, value.EvidenceIDs...)
	}
	return result
}

func sanitizedFlows(values []githubFlowFinding) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{"job": value.Job, "trigger": value.Trigger, "source": value.Source, "sink": value.Sink, "action": value.Action})
	}
	return result
}
func sanitizedRunners(values []githubRunnerFinding) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{"job": value.Job, "kind": value.Kind, "labels": value.Labels, "group": value.Group})
	}
	return result
}
func sanitizedDependencies(values []githubDependencyFinding) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{"job": value.Job, "kind": value.Kind, "reference": value.Reference, "pinType": value.PinType})
	}
	return result
}
