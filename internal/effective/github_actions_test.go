package effective

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestComposeGitHubActionsFindingsBuildsEvidenceBackedSecurityResults(t *testing.T) {
	asset := model.Asset{
		ID: "github-actions:.github/workflows/review.yml", Type: "workflow", Name: "review",
		Source: model.Source{Path: ".github/workflows/review.yml"},
		Evidence: []model.Evidence{
			{ID: "workflow-evidence", Path: ".github/workflows/review.yml", Line: 1, Parser: "github-actions", Confidence: "high"},
			{ID: "flow-evidence", Path: ".github/workflows/review.yml", Line: 12, Parser: "github-actions", Confidence: "high"},
			{ID: "runner-evidence", Path: ".github/workflows/review.yml", Line: 8, Parser: "github-actions", Confidence: "high"},
			{ID: "dependency-evidence", Path: ".github/workflows/review.yml", Line: 15, Parser: "github-actions", Confidence: "high"},
		},
		Controls: []model.Control{
			{Type: "githubPrivilegedTriggerExposure", Value: []map[string]any{{"event": "pull_request_target", "trustBoundary": "base-repository-privileged", "reason": "secret-reason"}}},
			{Type: "githubUntrustedDataFlow", Value: []map[string]any{{"job": "review", "trigger": "pull_request_target", "source": "github.event.comment.body", "sink": "runner-shell", "action": "run:bash", "reason": "secret-flow", "evidenceIds": []string{"workflow-evidence", "flow-evidence"}}}},
			{Type: "githubSelfHostedRunnerExposure", Value: []map[string]any{{"job": "review", "kind": "self-hosted", "labels": []string{"self-hosted", "linux"}, "reason": "secret-runner", "evidenceIds": []string{"workflow-evidence", "runner-evidence"}}}},
			{Type: "githubMutableDependencyExposure", Value: []map[string]any{{"job": "review", "kind": "action", "reference": "actions/checkout", "locator": "secret-locator", "pinType": "tag-or-branch", "reason": "secret-dependency", "evidenceIds": []string{"workflow-evidence", "dependency-evidence"}}}},
		},
	}
	bom := model.AgentBOM{Assets: []model.Asset{asset}}

	ComposeGitHubActionsFindings(&bom)

	if len(bom.Findings) != 4 {
		t.Fatalf("expected four GitHub Actions findings, got %#v", bom.Findings)
	}
	if findingByType(t, bom.Findings, "github-actions-untrusted-data-flow", asset.ID).Severity != "critical" {
		t.Fatal("direct shell flow must be critical")
	}
	if findingByType(t, bom.Findings, "github-actions-self-hosted-runner-exposure", asset.ID).Severity != "critical" {
		t.Fatal("self-hosted runner combined with untrusted data must be critical")
	}
	mutable := findingByType(t, bom.Findings, "github-actions-mutable-dependency", asset.ID)
	if len(mutable.Evidence) != 2 || mutable.Attributes["dependencies"] == nil {
		t.Fatalf("mutable dependency lacks evidence or attributes: %#v", mutable)
	}
	content, _ := json.Marshal(bom.Findings)
	for _, forbidden := range []string{"secret-reason", "secret-flow", "secret-runner", "secret-locator", "secret-dependency"} {
		if strings.Contains(string(content), forbidden) {
			t.Fatalf("control detail %q leaked into finding: %s", forbidden, content)
		}
	}
}

func TestComposeGitHubActionsFindingsDoesNotReportInventoryOnlyControls(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{{
		ID: "github-actions:safe", Type: "workflow", Name: "safe", Source: model.Source{Path: "safe.yml"},
		Evidence: []model.Evidence{{ID: "safe", Path: "safe.yml", Parser: "github-actions", Confidence: "high"}},
		Controls: []model.Control{
			{Type: "githubRunnerSelections", Value: []map[string]any{{"job": "build", "kind": "github-hosted"}}},
			{Type: "githubDependencyIntegrity", Value: []map[string]any{{"job": "build", "reference": "acme/action", "pinType": "full-commit-sha", "immutable": true}}},
		},
	}}}
	ComposeGitHubActionsFindings(&bom)
	if len(bom.Findings) != 0 {
		t.Fatalf("safe inventory controls produced findings: %#v", bom.Findings)
	}
}
