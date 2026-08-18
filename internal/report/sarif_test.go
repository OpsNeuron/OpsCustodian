package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/drift"
	"github.com/opscustodian/opscustodian/internal/risk"
)

func TestWriteSARIFProducesStableGitHubCodeScanningContract(t *testing.T) {
	report := drift.Report{
		BeforeRevision: "baseline",
		AfterRevision:  "proposed",
		Changes: []drift.Change{
			{
				ID: "finding-critical", Type: "capability-escalated", Severity: "critical",
				AgentID: "agent:deployer", Subject: "kubernetes.deployments.update",
				Before:    "kubernetes:production/apps/payments (write)",
				After:     "kubernetes:production/* (admin)",
				Reason:    "capability effect and scope increased",
				Locations: []drift.Location{{Path: "k8s/runtime.yaml", Line: 27, Column: 5}},
				Risk:      risk.Assessment{Score: 100, Level: "critical", Factors: []risk.Factor{{Name: "scope-expansion", Score: 20, Reason: "broader scope"}}},
			},
			{
				ID: "finding-warning", Type: "relationship-added", Severity: "medium",
				AgentID: "agent:deployer", Subject: "runs-as", After: "identity:production/deployer",
				Reason: "new runtime identity", Locations: []drift.Location{{Path: ".github/agents/deployer.md"}},
				Risk: risk.Assessment{Score: 45, Level: "medium"},
			},
			{
				ID: "finding-note", Type: "capability-escalated", Severity: "low",
				AgentID: "agent:reviewer", Subject: "github.issues.read", Reason: "read scope increased",
				Risk: risk.Assessment{Score: 20, Level: "low"},
			},
		},
	}

	var first bytes.Buffer
	if err := writeSARIF(&first, report); err != nil {
		t.Fatalf("writeSARIF() error = %v", err)
	}
	var second bytes.Buffer
	if err := writeSARIF(&second, report); err != nil {
		t.Fatalf("second writeSARIF() error = %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("SARIF output is not deterministic")
	}

	var log sarifLog
	if err := json.Unmarshal(first.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: %#v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "OpsCustodian" || run.Tool.Driver.InformationURI == "" || run.Tool.Driver.SemanticVersion == "" {
		t.Fatalf("incomplete SARIF tool identity: %#v", run.Tool.Driver)
	}
	if run.AutomationDetails.ID != "opscustodian/semantic-drift" {
		t.Fatalf("unexpected automation ID %q", run.AutomationDetails.ID)
	}

	wantRules := []string{"capability-escalated", "relationship-added"}
	gotRules := make([]string, 0, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		gotRules = append(gotRules, rule.ID)
		if rule.ShortDescription.Text == "" || rule.Help.Text == "" {
			t.Fatalf("rule %q lacks user-facing guidance", rule.ID)
		}
	}
	if !reflect.DeepEqual(gotRules, wantRules) {
		t.Fatalf("rules = %#v, want sorted and deduplicated %#v", gotRules, wantRules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}

	critical := run.Results[0]
	if critical.RuleID != "capability-escalated" || critical.RuleIndex != 0 || critical.Level != "error" {
		t.Fatalf("unexpected critical result routing: %#v", critical)
	}
	if critical.PartialFingerprints["opscustodianFindingId/v1"] != "finding-critical" {
		t.Fatalf("missing stable partial fingerprint: %#v", critical.PartialFingerprints)
	}
	if len(critical.Locations) != 1 {
		t.Fatalf("critical result locations = %#v", critical.Locations)
	}
	physical := critical.Locations[0].PhysicalLocation
	if physical.ArtifactLocation.URI != "k8s/runtime.yaml" || physical.Region == nil || physical.Region.StartLine != 27 || physical.Region.StartColumn != 5 {
		t.Fatalf("unexpected physical location: %#v", physical)
	}
	if run.Results[1].Level != "warning" || run.Results[1].Locations[0].PhysicalLocation.Region != nil {
		t.Fatalf("unexpected medium/locationless-region mapping: %#v", run.Results[1])
	}
	if run.Results[2].Level != "note" || run.Results[2].Locations != nil {
		t.Fatalf("unexpected low/no-location mapping: %#v", run.Results[2])
	}
}

func TestWriteSARIFUsesExplicitEmptyArrays(t *testing.T) {
	var output bytes.Buffer
	if err := writeSARIF(&output, drift.Report{}); err != nil {
		t.Fatalf("writeSARIF() error = %v", err)
	}
	jsonText := output.String()
	if !strings.Contains(jsonText, `"rules": []`) || !strings.Contains(jsonText, `"results": []`) {
		t.Fatalf("empty SARIF collections must be arrays, not null:\n%s", jsonText)
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := map[string]string{
		"critical": "error", "high": "error", "medium": "warning",
		"low": "note", "info": "note", "unknown": "note",
	}
	for severity, expected := range tests {
		if actual := sarifLevel(severity); actual != expected {
			t.Errorf("sarifLevel(%q) = %q, want %q", severity, actual, expected)
		}
	}
}
