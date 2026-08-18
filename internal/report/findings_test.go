package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestWriteFindingsAcrossTerminalJSONAndSARIF(t *testing.T) {
	bom := findingsTestBOM()
	for _, format := range []string{"terminal", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := WriteFindings(&output, bom, format); err != nil {
				t.Fatalf("WriteFindings(%s): %v", format, err)
			}
			if !strings.Contains(output.String(), "finding-stable") || !strings.Contains(output.String(), "kubernetes-effective-access-expansion") || !strings.Contains(output.String(), "kubernetes.reduce-access") {
				t.Fatalf("%s output missing finding identity: %s", format, output.String())
			}
			if format == "sarif" {
				for _, expected := range []string{`"automationDetails"`, `"opscustodian/current-state-findings"`, `"opscustodianFindingId/v1"`, `"uri": "rbac.yaml"`, `"startLine": 12`} {
					if !strings.Contains(output.String(), expected) {
						t.Fatalf("SARIF missing %s: %s", expected, output.String())
					}
				}
				var decoded map[string]any
				if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
					t.Fatalf("invalid SARIF JSON: %v", err)
				}
			}
		})
	}
}

func TestWriteFindingsUsesExplicitEmptyArrays(t *testing.T) {
	var output bytes.Buffer
	if err := WriteFindings(&output, model.AgentBOM{}, "json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"findings": []`) {
		t.Fatalf("empty findings must be an array: %s", output.String())
	}
}

func findingsTestBOM() model.AgentBOM {
	return model.AgentBOM{
		Metadata: model.DocumentMetadata{Source: "github:acme/platform", Revision: "abc123"},
		Assets:   []model.Asset{{ID: "role:admin", Evidence: []model.Evidence{{ID: "role-evidence", Path: "rbac.yaml", Line: 12, Parser: "kubernetes", Confidence: "high"}}}},
		Findings: []model.Finding{{
			ID: "finding-stable", Type: "kubernetes-effective-access-expansion", Severity: "critical", AssetID: "workload:agent",
			Title: "Effective access expanded", Reason: "RBAC grants administrator access", RemediationID: "kubernetes.reduce-access", Remediation: "Reduce the role.",
			Evidence: []model.FindingEvidence{{AssetID: "role:admin", EvidenceID: "role-evidence"}},
		}},
	}
}
