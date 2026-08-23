package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
	"github.com/opscustodian/opscustodian/internal/policy"
)

func TestPublicJSONContractsMatchGoldenFiles(t *testing.T) {
	bom := contractGoldenBOM()
	decision := policy.Decision{
		Deny: []policy.Message{{
			ID: "policy-contract", Rule: "current-state-critical-finding", Title: "Role can escalate privileges",
			Message: "Current-state finding affects role:admin.", Severity: "critical", AgentID: "role:admin",
			RemediationID: "kubernetes.reduce-rbac-privileges", Remediation: "Remove bind access.", EvidenceIDs: []string{"role-evidence"},
		}},
		Warn: []policy.Message{},
	}

	tests := []struct {
		name   string
		golden string
		write  func(*bytes.Buffer) error
	}{
		{name: "agentbom", golden: "agentbom.golden.json", write: func(output *bytes.Buffer) error { return WriteBOM(output, bom, "json") }},
		{name: "findings", golden: "findings.golden.json", write: func(output *bytes.Buffer) error { return WriteFindings(output, bom, "json") }},
		{name: "findings sarif", golden: "findings.golden.sarif", write: func(output *bytes.Buffer) error { return WriteFindings(output, bom, "sarif") }},
		{name: "policy decision", golden: "policy-decision.golden.json", write: func(output *bytes.Buffer) error { return WritePolicyDecision(output, decision, "json") }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := test.write(&output); err != nil {
				t.Fatalf("render contract: %v", err)
			}
			expected, err := os.ReadFile(filepath.Join("testdata", test.golden))
			if err != nil {
				t.Fatalf("read golden file: %v", err)
			}
			actualContract := compactGoldenJSON(t, "rendered contract", output.Bytes())
			expectedContract := compactGoldenJSON(t, test.golden, expected)
			if !bytes.Equal(actualContract, expectedContract) {
				t.Fatalf("public contract differs from %s\n--- expected ---\n%s\n--- actual ---\n%s", test.golden, expected, output.Bytes())
			}
		})
	}
}

func compactGoldenJSON(t *testing.T, name string, document []byte) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, document); err != nil {
		t.Fatalf("compact %s: %v", name, err)
	}
	return compact.Bytes()
}

func contractGoldenBOM() model.AgentBOM {
	return model.AgentBOM{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata: model.DocumentMetadata{
			Source: "github:acme/platform", Revision: "abc123", NormalizationVersion: "v1alpha1",
		},
		Assets: []model.Asset{},
		Findings: []model.Finding{{
			ID: "finding-contract", Type: "kubernetes-rbac-privilege-escalation", Severity: "critical", AssetID: "role:admin",
			Title: "Role can escalate privileges", Reason: "The role grants bind.", RemediationID: "kubernetes.reduce-rbac-privileges",
			Remediation: "Remove bind access.", Evidence: []model.FindingEvidence{},
		}},
	}
}
