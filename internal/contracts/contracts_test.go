package contracts

import "testing"

func TestBuildInfoExposesSupportedPublicContracts(t *testing.T) {
	info := BuildInfo("v0.4.0-test")
	if info.Version != "v0.4.0-test" || info.Contracts.AgentBOM != AgentBOMAPIVersion || info.Contracts.Normalization != NormalizationVersion {
		t.Fatalf("unexpected build information: %#v", info)
	}
	if info.Contracts.Findings == "" || info.Contracts.PolicyInput == "" || info.Contracts.PolicyDecision != PolicyDecisionVersion || info.Contracts.AuditEvent == "" || info.Contracts.ControlPlane == "" || info.Contracts.RepositorySet != RepositorySetAPIVersion || info.Contracts.Preflight != PreflightAPIVersion || info.Contracts.SARIF == "" {
		t.Fatalf("public contract registry is incomplete: %#v", info.Contracts)
	}
}
