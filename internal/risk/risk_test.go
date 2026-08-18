package risk

import (
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestCapabilityRiskCalibration(t *testing.T) {
	tests := []struct {
		name       string
		asset      model.Asset
		capability model.Capability
		score      int
		level      string
		factors    []string
	}{
		{name: "high confidence read", asset: riskAsset("high"), capability: riskCapability("kubernetes.pods.get", "kubernetes:development/core/pods/app", "read", "development"), score: 15, level: "low", factors: []string{"effect", "high-confidence"}},
		{name: "all production objects", asset: riskAsset("high"), capability: riskCapability("kubernetes.pods.get", "kubernetes:production/core/pods/*", "read", "production"), score: 50, level: "medium", factors: []string{"effect", "production", "broad-scope", "high-confidence"}},
		{name: "production admin wildcard", asset: riskAsset("high"), capability: riskCapability("kubernetes.*.*", "kubernetes:production/*/*", "admin", "production"), score: 100, level: "critical", factors: []string{"effect", "production", "broad-scope", "high-confidence"}},
		{name: "automounted service account token", asset: riskAsset("high"), capability: riskCapability("kubernetes.service_account_token.use", "kubernetes:service-account/production/agent", "execute", "production"), score: 80, level: "critical", factors: []string{"service-account-token"}},
		{name: "long lived projected token", asset: projectedTokenAsset(), capability: riskCapability("kubernetes.service_account_token.project", "kubernetes:token-audience/automation", "execute", "production"), score: 95, level: "critical", factors: []string{"projected-service-account-token", "long-lived-projected-token"}},
		{name: "production OIDC federation", asset: riskAsset("high"), capability: riskCapability("github.oidc_token.issue", "github:oidc-token", "execute", "production"), score: 80, level: "critical", factors: []string{"effect", "production", "oidc-token", "high-confidence"}},
		{name: "privileged trigger write", asset: privilegedTriggerAsset(), capability: riskCapability("github.contents.*", "github:repository", "write", "development"), score: 85, level: "critical", factors: []string{"effect", "broad-scope", "privileged-trigger", "high-confidence"}},
		{name: "privileged trigger data flow", asset: untrustedDataFlowAsset(), capability: riskCapability("github.contents.*", "github:repository", "write", "development"), score: 100, level: "critical", factors: []string{"privileged-trigger", "untrusted-data-flow"}},
		{name: "self hosted runner", asset: selfHostedRunnerAsset(), capability: riskCapability("github.contents.*", "github:repository", "read", "development"), score: 50, level: "medium", factors: []string{"effect", "broad-scope", "self-hosted-runner", "high-confidence"}},
		{name: "mutable action dependency", asset: mutableDependencyAsset(), capability: riskCapability("github.contents.*", "github:repository", "write", "development"), score: 80, level: "critical", factors: []string{"effect", "broad-scope", "mutable-dependency", "high-confidence"}},
		{name: "reusable workflow secret inheritance", asset: reusableSecretInheritanceAsset(), capability: riskCapability("github.contents.*", "github:repository", "read", "development"), score: 55, level: "medium", factors: []string{"effect", "broad-scope", "reusable-secret-inheritance", "high-confidence"}},
		{name: "human approval mitigation", asset: controlledRiskAsset("humanApproval"), capability: riskCapability("deploy.update", "kubernetes:production/apps/deployment", "write", "production"), score: 50, level: "medium", factors: []string{"human-approval"}},
		{name: "safe output mitigation", asset: controlledRiskAsset("safeOutputs"), capability: riskCapability("github.safe_output.add.comment", "github:acme/repo", "write", "development"), score: 30, level: "low", factors: []string{"safe-output"}},
		{name: "low confidence", asset: riskAsset("low"), capability: riskCapability("kubernetes.pods.get", "kubernetes:development/core/pods/app", "read", "development"), score: 5, level: "info", factors: []string{"low-confidence"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := Capability(test.asset, test.capability)
			assertAssessment(t, assessment, test.score, test.level, test.factors...)
		})
	}
}

func TestCapabilityEscalationCalibration(t *testing.T) {
	asset := riskAsset("high")
	capability := riskCapability("kubernetes.pods.get", "kubernetes:production/core/pods/app", "read", "production")
	assessment := CapabilityEscalation(asset, capability, true, true)
	assertAssessment(t, assessment, 70, "high", "effect-escalation", "scope-expansion")
}

func TestCredentialControlRelationshipAndAssetRisk(t *testing.T) {
	asset := controlledRiskAsset("humanApproval")
	asset.Capabilities = []model.Capability{{Action: "deploy.update", Resource: "kubernetes:production/apps/deployment", Effect: "write", Environment: "production"}}
	credential := Credential(asset, model.CredentialReference{Type: "secret", Reference: "prod/api-token"})
	assertAssessment(t, credential, 75, "high", "credential", "production-credential", "production", "human-approval")

	control := Control(model.Control{Type: "humanApproval", Value: true}, true)
	assertAssessment(t, control, 75, "high", "control-change", "approval-control")

	relationship := Relationship(model.Relationship{Type: "runs-as", TargetType: "asset"}, false)
	assertAssessment(t, relationship, 45, "medium", "runtime-identity")

	newAsset := riskAsset("high")
	newAsset.Capabilities = []model.Capability{riskCapability("kubernetes.*.*", "kubernetes:production/*/*", "admin", "production")}
	added := AssetAdded(newAsset)
	assertAssessment(t, added, 100, "critical", "new-asset")
}

func TestDelegatedAccessPathRisk(t *testing.T) {
	asset := riskAsset("high")
	path := model.AccessPath{
		Steps:      []model.AccessPathStep{{Kind: "origin", AssetID: "workflow:caller"}, {Kind: "delegation", AssetID: "workflow:callee"}},
		Capability: riskCapability("github.contents.*", "github:repository", "write", "development"),
	}
	assessment := AccessPath(asset, path, true, false, true)
	assertAssessment(t, assessment, 100, "critical", "effective-access-path", "delegated-access", "effect-escalation", "access-path-rerouted")
}

func riskAsset(confidence string) model.Asset {
	return model.Asset{Evidence: []model.Evidence{{ID: "evidence", Path: "fixture", Parser: "test", Confidence: confidence}}}
}

func controlledRiskAsset(controlType string) model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: controlType, Value: true}}
	return asset
}

func projectedTokenAsset() model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: "serviceAccountTokenProjection", Value: map[string]any{"expirationSeconds": 7200}}}
	return asset
}

func privilegedTriggerAsset() model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: "githubPrivilegedTriggerExposure", Value: true}}
	return asset
}

func untrustedDataFlowAsset() model.Asset {
	asset := privilegedTriggerAsset()
	asset.Controls = append(asset.Controls, model.Control{Type: "githubUntrustedDataFlow", Value: true})
	return asset
}

func selfHostedRunnerAsset() model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: "githubSelfHostedRunnerExposure", Value: true}}
	return asset
}

func mutableDependencyAsset() model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: "githubMutableDependencyExposure", Value: true}}
	return asset
}

func reusableSecretInheritanceAsset() model.Asset {
	asset := riskAsset("high")
	asset.Controls = []model.Control{{Type: "githubReusableWorkflowSecretInheritance", Value: true}}
	return asset
}

func riskCapability(action, resource, effect, environment string) model.Capability {
	return model.Capability{Action: action, Resource: resource, Effect: effect, Environment: environment, EvidenceIDs: []string{"evidence"}}
}

func assertAssessment(t *testing.T, assessment Assessment, score int, level string, factors ...string) {
	t.Helper()
	if assessment.Score != score || assessment.Level != level {
		t.Fatalf("assessment = %d/%s, expected %d/%s; factors=%#v", assessment.Score, assessment.Level, score, level, assessment.Factors)
	}
	for _, factor := range factors {
		if !assessmentHasFactor(assessment, factor) {
			t.Errorf("factor %q not found in %#v", factor, assessment.Factors)
		}
	}
}

func assessmentHasFactor(assessment Assessment, name string) bool {
	for _, factor := range assessment.Factors {
		if factor.Name == name {
			return true
		}
	}
	return false
}
