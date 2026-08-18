package effective

import (
	"testing"

	"github.com/opscustodian/opscustodian/internal/model"
)

func TestComposeGitHubReusableWorkflowsResolvesAndBoundsNestedCalls(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		githubWorkflowAsset("workflow:root", ".github/workflows/root.yml", "deploy", "write", model.GitHubReusableWorkflowCall{
			Job: "deploy", Reference: "./.github/workflows/middle.yml", Local: true, PermissionSource: "job", SecretMode: "inherit", Resolution: "local-candidate", EvidenceIDs: []string{"root-call"},
		}),
		githubWorkflowAsset("workflow:middle", ".github/workflows/middle.yml", "delegate", "write", model.GitHubReusableWorkflowCall{
			Job: "delegate", Reference: "./.github/workflows/leaf.yml", Local: true, PermissionSource: "job", SecretMode: "inherit", Resolution: "local-candidate", EvidenceIDs: []string{"middle-call"},
		}),
		githubWorkflowAsset("workflow:leaf", ".github/workflows/leaf.yml", "", "", model.GitHubReusableWorkflowCall{}),
	}}
	// The first caller can only pass read even though its fixture helper emits a
	// write request; the nested caller requests write and must remain read.
	bom.Assets[0].Capabilities[0].Effect = "read"
	bom.Assets[2].Controls = nil

	ComposeGitHubReusableWorkflows(&bom)

	calls := bom.Assets[0].Controls[0].Value.([]model.GitHubReusableWorkflowCall)
	if calls[0].Resolution != "local-resolved" {
		t.Fatalf("resolution = %q, expected local-resolved", calls[0].Resolution)
	}
	hops := compositionHops(t, bom.Assets[0])
	if len(hops) != 2 {
		t.Fatalf("expected 2 composed hops, got %#v", hops)
	}
	if hops[1].PermissionResolution != "nested-bounded-intersection" || len(hops[1].EffectivePermissions) != 1 || hops[1].EffectivePermissions[0].Effect != "read" {
		t.Fatalf("nested permission was not bounded by caller: %#v", hops[1])
	}
	if hops[1].EffectiveSecretMode != "inherited" {
		t.Fatalf("nested secret mode = %q, expected inherited", hops[1].EffectiveSecretMode)
	}
	if len(bom.AccessPaths) != 3 {
		t.Fatalf("expected root and independently callable workflow paths, got %#v", bom.AccessPaths)
	}
	var nestedPath model.AccessPath
	for _, accessPath := range bom.AccessPaths {
		if accessPath.Origin == "workflow:root" && len(accessPath.Steps) == 3 {
			nestedPath = accessPath
			break
		}
	}
	if len(nestedPath.Steps) != 3 || nestedPath.Steps[1].Kind != "delegation" || nestedPath.Steps[2].AssetID != "workflow:leaf" {
		t.Fatalf("unexpected nested delegation path: %#v", nestedPath)
	}
	if nestedPath.Capability.Effect != "read" {
		t.Fatalf("delegation path escaped caller ceiling: %#v", nestedPath.Capability)
	}
}

func TestComposeGitHubReusableWorkflowsReportsCycle(t *testing.T) {
	bom := model.AgentBOM{Assets: []model.Asset{
		githubWorkflowAsset("workflow:a", ".github/workflows/a.yml", "call-b", "read", model.GitHubReusableWorkflowCall{Job: "call-b", Reference: "./.github/workflows/b.yml", Local: true, SecretMode: "none"}),
		githubWorkflowAsset("workflow:b", ".github/workflows/b.yml", "call-a", "read", model.GitHubReusableWorkflowCall{Job: "call-a", Reference: "./.github/workflows/a.yml", Local: true, SecretMode: "none"}),
	}}

	ComposeGitHubReusableWorkflows(&bom)

	found := false
	for _, diagnostic := range bom.Diagnostics {
		if diagnostic.Code == "GITHUB_REUSABLE_WORKFLOW_CYCLE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected cycle diagnostic, got %#v", bom.Diagnostics)
	}
}

func githubWorkflowAsset(id, sourcePath, job, effect string, call model.GitHubReusableWorkflowCall) model.Asset {
	asset := model.Asset{ID: id, Type: "workflow", Name: id, Source: model.Source{Path: sourcePath}}
	if job != "" {
		asset.Capabilities = []model.Capability{{Action: "github.contents.*", Resource: "github:repository", Effect: effect, Scope: &model.Scope{Kind: "github-actions-job", Values: []string{job}}}}
	}
	if call.Reference != "" {
		asset.Controls = []model.Control{{Type: "githubReusableWorkflowCalls", Value: []model.GitHubReusableWorkflowCall{call}}}
	}
	return asset
}

func compositionHops(t *testing.T, asset model.Asset) []model.GitHubReusableWorkflowHop {
	t.Helper()
	for _, control := range asset.Controls {
		if control.Type == "githubReusableWorkflowComposition" {
			return control.Value.([]model.GitHubReusableWorkflowHop)
		}
	}
	t.Fatal("githubReusableWorkflowComposition control not found")
	return nil
}
