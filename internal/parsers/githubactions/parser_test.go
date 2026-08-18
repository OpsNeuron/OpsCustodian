package githubactions

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

func TestParseResolvesWorkflowAndJobTokenPermissionPrecedence(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/permissions.yml",
		Content: []byte(`name: permission precedence
permissions:
  contents: read
  issues: write
jobs:
  inherited:
    runs-on: ubuntu-latest
  restricted:
    runs-on: ubuntu-latest
    permissions:
      contents: read
  disabled:
    runs-on: ubuntu-latest
    permissions: {}
  release:
    runs-on: ubuntu-latest
    permissions: write-all
`),
	}

	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(assets))
	}
	asset := assets[0]
	want := []string{
		"inherited|github.contents.*|read",
		"inherited|github.issues.*|write",
		"release|github.oidc_token.issue|execute",
		"release|github.repository.*|write",
		"restricted|github.contents.*|read",
	}
	got := capabilitySummaries(t, asset.Capabilities)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effective token capabilities = %#v, want %#v", got, want)
	}
	for _, capability := range asset.Capabilities {
		if len(capability.EvidenceIDs) != 2 {
			t.Fatalf("capability lacks job and permission provenance: %#v", capability)
		}
	}
	if !controlContainsJob(asset.Controls, "githubTokenPermissionsDisabled", "disabled") {
		t.Fatalf("explicitly disabled job was not recorded: %#v", asset.Controls)
	}
	if controlOfType(asset.Controls, "githubTokenPermissionsUnspecified") != nil {
		t.Fatalf("inherited permissions must not be classified as unspecified: %#v", asset.Controls)
	}
}

func TestParseRecordsUnspecifiedTokenPermissions(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/implicit.yml",
		Content: []byte(`name: implicit permissions
jobs:
  review:
    runs-on: ubuntu-latest
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(assets[0].Capabilities) != 0 {
		t.Fatalf("repository-dependent defaults must not be invented: %#v", assets[0].Capabilities)
	}
	if !controlContainsJob(assets[0].Controls, "githubTokenPermissionsUnspecified", "review") {
		t.Fatalf("unspecified permission source was not preserved: %#v", assets[0].Controls)
	}
}

func TestParseModelsOIDCFederationAndDeploymentEnvironment(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/deploy.yml",
		Content: []byte(`name: deploy
permissions:
  contents: read
  id-token: write
jobs:
  production:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://deployments.example.test/current
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	oidc := requireCapability(t, asset.Capabilities, "github.oidc_token.issue")
	if oidc.Resource != "github:oidc-token" || oidc.Effect != "execute" || oidc.Environment != "production" {
		t.Fatalf("unexpected OIDC capability: %#v", oidc)
	}
	if len(oidc.EvidenceIDs) != 2 || oidc.Scope == nil || !reflect.DeepEqual(oidc.Scope.Values, []string{"production"}) {
		t.Fatalf("OIDC capability lacks job-scoped provenance: %#v", oidc)
	}
	deployment := requireCapability(t, asset.Capabilities, "github.environment.deploy")
	if deployment.Resource != "github:environment:production" || deployment.Effect != "execute" || len(deployment.EvidenceIDs) != 2 {
		t.Fatalf("unexpected deployment capability: %#v", deployment)
	}
	control := controlOfType(asset.Controls, "githubDeploymentEnvironment")
	if control == nil {
		t.Fatalf("deployment environment control is missing: %#v", asset.Controls)
	}
	value, ok := control.Value.(githubEnvironmentControl)
	if !ok || value.Job != "production" || value.Name != "production" || value.URL != "https://deployments.example.test/current" || value.ProtectionStatus != "unknown" {
		t.Fatalf("unexpected environment control: %#v", control.Value)
	}
}

func TestParseRecordsPrivilegedTriggerTrustBoundaries(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/privileged.yml",
		Content: []byte(`name: privileged automation
on:
  push:
  pull_request_target:
    types: [opened, synchronize]
  workflow_run:
    workflows: [Untrusted tests]
    types: [completed]
permissions:
  contents: write
jobs:
  respond:
    runs-on: ubuntu-latest
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	triggerControl := controlOfType(asset.Controls, "githubWorkflowTriggers")
	if triggerControl == nil || !reflect.DeepEqual(triggerControl.Value, []string{"pull_request_target", "push", "workflow_run"}) {
		t.Fatalf("unexpected workflow trigger inventory: %#v", triggerControl)
	}
	exposureControl := controlOfType(asset.Controls, "githubPrivilegedTriggerExposure")
	if exposureControl == nil {
		t.Fatalf("privileged trigger exposure is missing: %#v", asset.Controls)
	}
	exposures, ok := exposureControl.Value.([]githubTriggerExposure)
	if !ok || len(exposures) != 2 {
		t.Fatalf("unexpected trigger exposures: %#v", exposureControl.Value)
	}
	if exposures[0].Event != "pull_request_target" || exposures[0].TrustBoundary != "base-repository-privileged" {
		t.Fatalf("unexpected pull_request_target exposure: %#v", exposures[0])
	}
	if exposures[1].Event != "workflow_run" || exposures[1].TrustBoundary != "privileged-follow-up" {
		t.Fatalf("unexpected workflow_run exposure: %#v", exposures[1])
	}
}

func TestParseCorrelatesPrivilegedTriggersWithUntrustedWorkspaceFlows(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/data-flow.yml",
		Content: []byte(`name: privileged data flow
on: [pull_request_target, workflow_run]
permissions:
  contents: write
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - uses: actions/checkout@v4
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	control := controlOfType(asset.Controls, "githubUntrustedDataFlow")
	if control == nil {
		t.Fatalf("untrusted data-flow control is missing: %#v", asset.Controls)
	}
	flows, ok := control.Value.([]githubUntrustedDataFlow)
	if !ok || len(flows) != 2 {
		t.Fatalf("unexpected data flows: %#v", control.Value)
	}
	if flows[0].Trigger != "pull_request_target" || flows[0].Source != "pull-request-head-ref" || flows[0].Sink != "runner-workspace" {
		t.Fatalf("unexpected checkout flow: %#v", flows[0])
	}
	if flows[1].Trigger != "workflow_run" || flows[1].Source != "triggering-workflow-artifact" || flows[1].Sink != "runner-workspace" {
		t.Fatalf("unexpected artifact flow: %#v", flows[1])
	}
	for _, flow := range flows {
		if len(flow.EvidenceIDs) != 2 || !assetHasEvidence(asset, flow.EvidenceIDs[1]) {
			t.Fatalf("flow lacks stable owned evidence: %#v", flow)
		}
	}
}

func TestParseDetectsDirectRunInjectionButNotEnvironmentIndirection(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/comment.yml",
		Content: []byte(`name: comment automation
on: issue_comment
permissions:
  issues: write
jobs:
  respond:
    runs-on: ubuntu-latest
    env:
      SAFE_ISSUE_TITLE: ${{ github.event.issue.title }}
    steps:
      - name: Safe environment indirection
        run: printf '%s\n' "$SAFE_ISSUE_TITLE"
      - name: Unsafe direct interpolation
        shell: bash
        run: echo "${{ github.event.comment.body }}"
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	control := controlOfType(asset.Controls, "githubUntrustedDataFlow")
	if control == nil {
		t.Fatalf("script-injection data flow is missing: %#v", asset.Controls)
	}
	flows, ok := control.Value.([]githubUntrustedDataFlow)
	if !ok || len(flows) != 1 {
		t.Fatalf("expected only direct run interpolation to be reported, got %#v", control.Value)
	}
	flow := flows[0]
	if flow.Trigger != "issue_comment" || flow.Source != "github.event.comment.body" || flow.Sink != "runner-shell" || flow.Action != "run:bash" {
		t.Fatalf("unexpected script-injection flow: %#v", flow)
	}
	if len(flow.EvidenceIDs) != 2 || !assetHasEvidence(asset, flow.EvidenceIDs[1]) {
		t.Fatalf("script-injection flow lacks owned step evidence: %#v", flow)
	}
}

func TestParseClassifiesRunnerTrustWithoutGuessingDynamicOrGroupedRunners(t *testing.T) {
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/runners.yml",
		Content: []byte(`name: runner trust
on: push
jobs:
  hosted:
    runs-on: ubuntu-latest
  persistent:
    runs-on: [self-hosted, linux, x64]
  dynamic:
    runs-on: ${{ matrix.runner }}
  grouped:
    runs-on:
      group: production-runners
      labels: linux
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	selections := runnerControlValues(t, asset.Controls, "githubRunnerSelections")
	if len(selections) != 4 {
		t.Fatalf("runner selections = %#v, want 4", selections)
	}
	wantKinds := map[string]string{"hosted": "github-hosted", "persistent": "self-hosted", "dynamic": "unknown", "grouped": "unknown"}
	for _, selection := range selections {
		if selection.Kind != wantKinds[selection.Job] || len(selection.EvidenceIDs) != 2 || !assetHasEvidence(asset, selection.EvidenceIDs[1]) {
			t.Fatalf("unexpected runner selection: %#v", selection)
		}
	}
	selfHosted := runnerControlValues(t, asset.Controls, "githubSelfHostedRunnerExposure")
	if len(selfHosted) != 1 || selfHosted[0].Job != "persistent" {
		t.Fatalf("unexpected self-hosted exposure: %#v", selfHosted)
	}
	unknown := runnerControlValues(t, asset.Controls, "githubRunnerSelectionUnknown")
	if len(unknown) != 2 || unknown[0].Job != "dynamic" || !unknown[0].Dynamic || unknown[1].Job != "grouped" || unknown[1].Group != "production-runners" {
		t.Fatalf("unexpected unknown runner selections: %#v", unknown)
	}
}

func TestParseClassifiesActionAndReusableWorkflowIntegrity(t *testing.T) {
	sha := "a824008085750b8e136effc585c3cd6082bd575f"
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	artifact := discovery.Artifact{
		RelPath: ".github/workflows/dependencies.yml",
		Content: []byte(`name: dependencies
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: acme/verified-action@` + sha + `
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - uses: docker://ghcr.io/acme/tool@` + digest + `
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@main
`),
	}
	assets, err := (Parser{}).Parse(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	asset := assets[0]
	dependencies := dependencyControlValues(t, asset.Controls, "githubDependencyIntegrity")
	if len(dependencies) != 6 || len(asset.Dependencies) != 6 {
		t.Fatalf("dependency inventory = %#v, references = %#v", dependencies, asset.Dependencies)
	}
	wantPins := map[string]string{
		"actions/checkout": "tag-or-branch",
		"acme/verified-action": "full-commit-sha",
		"./local-action": "same-commit",
		"alpine": "container-tag",
		"ghcr.io/acme/tool": "container-digest",
		"acme/platform/.github/workflows/deploy.yml": "tag-or-branch",
	}
	for _, dependency := range dependencies {
		if dependency.PinType != wantPins[dependency.Reference] || len(dependency.EvidenceIDs) != 2 || !assetHasEvidence(asset, dependency.EvidenceIDs[1]) {
			t.Fatalf("unexpected dependency integrity: %#v", dependency)
		}
		wantImmutable := dependency.PinType == "full-commit-sha" || dependency.PinType == "container-digest" || dependency.PinType == "same-commit"
		if dependency.Immutable != wantImmutable {
			t.Fatalf("dependency immutability = %t, want %t: %#v", dependency.Immutable, wantImmutable, dependency)
		}
	}
	mutable := dependencyControlValues(t, asset.Controls, "githubMutableDependencyExposure")
	if len(mutable) != 3 {
		t.Fatalf("mutable dependencies = %#v, want checkout tag, container tag, and reusable workflow branch", mutable)
	}
}

func capabilitySummaries(t *testing.T, capabilities []model.Capability) []string {
	t.Helper()
	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability.Scope == nil || capability.Scope.Kind != "github-actions-job" || len(capability.Scope.Values) != 1 {
			t.Fatalf("capability lacks job scope: %#v", capability)
		}
		result = append(result, capability.Scope.Values[0]+"|"+capability.Action+"|"+capability.Effect)
	}
	sort.Strings(result)
	return result
}

func requireCapability(t *testing.T, capabilities []model.Capability, action string) model.Capability {
	t.Helper()
	for _, capability := range capabilities {
		if capability.Action == action {
			return capability
		}
	}
	t.Fatalf("capability %q not found in %#v", action, capabilities)
	return model.Capability{}
}

func controlContainsJob(controls []model.Control, controlType, job string) bool {
	control := controlOfType(controls, controlType)
	if control == nil {
		return false
	}
	jobs, ok := control.Value.([]string)
	if !ok {
		return false
	}
	for _, value := range jobs {
		if value == job {
			return true
		}
	}
	return false
}

func controlOfType(controls []model.Control, controlType string) *model.Control {
	for index := range controls {
		if controls[index].Type == controlType {
			return &controls[index]
		}
	}
	return nil
}

func assetHasEvidence(asset model.Asset, evidenceID string) bool {
	for _, evidence := range asset.Evidence {
		if evidence.ID == evidenceID {
			return true
		}
	}
	return false
}

func runnerControlValues(t *testing.T, controls []model.Control, controlType string) []githubRunnerSelection {
	t.Helper()
	control := controlOfType(controls, controlType)
	if control == nil {
		t.Fatalf("runner control %q is missing in %#v", controlType, controls)
	}
	values, ok := control.Value.([]githubRunnerSelection)
	if !ok {
		t.Fatalf("runner control %q has unexpected value %#v", controlType, control.Value)
	}
	return values
}

func dependencyControlValues(t *testing.T, controls []model.Control, controlType string) []githubDependencyIntegrity {
	t.Helper()
	control := controlOfType(controls, controlType)
	if control == nil {
		t.Fatalf("dependency control %q is missing in %#v", controlType, controls)
	}
	values, ok := control.Value.([]githubDependencyIntegrity)
	if !ok {
		t.Fatalf("dependency control %q has unexpected value %#v", controlType, control.Value)
	}
	return values
}
